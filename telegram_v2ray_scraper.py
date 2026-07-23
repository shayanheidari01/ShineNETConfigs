#!/usr/bin/env python3
"""
Telegram V2Ray Config Scraper - Fixed Name Parsing
==================================================

Scrapes VPN / V2Ray proxy configuration URIs from the public Telegram
web preview of a channel: https://t.me/s/<channel>

Supported protocols:
- VMess
- VLESS
- Trojan
- Shadowsocks (ss)

Important fix in this version
-----------------------------
Telegram may wrap emoji/flags and other inline parts of a config name inside
HTML tags such as <span>. Using BeautifulSoup.get_text(separator="\n") inserts
newlines between those inline tags and can break a name such as:

    #[🇩🇪]t.me/ConfigsHub

into multiple lines, causing the URI regex to keep only "#[".

This version preserves inline text exactly and inserts newlines ONLY for real
<br> tags. It also allows spaces in URI fragments (the display name after #).

Requirements
------------
    pip install requests beautifulsoup4

Examples
--------
    python telegram_v2ray_scraper_fixed.py
    python telegram_v2ray_scraper_fixed.py configshub -p 20 -d 2 --subscription
    python telegram_v2ray_scraper_fixed.py mychannel --protocols vmess,vless
"""

from __future__ import annotations

import argparse
import base64
import json
import logging
import re
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import requests
from bs4 import BeautifulSoup, NavigableString
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

TELEGRAM_PREVIEW_URL = "https://t.me/s/{channel}"

USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"
)

# Replace this channel tag in config display names.
NAME_REPLACE_FROM = "t.me/ConfigsHub"
NAME_REPLACE_TO = "SNV"

# Stable order for output files and all_configs.txt.
PROTOCOL_ORDER: Tuple[str, ...] = (
    "vmess",
    "vless",
    "trojan",
    "shadowsocks",
)

# For URI body: whitespace ends the technical URI portion.
_URI_BODY = r"[^\s<>\"']+"

# For URI fragment/name after '#': spaces and Unicode are allowed, but a real
# line break or HTML delimiter ends the config line.
_URI_FRAGMENT = r"[^\r\n<>\"']*"

# VMess is base64(JSON), so its display name is normally stored inside the
# decoded JSON in the `ps` field.
CONFIG_PATTERNS: Dict[str, re.Pattern[str]] = {
    "vmess": re.compile(r"vmess://[A-Za-z0-9+/=_-]{20,}"),

    # Stop the technical part before a literal '#', then keep the full fragment
    # (including spaces / emoji / Persian text) until the end of the logical line.
    "vless": re.compile(rf"vless://[^\s<>\"'#]+(?:#{_URI_FRAGMENT})?"),
    "trojan": re.compile(rf"trojan://[^\s<>\"'#]+(?:#{_URI_FRAGMENT})?"),

    # Negative lookbehind prevents matching the "ss://" suffix inside
    # "vmess://" or "vless://".
    "shadowsocks": re.compile(
        rf"(?<![A-Za-z0-9_])ss://[^\s<>\"'#]+(?:#{_URI_FRAGMENT})?"
    ),
}

VALID_PROTOCOLS = set(PROTOCOL_ORDER)
LOG = logging.getLogger("tg_scraper")


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class ScraperConfig:
    channel: str
    max_pages: int = 10
    delay: float = 1.5
    timeout: int = 15
    output_dir: Path = Path("configs_output")
    protocols: Tuple[str, ...] = PROTOCOL_ORDER
    make_subscription: bool = False
    verbose: bool = False


@dataclass
class ScrapeStats:
    pages_fetched: int = 0
    messages_parsed: int = 0
    configs_found: Dict[str, int] = field(
        default_factory=lambda: {k: 0 for k in PROTOCOL_ORDER}
    )


# ---------------------------------------------------------------------------
# Scraper
# ---------------------------------------------------------------------------

class TelegramConfigScraper:
    """Scrapes a public Telegram channel preview for V2Ray-style configs."""

    def __init__(self, config: ScraperConfig):
        self.config = config
        self.session = self._build_session()
        self.seen: set[str] = set()
        self.stats = ScrapeStats()

    # -- setup -------------------------------------------------------------

    def _build_session(self) -> requests.Session:
        session = requests.Session()

        retry = Retry(
            total=4,
            connect=4,
            read=4,
            backoff_factor=1.5,
            status_forcelist=(429, 500, 502, 503, 504),
            allowed_methods=("GET",),
            raise_on_status=False,
        )

        adapter = HTTPAdapter(max_retries=retry, pool_maxsize=10)
        session.mount("https://", adapter)
        session.mount("http://", adapter)

        session.headers.update(
            {
                "User-Agent": USER_AGENT,
                "Accept-Language": "en-US,en;q=0.9",
                "Accept": "text/html,application/xhtml+xml",
            }
        )

        return session

    # -- network -----------------------------------------------------------

    def _fetch_page(self, before_id: Optional[int]) -> Optional[str]:
        url = TELEGRAM_PREVIEW_URL.format(channel=self.config.channel)
        params = {"before": before_id} if before_id else None

        try:
            response = self.session.get(
                url,
                params=params,
                timeout=self.config.timeout,
            )
            response.raise_for_status()
            return response.text

        except requests.RequestException as exc:
            LOG.error("Request failed (before=%s): %s", before_id, exc)
            return None

    # -- parsing -----------------------------------------------------------

    @staticmethod
    def _message_id(message_div) -> Optional[int]:
        data_post = message_div.get("data-post", "")

        if "/" not in data_post:
            return None

        tail = data_post.rsplit("/", 1)[-1]
        return int(tail) if tail.isdigit() else None

    @staticmethod
    def _node_text(node) -> str:
        """
        Convert a Telegram HTML node to text without breaking inline content.

        Why not `get_text(separator="\\n")`?
        --------------------------------------
        Telegram often wraps flags, emoji and pieces of display names in inline
        tags. A newline separator between every text node can turn:

            #[🇩🇪]t.me/ConfigsHub

        into:

            #[\n🇩🇪\n]t.me/ConfigsHub

        which causes URI extraction to stop at the first newline.

        This implementation inserts a newline ONLY for an actual <br> tag and
        concatenates every other inline text node exactly as displayed.
        """
        parts: List[str] = []

        for item in node.descendants:
            if isinstance(item, NavigableString):
                parts.append(str(item))
            elif getattr(item, "name", None) == "br":
                parts.append("\n")

        return "".join(parts)

    def _parse_html(self, html: str) -> Tuple[List[str], Optional[int]]:
        soup = BeautifulSoup(html, "html.parser")
        blocks = soup.select("div.tgme_widget_message")

        texts: List[str] = []
        min_id: Optional[int] = None

        for block in blocks:
            msg_id = self._message_id(block)
            if msg_id is not None:
                min_id = msg_id if min_id is None else min(min_id, msg_id)

            text_node = block.select_one(".tgme_widget_message_text")
            if text_node:
                text = self._node_text(text_node)
                if text.strip():
                    texts.append(text)

            # Some Telegram messages may expose config content in code/pre.
            # Keep this fallback, but avoid adding the exact same extracted text
            # twice when it was already included in the main message body.
            for code_node in block.select("code, pre"):
                code_text = self._node_text(code_node)
                if code_text.strip() and code_text not in texts:
                    texts.append(code_text)

        self.stats.messages_parsed += len(blocks)
        return texts, min_id

    # -- extraction --------------------------------------------------------

    def _extract(self, text: str) -> Dict[str, List[str]]:
        found: Dict[str, List[str]] = {}

        for proto in self.config.protocols:
            matches = CONFIG_PATTERNS[proto].findall(text)
            if matches:
                found[proto] = matches

        return found

    @staticmethod
    def _is_valid_vmess(uri: str) -> bool:
        """Validate that a VMess URI is base64(JSON) with basic required keys."""
        try:
            payload = uri[len("vmess://"):].strip()

            # Support standard and URL-safe base64 variants.
            payload += "=" * (-len(payload) % 4)
            decoded = base64.urlsafe_b64decode(payload)
            obj = json.loads(decoded.decode("utf-8", errors="strict"))

            return (
                isinstance(obj, dict)
                and "add" in obj
                and "port" in obj
            )

        except Exception:
            return False

    @staticmethod
    def _rename_config(uri: str, proto: str) -> str:
        """Replace t.me/ConfigsHub with SNV in the config display name.

        VMess display names live inside the base64-encoded JSON `ps` field,
        while VLESS/Trojan/Shadowsocks names are normally stored after `#`.
        Only the display-name portion is modified; connection parameters are
        left untouched.
        """
        if proto == "vmess":
            try:
                payload = uri[len("vmess://"):].strip()
                payload += "=" * (-len(payload) % 4)
                decoded = base64.urlsafe_b64decode(payload)
                obj = json.loads(decoded.decode("utf-8", errors="strict"))

                if isinstance(obj, dict) and isinstance(obj.get("ps"), str):
                    obj["ps"] = obj["ps"].replace(
                        NAME_REPLACE_FROM, NAME_REPLACE_TO
                    )

                    compact = json.dumps(
                        obj, ensure_ascii=False, separators=(",", ":")
                    ).encode("utf-8")
                    encoded = base64.b64encode(compact).decode("ascii")
                    return "vmess://" + encoded
            except Exception:
                return uri

            return uri

        # URI-based protocols keep the display name after '#'.
        if "#" not in uri:
            return uri

        base, fragment = uri.split("#", 1)
        fragment = fragment.replace(NAME_REPLACE_FROM, NAME_REPLACE_TO)
        return f"{base}#{fragment}"

    @staticmethod
    def _clean(uri: str) -> str:
        """
        Remove accidental invisible edge characters without modifying the name.

        Do NOT strip '[' / ']' / emoji / spaces from the fragment because those
        can legitimately be part of a config display name.
        """
        uri = uri.strip()

        # Remove common zero-width / direction marks only from the outer edges.
        edge_chars = "\u200b\u200c\u200d\u2060\ufeff\u200e\u200f"
        uri = uri.strip(edge_chars)

        # Trim punctuation that is commonly attached by surrounding prose.
        # Avoid aggressive cleanup because fragments may intentionally contain
        # punctuation.
        if "#" not in uri:
            uri = uri.rstrip(".,;)")

        return uri

    # -- main loop ---------------------------------------------------------

    def run(self) -> Dict[str, List[str]]:
        results: Dict[str, List[str]] = {
            proto: [] for proto in self.config.protocols
        }

        before_id: Optional[int] = None

        try:
            for page in range(1, self.config.max_pages + 1):
                LOG.info(
                    "Page %d/%d (before=%s)",
                    page,
                    self.config.max_pages,
                    before_id,
                )

                html = self._fetch_page(before_id)
                if html is None:
                    LOG.warning("Stopping after a failed request.")
                    break

                self.stats.pages_fetched += 1
                texts, min_id = self._parse_html(html)

                if not texts:
                    LOG.info("No messages found on this page, stopping.")
                    break

                for text in texts:
                    extracted = self._extract(text)

                    for proto, uris in extracted.items():
                        for raw_uri in uris:
                            uri = self._clean(raw_uri)
                            uri = self._rename_config(uri, proto)

                            if not uri or uri in self.seen:
                                continue

                            if proto == "vmess" and not self._is_valid_vmess(uri):
                                LOG.debug("Rejected invalid VMess URI: %.80s...", uri)
                                continue

                            self.seen.add(uri)
                            results[proto].append(uri)
                            self.stats.configs_found[proto] += 1

                if min_id is None or min_id == before_id:
                    LOG.info("Reached the beginning of the channel history.")
                    break

                before_id = min_id

                if page < self.config.max_pages:
                    time.sleep(self.config.delay)

        except KeyboardInterrupt:
            LOG.warning("Interrupted by user - returning partial results.")

        return results

    # -- output ------------------------------------------------------------

    def save(self, results: Dict[str, List[str]]) -> Path:
        out_dir = self.config.output_dir
        out_dir.mkdir(parents=True, exist_ok=True)

        combined: List[str] = []

        for proto in self.config.protocols:
            uris = results.get(proto, [])
            if not uris:
                continue

            path = out_dir / f"{proto}.txt"
            path.write_text("\n".join(uris) + "\n", encoding="utf-8")
            combined.extend(uris)

            LOG.info(
                "%-12s -> %4d configs -> %s",
                proto,
                len(uris),
                path,
            )

        combined_path = out_dir / "all_configs.txt"
        combined_path.write_text(
            ("\n".join(combined) + "\n") if combined else "",
            encoding="utf-8",
        )

        LOG.info(
            "%-12s -> %4d configs -> %s",
            "TOTAL",
            len(combined),
            combined_path,
        )

        if self.config.make_subscription and combined:
            sub_path = out_dir / "subscription.txt"
            encoded = base64.b64encode(
                "\n".join(combined).encode("utf-8")
            ).decode("ascii")

            sub_path.write_text(encoded, encoding="utf-8")
            LOG.info("Subscription file -> %s", sub_path)

        return combined_path


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _parse_protocols(raw: str) -> Tuple[str, ...]:
    aliases = {"ss": "shadowsocks"}

    requested: List[str] = []
    for item in raw.split(","):
        proto = item.strip().lower()
        if not proto:
            continue

        proto = aliases.get(proto, proto)

        if proto not in VALID_PROTOCOLS:
            raise argparse.ArgumentTypeError(
                f"Unknown protocol: {proto}. Choose from: "
                f"{', '.join(PROTOCOL_ORDER[:-1])}, ss"
            )

        if proto not in requested:
            requested.append(proto)

    if not requested:
        return PROTOCOL_ORDER

    # Keep the user's requested order.
    return tuple(requested)


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Scrape V2Ray/VPN proxy configs from a public Telegram channel "
            "while preserving config display names."
        ),
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )

    parser.add_argument(
        "channel",
        nargs="?",
        default="configshub",
        help="Telegram channel username (without @)",
    )

    parser.add_argument(
        "-p",
        "--max-pages",
        type=int,
        default=10,
        help="Max number of pages to paginate through",
    )

    parser.add_argument(
        "-d",
        "--delay",
        type=float,
        default=1.5,
        help="Delay (seconds) between page requests",
    )

    parser.add_argument(
        "-t",
        "--timeout",
        type=int,
        default=15,
        help="HTTP request timeout (seconds)",
    )

    parser.add_argument(
        "-o",
        "--output-dir",
        type=Path,
        default=Path("configs_output"),
        help="Directory to write results into",
    )

    parser.add_argument(
        "--protocols",
        type=_parse_protocols,
        default=PROTOCOL_ORDER,
        help="Comma-separated protocol filter: vmess,vless,trojan,ss",
    )

    parser.add_argument(
        "--subscription",
        action="store_true",
        help=(
            "Also write base64 subscription.txt "
            "(v2rayNG/NekoBox compatible format)"
        ),
    )

    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Enable debug logging",
    )

    return parser


def setup_logging(verbose: bool) -> None:
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%H:%M:%S",
    )


def main(argv: Optional[List[str]] = None) -> int:
    args = build_arg_parser().parse_args(argv)
    setup_logging(args.verbose)

    if args.max_pages < 1:
        LOG.error("--max-pages must be at least 1")
        return 2

    if args.delay < 0:
        LOG.error("--delay cannot be negative")
        return 2

    if args.timeout < 1:
        LOG.error("--timeout must be at least 1 second")
        return 2

    channel = args.channel.strip().lstrip("@").strip()
    if not channel:
        LOG.error("Channel username cannot be empty")
        return 2

    config = ScraperConfig(
        channel=channel,
        max_pages=args.max_pages,
        delay=args.delay,
        timeout=args.timeout,
        output_dir=args.output_dir,
        protocols=args.protocols,
        make_subscription=args.subscription,
        verbose=args.verbose,
    )

    LOG.info("Target channel : %s", config.channel)
    LOG.info("Protocols      : %s", ", ".join(config.protocols))

    scraper = TelegramConfigScraper(config)
    results = scraper.run()
    combined_path = scraper.save(results)

    LOG.info("=" * 48)
    LOG.info("Pages fetched   : %d", scraper.stats.pages_fetched)
    LOG.info("Messages parsed : %d", scraper.stats.messages_parsed)

    for proto in config.protocols:
        LOG.info(
            "  %-12s: %d",
            proto,
            scraper.stats.configs_found.get(proto, 0),
        )

    LOG.info("Saved combined  : %s", combined_path)

    return 0


if __name__ == "__main__":
    sys.exit(main())
