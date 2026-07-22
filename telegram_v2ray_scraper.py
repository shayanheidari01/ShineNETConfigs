#!/usr/bin/env python3
"""
Telegram V2Ray Config Scraper
==============================

Professional, production-ready scraper for extracting VPN / V2Ray proxy
configuration URIs (VMess, VLess, Trojan, Shadowsocks) from the public
web-preview of any Telegram channel (https://t.me/s/<channel>).

Default target channel: configshub

Features
--------
- No Telegram login / API token required (uses the public t.me/s/ preview).
- Automatic pagination back through channel history.
- Retry with exponential backoff + connection pooling.
- Regex-based extraction for vmess / vless / trojan / shadowsocks (ss).
- VMess payload validation (base64 + JSON structural check).
- Deduplication across the whole run.
- Per-protocol output files + a combined file.
- Optional base64 "subscription" file (ready for v2rayNG / NekoBox / etc).
- Clean CLI: page count, delay, timeout, protocol filter, verbosity.
- Graceful Ctrl+C handling (partial results are still saved).

Usage
-----
    python telegram_v2ray_scraper.py
    python telegram_v2ray_scraper.py configshub -p 20 -d 2 --subscription
    python telegram_v2ray_scraper.py mychannel --protocols vmess,vless

Requirements
------------
    pip install requests beautifulsoup4
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
from bs4 import BeautifulSoup
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

# Zero-width characters that sometimes leak into Telegram text around RTL
# (Persian/Arabic) captions and must not be swallowed into a config URI.
_EXCLUDE_CHARS = r"\s<>\"'\u200c\u200b"

# IMPORTANT: "vmess://" and "vless://" both *end* in "ss://", so a naive
# ss:// pattern would also match inside them (e.g. "vme[ss://...]"). The
# negative lookbehind below ensures "ss://" is only matched when it is NOT
# immediately preceded by a letter/digit/underscore.
CONFIG_PATTERNS: Dict[str, re.Pattern] = {
    "vmess": re.compile(r"vmess://[A-Za-z0-9+/=_-]{20,}"),
    "vless": re.compile(r"vless://[^\s<>\"]+"),
    "trojan": re.compile(r"trojan://[^\s<>\"]+"),
    "shadowsocks": re.compile(rf"(?<![A-Za-z0-9_])ss://[^{_EXCLUDE_CHARS}]+"),
}

VALID_PROTOCOLS = set(CONFIG_PATTERNS.keys())

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
    protocols: Tuple[str, ...] = tuple(CONFIG_PATTERNS.keys())
    make_subscription: bool = False
    verbose: bool = False


@dataclass
class ScrapeStats:
    pages_fetched: int = 0
    messages_parsed: int = 0
    configs_found: Dict[str, int] = field(
        default_factory=lambda: {k: 0 for k in CONFIG_PATTERNS}
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

    # -- setup ---------------------------------------------------------

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

    # -- network ---------------------------------------------------------

    def _fetch_page(self, before_id: Optional[int]) -> Optional[str]:
        url = TELEGRAM_PREVIEW_URL.format(channel=self.config.channel)
        params = {"before": before_id} if before_id else None
        try:
            resp = self.session.get(url, params=params, timeout=self.config.timeout)
            resp.raise_for_status()
            return resp.text
        except requests.RequestException as exc:
            LOG.error("Request failed (before=%s): %s", before_id, exc)
            return None

    # -- parsing ---------------------------------------------------------

    @staticmethod
    def _message_id(message_div) -> Optional[int]:
        data_post = message_div.get("data-post", "")
        if "/" in data_post:
            tail = data_post.rsplit("/", 1)[-1]
            if tail.isdigit():
                return int(tail)
        return None

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
                texts.append(text_node.get_text(separator="\n"))

            # Configs are sometimes wrapped in <code>/<pre> blocks instead.
            for code_node in block.select("code, pre"):
                texts.append(code_node.get_text(separator="\n"))

        self.stats.messages_parsed += len(blocks)
        return texts, min_id

    # -- extraction ---------------------------------------------------------

    def _extract(self, text: str) -> Dict[str, List[str]]:
        found: Dict[str, List[str]] = {}
        for proto in self.config.protocols:
            matches = CONFIG_PATTERNS[proto].findall(text)
            if matches:
                found[proto] = matches
        return found

    @staticmethod
    def _is_valid_vmess(uri: str) -> bool:
        """VMess URIs are base64(JSON). Reject anything that doesn't decode."""
        try:
            payload = uri[len("vmess://"):].strip()
            payload += "=" * (-len(payload) % 4)
            decoded = base64.b64decode(payload, validate=False)
            obj = json.loads(decoded)
            return isinstance(obj, dict) and "add" in obj and "port" in obj
        except Exception:
            return False

    @staticmethod
    def _clean(uri: str) -> str:
        return uri.strip().rstrip(".,;)\u200c\u200b")

    # -- main loop ---------------------------------------------------------

    def run(self) -> Dict[str, List[str]]:
        results: Dict[str, List[str]] = {p: [] for p in self.config.protocols}
        before_id: Optional[int] = None

        try:
            for page in range(1, self.config.max_pages + 1):
                LOG.info(
                    "Page %d/%d (before=%s)", page, self.config.max_pages, before_id
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
                    for proto, uris in self._extract(text).items():
                        for raw in uris:
                            uri = self._clean(raw)
                            if uri in self.seen:
                                continue
                            if proto == "vmess" and not self._is_valid_vmess(uri):
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
            LOG.warning("Interrupted by user — returning partial results.")

        return results

    # -- output ---------------------------------------------------------

    def save(self, results: Dict[str, List[str]]) -> Path:
        out_dir = self.config.output_dir
        out_dir.mkdir(parents=True, exist_ok=True)

        combined: List[str] = []
        for proto, uris in results.items():
            if not uris:
                continue
            path = out_dir / f"{proto}.txt"
            path.write_text("\n".join(uris) + "\n", encoding="utf-8")
            combined.extend(uris)
            LOG.info("%-12s -> %4d configs -> %s", proto, len(uris), path)

        combined_path = out_dir / "all_configs.txt"
        combined_path.write_text("\n".join(combined) + "\n", encoding="utf-8")
        LOG.info("%-12s -> %4d configs -> %s", "TOTAL", len(combined), combined_path)

        if self.config.make_subscription and combined:
            sub_path = out_dir / "subscription.txt"
            encoded = base64.b64encode("\n".join(combined).encode("utf-8"))
            sub_path.write_text(encoded.decode("utf-8"), encoding="utf-8")
            LOG.info("Subscription file -> %s", sub_path)

        return combined_path


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _parse_protocols(raw: str) -> Tuple[str, ...]:
    requested = {p.strip().lower() for p in raw.split(",") if p.strip()}
    aliases = {"ss": "shadowsocks"}
    normalized = {aliases.get(p, p) for p in requested}
    invalid = normalized - VALID_PROTOCOLS
    if invalid:
        raise argparse.ArgumentTypeError(
            f"Unknown protocol(s): {', '.join(sorted(invalid))}. "
            f"Choose from: {', '.join(sorted(VALID_PROTOCOLS))}"
        )
    return tuple(normalized) if normalized else tuple(VALID_PROTOCOLS)


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Scrape V2Ray/VPN proxy configs from a public Telegram channel.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "channel", nargs="?", default="configshub",
        help="Telegram channel username (without @)",
    )
    parser.add_argument("-p", "--max-pages", type=int, default=10,
                         help="Max number of pages to paginate through")
    parser.add_argument("-d", "--delay", type=float, default=1.5,
                         help="Delay (seconds) between page requests")
    parser.add_argument("-t", "--timeout", type=int, default=15,
                         help="HTTP request timeout (seconds)")
    parser.add_argument("-o", "--output-dir", type=Path, default=Path("configs_output"),
                         help="Directory to write results into")
    parser.add_argument("--protocols", type=_parse_protocols,
                         default=tuple(VALID_PROTOCOLS),
                         help="Comma-separated protocol filter: vmess,vless,trojan,ss")
    parser.add_argument("--subscription", action="store_true",
                         help="Also write a base64 'subscription.txt' (v2rayNG/NekoBox compatible)")
    parser.add_argument("-v", "--verbose", action="store_true",
                         help="Enable debug logging")
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

    config = ScraperConfig(
        channel=args.channel,
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
    scraper.save(results)

    LOG.info("=" * 48)
    LOG.info("Pages fetched   : %d", scraper.stats.pages_fetched)
    LOG.info("Messages parsed : %d", scraper.stats.messages_parsed)
    for proto, count in scraper.stats.configs_found.items():
        LOG.info("  %-12s: %d", proto, count)

    return 0


if __name__ == "__main__":
    sys.exit(main())
