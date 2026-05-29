#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Mining order:
1- Telegram (multiple channels)
2- v2nodes.com
3- GitHub fallback (ONLY if both empty)
"""

import requests
from bs4 import BeautifulSoup
import re
from pathlib import Path
import base64
import json
import random
import sys
from urllib.parse import unquote
from concurrent.futures import ThreadPoolExecutor


# ---------------- SETTINGS ----------------
CHANNELS = [
    "ConfigsHUB2",
    # "V2WRAY",
    # "MARAMBASHI",
    # "configshere",
]

PAGES_TO_CHECK = 8

V2_URL = "https://www.v2nodes.com"
FALLBACK_URL = "https://raw.githubusercontent.com/darkvpnapp/CloudflarePlus/refs/heads/main/proxy"

OUTPUT_FILE = Path("configs.txt")
REQUEST_TIMEOUT = 12

CONFIG_NAME = "ShineNET VPN ⚡️"

# ------------------------------------------


URI_RE = re.compile(
    r'(?:vless|vmess|trojan|ss)://[^\s\'\"<>()[\]{}]+',
    re.IGNORECASE
)

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/122",
    "Mozilla/5.0 (X11; Linux x86_64) Firefox/117",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) Safari/604",
]


# ---------------- RANDOM ----------------
def random_ip():
    return ".".join(str(random.randint(1, 255)) for _ in range(4))


def random_headers():
    return {
        "User-Agent": random.choice(USER_AGENTS),
        "X-Forwarded-For": random_ip(),
        "Client-IP": random_ip(),
        "Accept": "*/*",
        "Connection": "keep-alive",
    }


# ---------------- VMESS FIX ----------------
def transform_vmess(uri: str) -> str:
    """
    Fix vmess name safely.
    """

    try:
        proto, payload = uri.split("://", 1)

        if proto.lower() != "vmess":
            return uri

        # remove old fragment
        payload = payload.split("#")[0]

        # base64 padding
        payload += "=" * (-len(payload) % 4)

        decoded = base64.b64decode(payload).decode("utf-8", errors="ignore")
        data = json.loads(decoded)

        # replace config name
        data["ps"] = CONFIG_NAME

        encoded = base64.b64encode(
            json.dumps(
                data,
                ensure_ascii=False,
                separators=(",", ":")
            ).encode()
        ).decode()

        return f"vmess://{encoded}"

    except Exception:
        return uri


# ---------------- VALIDATION ----------------
def validate(uri: str) -> bool:
    u = uri.lower()

    if u.startswith("vmess://"):
        return len(uri.split("://")[1]) > 16

    if u.startswith(("vless://", "trojan://")):
        return "@" in uri and ":" in uri

    if u.startswith("ss://"):
        return True

    return False


# ---------------- CLEAN ----------------
def clean_uri(uri: str) -> str:
    """
    Normalize config and fix names.
    """

    uri = uri.strip()

    # remove spaces/newlines
    uri = uri.replace("\n", "").replace("\r", "")

    # remove duplicated fragments
    uri = uri.split("#")[0]

    # fix vmess separately
    if uri.startswith("vmess://"):
        return transform_vmess(uri)

    # remove ending slash only if safe
    if not re.search(r"://[^/]+/$", uri):
        uri = uri.rstrip("/")

    # final clean name
    return f"{uri}#{CONFIG_NAME}"


# ---------------- TELEGRAM ----------------
def mine_telegram():
    print("[INFO] mining Telegram channels...")

    all_configs = []

    for channel in CHANNELS:

        print(f"[INFO] channel → {channel}")

        base = f"https://t.me/s/{channel}"

        posts = []

        for i in range(PAGES_TO_CHECK):

            url = base if i == 0 else f"{base}?before={i * 50}"

            try:
                response = requests.get(
                    url,
                    headers=random_headers(),
                    timeout=REQUEST_TIMEOUT
                )

                html = response.text

            except Exception:
                continue

            soup = BeautifulSoup(html, "html.parser")

            for p in soup.select(".tgme_widget_message_text"):
                posts.append(
                    p.get_text("\n", strip=True)
                )

        # unique + latest
        posts = list(dict.fromkeys(posts))[-50:]

        for text in posts:

            for c in URI_RE.findall(text):

                c = re.split(
                    r"\s|\[|\(|➡|🔗|👇",
                    c
                )[0]

                c = clean_uri(c)

                if validate(c):
                    print(c)
                    all_configs.append(c)

    all_configs = list(dict.fromkeys(all_configs))

    print(f"[INFO] Telegram total configs: {len(all_configs)}")

    return all_configs


# ---------------- V2NODES ----------------
def extract_from_server(url):

    try:
        response = requests.get(
            url,
            headers=random_headers(),
            timeout=REQUEST_TIMEOUT
        )

        html = response.text

        found = []

        for x in URI_RE.findall(html):

            x = clean_uri(x)

            if validate(x):
                found.append(x)

        return list(dict.fromkeys(found))

    except Exception:
        return []


def mine_v2nodes(pages=5):

    print("[INFO] mining v2nodes...")

    def fetch_page(page):

        try:
            url = f"{V2_URL}/?page={page}"

            response = requests.get(
                url,
                headers=random_headers(),
                timeout=REQUEST_TIMEOUT
            )

            html = response.text

            soup = BeautifulSoup(html, "html.parser")

            return [
                a["href"]
                for a in soup.find_all("a", href=True)
                if a["href"].startswith("/servers/")
            ]

        except Exception:
            return []

    with ThreadPoolExecutor(max_workers=5) as ex:
        res = list(
            ex.map(fetch_page, range(1, pages + 1))
        )

    links = list(dict.fromkeys(sum(res, [])))

    if not links:
        return []

    with ThreadPoolExecutor(max_workers=10) as ex:

        final = list(
            ex.map(
                lambda r: extract_from_server(V2_URL + r),
                links
            )
        )

    configs = list(dict.fromkeys(sum(final, [])))

    print(f"[INFO] v2nodes configs: {len(configs)}")

    return configs


# ---------------- FALLBACK ----------------
def mine_fallback():

    print("[INFO] mining fallback...")

    try:
        response = requests.get(
            FALLBACK_URL,
            headers=random_headers(),
            timeout=REQUEST_TIMEOUT
        )

        html = response.text

        configs = []

        for x in URI_RE.findall(html):

            x = clean_uri(x)

            if validate(x):
                configs.append(x)

        configs = list(dict.fromkeys(configs))

        print(f"[INFO] fallback configs: {len(configs)}")

        return configs

    except Exception:
        return []


# ---------------- SAVE ----------------
def save(configs):

    OUTPUT_FILE.write_text(
        "\n\n".join(configs) + "\n",
        encoding="utf-8"
    )

    print(f"[INFO] saved {len(configs)} configs")


# ---------------- MAIN ----------------
if __name__ == "__main__":

    telegram_configs = mine_telegram()

    v2_configs = mine_v2nodes()

    if not telegram_configs and not v2_configs:

        print("[WARN] Telegram + v2nodes empty → fallback…")

        configs = mine_fallback()

    else:
        configs = telegram_configs + v2_configs

    # unique
    configs = list(dict.fromkeys(configs))

    if not configs:

        print("[ERROR] nothing found.")

        sys.exit(1)

    save(configs)

    print("✅ Done.")
def validate(uri: str) -> bool:
    u = uri.lower()
    if u.startswith("vmess://"):
        return len(uri.split("://")[1]) > 16
    if u.startswith(("vless://", "trojan://")):
        return "@" in uri and ":" in uri
    if u.startswith("ss://"):
        return True
    return False


def clean_uri(uri: str) -> str:
    uri = uri.strip().rstrip("/")
    if uri.startswith("vmess://"):
        uri = transform_vmess(uri)
    return uri + "ShineNET VPN ⚡️"


# ---------------- 1) TELEGRAM ----------------
def mine_telegram():
    print("[INFO] mining Telegram channels...")
    all_configs = []

    for channel in CHANNELS:
        print(f"[INFO] channel → {channel}")
        base = f"https://t.me/s/{channel}"
        posts = []

        for i in range(PAGES_TO_CHECK):
            url = base if i == 0 else f"{base}?before={i * 50}"
            try:
                html = requests.get(
                    url,
                    headers=random_headers(),
                    timeout=REQUEST_TIMEOUT
                ).text
            except Exception:
                continue

            soup = BeautifulSoup(html, "html.parser")
            for p in soup.select(".tgme_widget_message_text"):
                posts.append(p.get_text("\n", strip=True))

        posts = list(dict.fromkeys(posts))[-50:]

        for text in posts:
            for c in URI_RE.findall(text):
                c = re.split(
                    r"#|\s|\[|\(|$|➡|🔗|👇",
                    "#"+c
                )[0]
                c = clean_uri(c)
                if validate(c):
                    all_configs.append(c)

    all_configs = list(dict.fromkeys(all_configs))
    print(f"[INFO] Telegram total configs: {len(all_configs)}")
    return all_configs


# ---------------- 2) V2NODES ----------------
def extract_from_server(url):
    try:
        html = requests.get(
            url,
            headers=random_headers(),
            timeout=REQUEST_TIMEOUT
        ).text

        found = []
        for x in URI_RE.findall(html):
            x = clean_uri(x)
            if validate(x):
                found.append(x)

        return list(dict.fromkeys(found))
    except Exception:
        return []


def mine_v2nodes(pages=5):
    print("[INFO] mining v2nodes...")
    links = []

    def fetch_page(page):
        try:
            url = f"{V2_URL}/?page={page}"
            html = requests.get(
                url,
                headers=random_headers(),
                timeout=REQUEST_TIMEOUT
            ).text

            soup = BeautifulSoup(html, "html.parser")
            return [
                a["href"]
                for a in soup.find_all("a", href=True)
                if a["href"].startswith("/servers/")
            ]
        except Exception:
            return []

    with ThreadPoolExecutor(max_workers=5) as ex:
        res = list(ex.map(fetch_page, range(1, pages + 1)))

    links = list(dict.fromkeys(sum(res, [])))
    if not links:
        return []

    with ThreadPoolExecutor(max_workers=10) as ex:
        final = list(
            ex.map(
                lambda r: extract_from_server(V2_URL + r),
                links
            )
        )

    configs = list(dict.fromkeys(sum(final, [])))
    print(f"[INFO] v2nodes configs: {len(configs)}")
    return configs


# ---------------- 3) FALLBACK ----------------
def mine_fallback():
    print("[INFO] mining fallback...")
    try:
        html = requests.get(
            FALLBACK_URL,
            headers=random_headers(),
            timeout=REQUEST_TIMEOUT
        ).text

        configs = []
        for x in URI_RE.findall(html):
            x = clean_uri(x)
            if validate(x):
                configs.append(x)

        configs = list(dict.fromkeys(configs))
        print(f"[INFO] fallback configs: {len(configs)}")
        return configs
    except Exception:
        return []


# ---------------- SAVE ----------------
def save(configs):
    OUTPUT_FILE.write_text(
        "\n\n".join(configs) + "\n",
        encoding="utf-8"
    )
    print(f"[INFO] saved {len(configs)} configs")


# ---------------- MAIN ----------------
if __name__ == "__main__":

    telegram_configs = mine_telegram()
    v2_configs = mine_v2nodes()

    if not telegram_configs and not v2_configs:
        print("[WARN] Telegram + v2nodes empty → fallback…")
        configs = mine_fallback()
    else:
        configs = telegram_configs + v2_configs

    configs = list(dict.fromkeys(configs))

    if not configs:
        print("[ERROR] nothing found.")
        sys.exit(1)

    save(configs)
    print("✅ Done.")
