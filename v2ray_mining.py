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
from concurrent.futures import ThreadPoolExecutor


# ---------------- SETTINGS ----------------
CHANNELS = [
    "ConfigsHUB2",
    "V2WRAY",
 #   "MARAMBASHI",
#    "configshere",
]

PAGES_TO_CHECK = 8

V2_URL = "https://www.v2nodes.com"
FALLBACK_URL = "https://raw.githubusercontent.com/darkvpnapp/CloudflarePlus/refs/heads/main/proxy"

OUTPUT_FILE = Path("configs.txt")
REQUEST_TIMEOUT = 12
# ------------------------------------------


URI_RE = re.compile(
    r'(?:vless|vmess|trojan|ss)://[^\s\'\"<>()[\]{}]+',
    re.IGNORECASE
)

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; x64) Chrome/122",
    "Mozilla/5.0 (X11; Linux) Firefox/117",
    "Mozilla/5.0 (iPhone) Safari/604",
]


def random_ip():
    return ".".join(str(random.randint(1, 255)) for _ in range(4))


def random_headers():
    return {
        "User-Agent": random.choice(USER_AGENTS),
        "X-Forwarded-For": random_ip(),
        "Client-IP": random_ip(),
        "Accept": "*/*",
    }


# ---------------- VMESS FIX ----------------
def transform_vmess(uri: str) -> str:
    try:
        proto, payload = uri.split("://", 1)
        if proto.lower() != "vmess":
            return uri

        payload = payload.split("#")[0]
        pad = len(payload) % 4
        if pad:
            payload += "=" * (4 - pad)

        data = json.loads(base64.b64decode(payload))
        data["ps"] = "🏴‍Shine"

        jb = json.dumps(
            data,
            ensure_ascii=False,
            separators=(",", ":")
        )
        return "vmess://" + base64.b64encode(jb.encode()).decode()
    except Exception:
        return uri


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
