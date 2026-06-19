#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import base64
import json
import os
import random
import re
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import List

import requests
from bs4 import BeautifulSoup

# ---------------- SETTINGS ----------------

CHANNELS = [
    "iraniroid",
    "ConfigsHUB2",
]

PAGES_TO_CHECK = 2

V2_URL = "https://www.v2nodes.com"
FALLBACK_URL = "https://raw.githubusercontent.com/darkvpnapp/CloudflarePlus/refs/heads/main/proxy"

OUTPUT_FILE = Path("configs.txt")
REQUEST_TIMEOUT = 15

CONFIG_NAME = "ShineNET VPN ⚡️"
TELEGRAM_CONFIG_NAME = "Telegram: @FreeV2rayCH ⚡️"

BOT_TOKEN = os.getenv("BOT_TOKEN", "").strip()
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID", "@FreeV2rayCH").strip()

TG_TEXT_LIMIT = 4096
TG_SEND_DELAY_MIN = 0.8
TG_SEND_DELAY_MAX = 1.6
TG_MAX_RETRIES = 4

# ---------------- REGEX ----------------

URI_RE = re.compile(
    r'(?:vless|vmess|trojan|ss)://[^\s\'"<>()\[\]{}]+',
    re.IGNORECASE
)

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/122",
    "Mozilla/5.0 (X11; Linux x86_64) Firefox/117",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) Safari/604",
]

# ---------------- HELPERS ----------------

def random_ip() -> str:
    return ".".join(str(random.randint(1, 255)) for _ in range(4))

def random_headers() -> dict:
    return {
        "User-Agent": random.choice(USER_AGENTS),
        "X-Forwarded-For": random_ip(),
        "Client-IP": random_ip(),
        "Accept": "*/*",
        "Connection": "keep-alive",
    }

def mdv2_escape(text: str) -> str:
    special = r'_*[]()~`>#+-=|{}.!'
    return "".join("\\" + ch if ch in special else ch for ch in text)

def mdv2_code_block(text: str) -> str:
    text = text.replace("\\", "\\\\").replace("`", "\\`")
    return f"\n```\n{text}\n```"

# ---------------- CLEAN ----------------

def clean_uri(uri: str, name: str = CONFIG_NAME) -> str:
    uri = uri.strip().replace("\n", "").replace("\r", "")
    uri = uri.split()[0]
    uri = uri.split("#")[0]
    uri = uri.rstrip("/")
    return f"{uri}#{name}"

def rename_for_telegram(uri: str) -> str:
    return clean_uri(uri, name=TELEGRAM_CONFIG_NAME)

# ---------------- VALIDATION ----------------

def validate(uri: str) -> bool:
    u = uri.lower()

    if u.startswith("vmess://"):
        payload = uri.split("://", 1)[1]
        return len(payload) > 16

    if u.startswith(("vless://", "trojan://")):
        return "@" in uri and "://" in uri

    if u.startswith("ss://"):
        return len(uri.split("://", 1)[1]) > 6

    return False

# ---------------- TELEGRAM MINER ----------------

def mine_telegram() -> List[str]:
    all_configs = []

    for channel in CHANNELS:
        base = f"https://t.me/s/{channel}"
        posts = []

        for i in range(PAGES_TO_CHECK):
            url = base if i == 0 else f"{base}?before={i * 50}"
            try:
                r = requests.get(url, headers=random_headers(), timeout=REQUEST_TIMEOUT)
                r.raise_for_status()
            except Exception:
                continue

            soup = BeautifulSoup(r.text, "html.parser")
            for p in soup.select(".tgme_widget_message_text"):
                posts.append(p.get_text("\n", strip=True))

        # حفظ ترتیب طبیعی + حذف تکراری بدون shuffle
        seen = set()
        for text in posts:
            for c in URI_RE.findall(text):
                c = clean_uri(c)
                if validate(c) and c not in seen:
                    seen.add(c)
                    all_configs.append(c)

    return all_configs

# ---------------- V2 + FALLBACK ----------------

def extract_from_server(url: str) -> List[str]:
    try:
        r = requests.get(url, headers=random_headers(), timeout=REQUEST_TIMEOUT)
        r.raise_for_status()

        found = []
        for x in URI_RE.findall(r.text):
            x = clean_uri(x)
            if validate(x):
                found.append(x)

        return found
    except Exception:
        return []

def mine_v2nodes() -> List[str]:
    def fetch_page(page: int):
        try:
            url = f"{V2_URL}/?page={page}"
            r = requests.get(url, headers=random_headers(), timeout=REQUEST_TIMEOUT)
            r.raise_for_status()
            soup = BeautifulSoup(r.text, "html.parser")
            return [a["href"] for a in soup.find_all("a", href=True) if a["href"].startswith("/servers/")]
        except Exception:
            return []

    with ThreadPoolExecutor(max_workers=5) as ex:
        pages = list(ex.map(fetch_page, range(1, PAGES_TO_CHECK + 1)))

    links = []
    for p in pages:
        links.extend(p)

    seen = set()
    configs = []

    with ThreadPoolExecutor(max_workers=10) as ex:
        results = ex.map(lambda r: extract_from_server(V2_URL + r), links)

        for group in results:
            for c in group:
                if c not in seen:
                    seen.add(c)
                    configs.append(c)

    return configs

def mine_fallback() -> List[str]:
    try:
        r = requests.get(FALLBACK_URL, headers=random_headers(), timeout=REQUEST_TIMEOUT)
        r.raise_for_status()

        configs = []
        seen = set()

        for x in URI_RE.findall(r.text):
            x = clean_uri(x)
            if validate(x) and x not in seen:
                seen.add(x)
                configs.append(x)

        return configs
    except Exception:
        return []

# ---------------- SAVE (FIX اصلی) ----------------

def save(configs: List[str]) -> None:
    # 👇 مهم: فقط line-by-line بدون فاصله اضافی
    OUTPUT_FILE.write_text("\n".join(configs) + "\n", encoding="utf-8")
    print(f"[INFO] saved {len(configs)} configs -> {OUTPUT_FILE}")

# ---------------- MAIN ----------------

def main():
    telegram_configs = mine_telegram()
    v2_configs = mine_v2nodes()

    if not telegram_configs and not v2_configs:
        configs = mine_fallback()
    else:
        configs = telegram_configs + v2_configs

    # dedupe بدون تغییر ترتیب
    seen = set()
    final = []
    for c in configs:
        if c not in seen:
            seen.add(c)
            final.append(c)

    if not final:
        print("[ERROR] no configs found")
        sys.exit(1)

    save(final)
    print("DONE")

if __name__ == "__main__":
    main()
