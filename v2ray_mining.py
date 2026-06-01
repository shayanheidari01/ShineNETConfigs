#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Mining order:
1) Telegram channels
2) v2nodes.com
3) GitHub fallback (ONLY if 1 & 2 are empty)

Then:
- Save configs to file
- Send configs to Telegram channel
"""

import base64
import json
import random
import re
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import List
from urllib.parse import quote

import requests
from bs4 import BeautifulSoup

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
REQUEST_TIMEOUT = 15
CONFIG_NAME = "ShineNET VPN ⚡️"

# Telegram publish settings (read from env in CI)
# BOT_TOKEN -> GitHub Secret
# TELEGRAM_CHAT_ID -> e.g. @FreeV2rayCH or numeric channel id
import os
BOT_TOKEN = os.getenv("BOT_TOKEN", "").strip()
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID", "@FreeV2rayCH").strip()

# Telegram max text length per message
TG_TEXT_LIMIT = 4096

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

# ---------------- VMESS FIX ----------------

def transform_vmess(uri: str) -> str:
    """
    Safely decode vmess payload, set "ps" name, then re-encode.
    """
    try:
        proto, payload = uri.split("://", 1)
        if proto.lower() != "vmess":
            return uri

        payload = payload.split("#")[0]
        payload += "=" * (-len(payload) % 4)

        decoded = base64.b64decode(payload).decode("utf-8", errors="ignore")
        data = json.loads(decoded)

        data["ps"] = CONFIG_NAME

        encoded = base64.b64encode(
            json.dumps(data, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        ).decode("utf-8")

        return f"vmess://{encoded}"
    except Exception:
        return uri

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

# ---------------- CLEAN ----------------

def clean_uri(uri: str) -> str:
    uri = uri.strip().replace("\n", "").replace("\r", "")
    uri = uri.split()[0]
    uri = uri.split("#")[0]

    if uri.startswith("vmess://"):
        return transform_vmess(uri)

    # for non-vmess append fragment name
    uri = uri.rstrip("/")
    return f"{uri}#{CONFIG_NAME}"

# ---------------- TELEGRAM MINER ----------------

def mine_telegram() -> List[str]:
    print("[INFO] mining Telegram channels...")
    all_configs = []

    for channel in CHANNELS:
        print(f"[INFO] channel → {channel}")
        base = f"https://t.me/s/{channel}"
        posts = []

        for i in range(PAGES_TO_CHECK):
            url = base if i == 0 else f"{base}?before={i * 50}"
            try:
                response = requests.get(url, headers=random_headers(), timeout=REQUEST_TIMEOUT)
                response.raise_for_status()
                html = response.text
            except Exception:
                continue

            soup = BeautifulSoup(html, "html.parser")
            for p in soup.select(".tgme_widget_message_text"):
                posts.append(p.get_text("\n", strip=True))

        posts = list(dict.fromkeys(posts))[-50:]

        for text in posts:
            for c in URI_RE.findall(text):
                c = re.split(r"\s|\[|\(|➡|🔗|👇", c)[0]
                c = clean_uri(c)
                if validate(c):
                    all_configs.append(c)

    all_configs = list(dict.fromkeys(all_configs))
    print(f"[INFO] Telegram total configs: {len(all_configs)}")
    return all_configs

# ---------------- V2NODES MINER ----------------

def extract_from_server(url: str) -> List[str]:
    try:
        response = requests.get(url, headers=random_headers(), timeout=REQUEST_TIMEOUT)
        response.raise_for_status()
        html = response.text

        found = []
        for x in URI_RE.findall(html):
            x = clean_uri(x)
            if validate(x):
                found.append(x)

        return list(dict.fromkeys(found))
    except Exception:
        return []

def mine_v2nodes(pages: int = 5) -> List[str]:
    print("[INFO] mining v2nodes...")

    def fetch_page(page: int) -> List[str]:
        try:
            url = f"{V2_URL}/?page={page}"
            response = requests.get(url, headers=random_headers(), timeout=REQUEST_TIMEOUT)
            response.raise_for_status()
            soup = BeautifulSoup(response.text, "html.parser")
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
        final = list(ex.map(lambda r: extract_from_server(V2_URL + r), links))

    configs = list(dict.fromkeys(sum(final, [])))
    print(f"[INFO] v2nodes configs: {len(configs)}")
    return configs

# ---------------- FALLBACK MINER ----------------

def mine_fallback() -> List[str]:
    print("[INFO] mining fallback...")
    try:
        response = requests.get(FALLBACK_URL, headers=random_headers(), timeout=REQUEST_TIMEOUT)
        response.raise_for_status()
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

def save(configs: List[str]) -> None:
    OUTPUT_FILE.write_text("\n\n".join(configs) + "\n", encoding="utf-8")
    print(f"[INFO] saved {len(configs)} configs -> {OUTPUT_FILE}")

# ---------------- TELEGRAM PUBLISH ----------------

def tg_send_message(text: str) -> bool:
    if not BOT_TOKEN or not TELEGRAM_CHAT_ID:
        print("[WARN] BOT_TOKEN/TELEGRAM_CHAT_ID not set. Skipping Telegram send.")
        return False

    url = f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage"
    payload = {
        "chat_id": TELEGRAM_CHAT_ID,
        "text": text,
        "disable_web_page_preview": True,
    }
    try:
        r = requests.post(url, json=payload, timeout=REQUEST_TIMEOUT)
        if r.status_code != 200:
            print(f"[WARN] Telegram send failed: {r.status_code} | {r.text[:300]}")
            return False
        return True
    except Exception as e:
        print(f"[WARN] Telegram send exception: {e}")
        return False

def send_configs_to_channel(configs: List[str]) -> None:
    if not configs:
        tg_send_message("❌ هیچ کانفیگی پیدا نشد.")
        return

    header = f"✅ Total configs: {len(configs)}\n\n"
    buffer = header

    sent_count = 0
    for c in configs:
        line = c + "\n"
        if len(buffer) + len(line) > TG_TEXT_LIMIT:
            if tg_send_message(buffer):
                sent_count += 1
            buffer = line
        else:
            buffer += line

    if buffer.strip():
        if tg_send_message(buffer):
            sent_count += 1

    print(f"[INFO] Telegram messages sent: {sent_count}")

# ---------------- MAIN ----------------

def main():
    telegram_configs = mine_telegram()
    v2_configs = mine_v2nodes()

    if not telegram_configs and not v2_configs:
        print("[WARN] Telegram + v2nodes empty → fallback...")
        configs = mine_fallback()
    else:
        configs = telegram_configs + v2_configs

    configs = list(dict.fromkeys(configs))

    if not configs:
        print("[ERROR] nothing found.")
        send_configs_to_channel([])
        sys.exit(1)

    save(configs)
    send_configs_to_channel(configs)
    print("✅ Done.")

if __name__ == "__main__":
    main()
