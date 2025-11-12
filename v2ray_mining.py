#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
v2ray_mining.py (Anti-block + fallback)
---------------------------------------

ویژگی‌ها:
- استخراج لینک‌های vmess/vless/trojan/ss از v2nodes.com
- ضد بلاک 403 با IP جعلی و User-Agent تصادفی
- اعتبارسنجی پایه‌ی لینک‌ها
- ذخیره در configs.txt
- در صورت بی‌نتیجه بودن، استفاده از سورس بکاپ GitHub
"""

import requests
from bs4 import BeautifulSoup
import re
import sys
from pathlib import Path
import json
import base64
from concurrent.futures import ThreadPoolExecutor
import random

# ---------------- SETTINGS ----------------
BASE_URL = "https://www.v2nodes.com"
FALLBACK_URL = "https://raw.githubusercontent.com/darkvpnapp/CloudflarePlus/refs/heads/main/proxy"
PAGES_TO_SCRAPE = 1
REQUEST_TIMEOUT = 12
OUTPUT_FILE = Path("configs.txt")
# ------------------------------------------

URI_RE = re.compile(
    r'(?:vless|vmess|trojan|ss)://[^\s\'\"<>()[\]{}]+(?:#[^\n\r]{0,200})?', re.IGNORECASE
)
FLAG_RE = re.compile(r'[\U0001F1E6-\U0001F1FF]{2}')

# چند user-agent تصادفی برای ضد بلاک
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) Gecko/20100101 Firefox/117.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_3_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.5 Safari/605.1.15",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 16_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.3 Mobile/15E148 Safari/604.1"
]


def random_ip():
    """ساخت IP جعلی برای ارسال در هدر"""
    return ".".join(str(random.randint(1, 255)) for _ in range(4))


def random_headers():
    """ایجاد هدر تصادفی با IP و User-Agent متفاوت"""
    return {
        "User-Agent": random.choice(USER_AGENTS),
        "Accept": "*/*",
        "Connection": "keep-alive",
        "X-Forwarded-For": random_ip(),
        "Client-IP": random_ip(),
        "Referer": BASE_URL,
        "Accept-Language": "en-US,en;q=0.9",
    }


def clean_uri(uri: str) -> str:
    if not uri:
        return uri
    uri = uri.strip().strip(' \t\n\r"\'')
    while uri.startswith('(') and uri.endswith(')'):
        uri = uri[1:-1].strip()
    return uri.rstrip('.,;:!?)"\' ]')


def extract_flag_from_ps(ps: str) -> str:
    if not ps:
        return ""
    m = FLAG_RE.search(ps)
    if m:
        return m.group(0)
    return ps.strip()[:4]


def transform_vmess(uri: str) -> str:
    try:
        prefix, payload = uri.split('://', 1)
    except ValueError:
        return uri
    if prefix.lower() != 'vmess':
        return uri
    frag = ''
    if '#' in payload:
        payload, frag = payload.split('#', 1)
    missing_padding = len(payload) % 4
    if missing_padding:
        payload += '=' * (4 - missing_padding)
    try:
        decoded = base64.b64decode(payload).decode('utf-8', errors='replace')
        data = json.loads(decoded)
    except Exception:
        return uri
    ps = data.get('ps', '') or ''
    flag = extract_flag_from_ps(ps)
    if flag:
        data['ps'] = flag
    try:
        new_json = json.dumps(data, ensure_ascii=False, separators=(',', ':'))
        new_b64 = base64.b64encode(new_json.encode('utf-8')).decode('utf-8')
        return 'vmess://' + new_b64 + (('#' + frag) if frag else '')
    except Exception:
        return uri


def validate_uri_basic(uri: str) -> bool:
    if not uri or '://' not in uri:
        return False
    scheme = uri.split('://', 1)[0].lower()
    if scheme not in ('vmess', 'vless', 'trojan', 'ss'):
        return False
    if scheme == 'vmess':
        payload = uri.split('://', 1)[1].split('#')[0]
        if len(payload) < 16:
            return False
        try:
            missing = len(payload) % 4
            if missing:
                payload += '=' * (4 - missing)
            decoded = base64.b64decode(payload)
            text = decoded.decode('utf-8', errors='ignore')
            return text.strip().startswith('{') and 'ps' in text
        except Exception:
            return False
    if scheme == 'vless':
        return ('@' in uri and ':' in uri)
    if scheme == 'trojan':
        return len(uri) > 10 and '@' in uri
    if scheme == 'ss':
        return len(uri) > 8
    return False


def extract_configs_from_html(html: str) -> list:
    found = []
    for m in URI_RE.findall(html):
        uri = clean_uri(m)
        if uri.lower().startswith('vmess://'):
            uri = transform_vmess(uri)
        if validate_uri_basic(uri):
            found.append(uri)
    return list(dict.fromkeys(found))


def extract_from_server(server_url: str) -> list:
    try:
        resp = requests.get(server_url, headers=random_headers(), timeout=REQUEST_TIMEOUT)
        resp.raise_for_status()
        html = resp.text
        return extract_configs_from_html(html)
    except Exception as e:
        print(f"[WARN] fetch error {server_url}: {e}", file=sys.stderr)
        return []


def scrape(base_url=BASE_URL, pages=PAGES_TO_SCRAPE):
    def fetch_page(page):
        url = f"{base_url}/?page={page}"
        try:
            resp = requests.get(url, headers=random_headers(), timeout=REQUEST_TIMEOUT)
            resp.raise_for_status()
            soup = BeautifulSoup(resp.text, 'html.parser')
            links = [a['href'] for a in soup.find_all('a', href=True) if re.match(r'^/servers/\d+/?', a['href'])]
            return links
        except Exception as e:
            print(f"[WARN] index fetch error {url}: {e}")
            return []

    print(f"[INFO] scraping {pages} index pages concurrently...")
    with ThreadPoolExecutor(max_workers=5) as ex:
        page_results = list(ex.map(fetch_page, range(1, pages + 1)))

    all_links = list(dict.fromkeys(sum(page_results, [])))
    print(f"[INFO] total unique server links: {len(all_links)}")

    if not all_links:
        return []

    def fetch_server(rel):
        return extract_from_server(base_url + rel)

    print("[INFO] scraping server pages concurrently...")
    with ThreadPoolExecutor(max_workers=10) as ex:
        server_results = list(ex.map(fetch_server, all_links))

    configs = list(dict.fromkeys(sum(server_results, [])))
    return configs


def fetch_fallback():
    """در صورت بی‌نتیجه بودن scraping، از سورس GitHub استفاده می‌شود"""
    try:
        print(f"[INFO] fetching fallback configs from {FALLBACK_URL} ...")
        resp = requests.get(FALLBACK_URL, headers=random_headers(), timeout=REQUEST_TIMEOUT)
        resp.raise_for_status()
        text = resp.text
        found = [clean_uri(x) for x in URI_RE.findall(text) if validate_uri_basic(x)]
        print(f"[INFO] fetched {len(found)} fallback configs.")
        return list(dict.fromkeys(found))
    except Exception as e:
        print(f"[ERROR] fallback fetch failed: {e}")
        return []


def save_configs(configs: list, out_file: Path):
    out_file.parent.mkdir(parents=True, exist_ok=True)
    out_file.write_text("\n".join(configs) + "\n", encoding="utf-8")
    print(f"[INFO] saved {len(configs)} configs to {out_file}")


if __name__ == "__main__":
    configs = scrape()

    if not configs:
        print("[WARN] No configs found from v2nodes, using fallback...")
        configs = fetch_fallback()

    if not configs:
        print("[ERROR] No configs found at all.")
        sys.exit(1)

    save_configs(configs, OUTPUT_FILE)
    print("✅ Done.")
