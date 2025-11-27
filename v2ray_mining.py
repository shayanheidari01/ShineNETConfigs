#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Mining order:
1- Telegram
2- v2nodes.com
3- GitHub fallback
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
CHANNEL = "ConfigsHUB"
PAGES_TO_CHECK = 8
BASE = f"https://t.me/s/{CHANNEL}"

V2_URL = "https://www.v2nodes.com"
FALLBACK_URL = "https://raw.githubusercontent.com/darkvpnapp/CloudflarePlus/refs/heads/main/proxy"
OUTPUT_FILE = Path("configs.txt")
REQUEST_TIMEOUT = 12
# ------------------------------------------

URI_RE = re.compile(r'(?:vless|vmess|trojan|ss)://[^\s\'\"<>()[\]{}]+', re.IGNORECASE)

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; x64) Chrome/122",
    "Mozilla/5.0 (X11; Linux) Firefox/117",
    "Mozilla/5.0 (iPhone) Safari/604",
]


def random_ip():
    return ".".join(str(random.randint(1,255)) for _ in range(4))


def random_headers():
    return {
        "User-Agent": random.choice(USER_AGENTS),
        "X-Forwarded-For": random_ip(),
        "Client-IP": random_ip(),
        "Accept": "*/*",
    }


# ----- VMESS fix -----
def transform_vmess(uri: str) -> str:
    try:
        p, payload = uri.split("://", 1)
        if p.lower() != "vmess":
            return uri
        payload = payload.split('#')[0]
        pad = len(payload) % 4
        if pad:
            payload += "="*(4-pad)
        data = json.loads(base64.b64decode(payload))
        data['ps'] = "🏴‍Shine"
        jb = json.dumps(data, ensure_ascii=False, separators=(",", ":"))
        return "vmess://" + base64.b64encode(jb.encode()).decode()
    except:
        return uri


def validate(uri: str) -> bool:
    u = uri.lower()
    if u.startswith("vmess://"):
        return len(uri.split("://")[1]) > 16
    if u.startswith("vless://") or u.startswith("trojan://"):
        return '@' in uri and ':' in uri
    if u.startswith("ss://"):
        return True
    return False


def clean_uri(uri: str) -> str:
    uri = uri.strip().rstrip('/')
    if uri.startswith("vmess://"):
        uri = transform_vmess(uri)
    return uri + "#ShineNET%20VPN"


# -------- 1) Mining Telegram --------
def mine_telegram():
    print("[INFO] mining Telegram...")
    posts = []

    for i in range(PAGES_TO_CHECK):
        url = BASE if i == 0 else f"{BASE}?before={i*50}"
        try:
            html = requests.get(url, headers=random_headers(), timeout=REQUEST_TIMEOUT).text
        except:
            continue

        soup = BeautifulSoup(html, "html.parser")
        for p in soup.select(".tgme_widget_message_text"):
            posts.append(p.get_text("\n", strip=True))

    posts = list(dict.fromkeys(posts))
    posts = posts[-50:]

    configs = []
    for text in posts:
        for c in URI_RE.findall(text):
            c = re.split(r"#|\s|\[|\(|$|➡|🔗|👇", c)[0]
            c = clean_uri(c)
            if validate(c):
                configs.append(c)

    configs = list(dict.fromkeys(configs))
    print(f"[INFO] Telegram configs: {len(configs)}")
    return configs


# -------- 2) Mining v2nodes --------

def extract_from_server(url):
    try:
        html = requests.get(url, headers=random_headers(), timeout=REQUEST_TIMEOUT).text
        found = []
        for x in URI_RE.findall(html):
            x = clean_uri(x)
            if validate(x):
                found.append(x)
        return list(dict.fromkeys(found))
    except:
        return []


def mine_v2nodes(pages=5):
    print("[INFO] mining v2nodes...")
    links = []

    def fetch_page(page):
        try:
            url = f"{V2_URL}/?page={page}"
            html = requests.get(url, headers=random_headers(), timeout=REQUEST_TIMEOUT).text
            soup = BeautifulSoup(html, "html.parser")
            return [a['href'] for a in soup.find_all('a', href=True) if a['href'].startswith("/servers/")]
        except:
            return []

    with ThreadPoolExecutor(5) as ex:
        res = list(ex.map(fetch_page, range(1, pages+1)))

    links = list(dict.fromkeys(sum(res, [])))
    if not links:
        return []

    with ThreadPoolExecutor(10) as ex:
        final = list(ex.map(lambda r: extract_from_server(V2_URL+r), links))

    configs = list(dict.fromkeys(sum(final, [])))
    print(f"[INFO] v2nodes configs: {len(configs)}")
    return configs


# -------- 3) fallback --------

def mine_fallback():
    print("[INFO] mining fallback...")
    try:
        html = requests.get(FALLBACK_URL, headers=random_headers()).text
        configs = []
        for x in URI_RE.findall(html):
            x = clean_uri(x)
            if validate(x):
                configs.append(x)
        configs = list(dict.fromkeys(configs))
        print(f"[INFO] fallback configs: {len(configs)}")
        return configs
    except:
        return []


def save(configs):
    OUTPUT_FILE.write_text("\n".join(configs)+"\n", encoding="utf-8")
    print(f"[INFO] saved {len(configs)} configs")


# ------------- MAIN -------------

if __name__ == "__main__":
    configs = mine_telegram()

    if not configs:
        print("[WARN] Telegram failed → trying v2nodes…")
        configs = mine_v2nodes()

    if not configs:
        print("[WARN] v2nodes failed → trying fallback…")
        configs = mine_fallback()

    if not configs:
        print("[ERROR] nothing found.")
        sys.exit(1)

    save(configs)
    print("✅ Done.")FLAG_RE = re.compile(r'[\U0001F1E6-\U0001F1FF]{2}')

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
