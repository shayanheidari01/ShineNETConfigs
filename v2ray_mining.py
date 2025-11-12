#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
v2ray_mining.py

Final enhanced version:
- Rotates User-Agent strings
- Rotates/sets fake IP headers (X-Forwarded-For, X-Real-IP, Client-IP, Forwarded, CF-Connecting-IP, ...)
- Uses requests.Session with retries for transient errors
- Exponential backoff + jitter on 403 and rate limits
- Proxy support via PROXIES env var or standard HTTP_PROXY/HTTPS_PROXY
- Alternative base URLs support via ALTERNATIVE_BASES env var
- Reduced concurrency mode when blocking detected
- Keeps original vmess transformation, lightweight validation and saving logic
- Detailed warnings/logs on failures (prints status, attempt, proxy, UA, and key headers)
"""

from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import base64
import json
import re
import sys
import time
import random
import os
from typing import List, Optional
import requests
from bs4 import BeautifulSoup
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# ---------------- SETTINGS ----------------
BASE_URL = os.environ.get("BASE_URL", "https://www.v2nodes.com")
ALTERNATIVE_BASES = [u.strip() for u in os.environ.get("ALTERNATIVE_BASES", "").split(",") if u.strip()]
PAGES_TO_SCRAPE = int(os.environ.get("PAGES_TO_SCRAPE", "1"))
REQUEST_TIMEOUT = int(os.environ.get("REQUEST_TIMEOUT", "12"))
OUTPUT_FILE = Path(os.environ.get("OUTPUT_FILE", "configs.txt"))
SLEEP_BETWEEN_REQUESTS = float(os.environ.get("SLEEP_BETWEEN_REQUESTS", "0.5"))
MAX_WORKERS_DEFAULT = int(os.environ.get("MAX_WORKERS", "10"))
MAX_403_ATTEMPTS = int(os.environ.get("MAX_403_ATTEMPTS", "6"))
# ------------------------------------------

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.4 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1"
]

# proxies support
PROXIES_ENV = [p.strip() for p in os.environ.get("PROXIES", "").split(",") if p.strip()]
STANDARD_HTTP_PROXY = os.environ.get("HTTP_PROXY") or os.environ.get("http_proxy")
STANDARD_HTTPS_PROXY = os.environ.get("HTTPS_PROXY") or os.environ.get("https_proxy")
if STANDARD_HTTP_PROXY and STANDARD_HTTP_PROXY not in PROXIES_ENV:
    PROXIES_ENV.append(STANDARD_HTTP_PROXY)
if STANDARD_HTTPS_PROXY and STANDARD_HTTPS_PROXY not in PROXIES_ENV:
    PROXIES_ENV.append(STANDARD_HTTPS_PROXY)

BASE_HEADERS = {
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
    'Accept-Language': 'en-US,en;q=0.9',
    'Accept-Encoding': 'gzip, deflate, br',
    'Connection': 'keep-alive',
}

URI_RE = re.compile(
    r'(?:vless|vmess|trojan|ss)://'            # scheme
    r'[^\s\'\"<>()[\]{}]+'                     # body until a breaking char
    r'(?:#[^\n\r]{0,200})?',                  # optional fragment up to newline (max 200 chars)
    re.IGNORECASE
)

FLAG_RE = re.compile(r'[\U0001F1E6-\U0001F1FF]{2}')

# ---------- IP fakery helpers ----------
def random_ipv4():
    while True:
        a = random.randint(1, 223)
        b = random.randint(0, 255)
        c = random.randint(0, 255)
        d = random.randint(1, 254)
        # skip common private/reserved
        if a == 10 or a == 127 or (a == 169 and b == 254) or (a == 192 and b == 168) or (a == 172 and 16 <= b <= 31):
            continue
        if 224 <= a <= 255:
            continue
        return f"{a}.{b}.{c}.{d}"

def random_ipv6():
    parts = [format(random.randint(0, 0xffff), 'x') for _ in range(8)]
    return ":".join(parts)

def random_ip(pref='ipv4'):
    if pref == 'ipv6':
        return random_ipv6()
    return random_ipv4()

def random_x_forwarded_for(count=1):
    ips = [random_ip() for _ in range(count)]
    return ", ".join(ips)
# ---------- end helpers ----------

def random_sleep(min_s=0.2, max_s=1.0):
    time.sleep(random.uniform(min_s, max_s))

def make_session(proxy: Optional[str] = None, backoff_factor: float = 0.5) -> requests.Session:
    session = requests.Session()
    retries = Retry(
        total=3,
        backoff_factor=backoff_factor,
        status_forcelist=(429, 500, 502, 503, 504),
        allowed_methods=frozenset(['GET', 'POST', 'HEAD', 'OPTIONS'])
    )
    adapter = HTTPAdapter(max_retries=retries)
    session.mount('http://', adapter)
    session.mount('https://', adapter)
    if proxy:
        session.proxies.update({'http': proxy, 'https': proxy})
    return session

def choose_proxy(attempt: int) -> Optional[str]:
    if not PROXIES_ENV:
        return None
    return random.choice(PROXIES_ENV)

def build_headers():
    ua = random.choice(USER_AGENTS)
    h = BASE_HEADERS.copy()
    h['User-Agent'] = ua
    h['Referer'] = random.choice([BASE_URL, BASE_URL + '/', BASE_URL + '/?page=1'])
    h['Accept-Language'] = 'en-US,en;q=0.9'

    fake_client_ip = random_ip()
    h['X-Real-IP'] = fake_client_ip
    h['Client-IP'] = fake_client_ip
    h['True-Client-IP'] = fake_client_ip

    h['X-Forwarded-For'] = random_x_forwarded_for(count=random.choice([1,2,3]))

    try:
        proto = 'https' if str(BASE_URL).startswith('https') else 'http'
    except Exception:
        proto = random.choice(['http','https'])
    h['Forwarded'] = f'for={fake_client_ip};proto={proto}'

    h['CF-Connecting-IP'] = fake_client_ip
    h['X-Cluster-Client-IP'] = fake_client_ip
    h['X-Requested-With'] = random.choice(['XMLHttpRequest', '']) or 'XMLHttpRequest'

    return h

def clean_uri(uri: str) -> str:
    if not uri:
        return uri
    uri = uri.strip()
    uri = uri.strip(' \t\n\r"\'')
    while uri.startswith('(') and uri.endswith(')'):
        uri = uri[1:-1].strip()
    uri = uri.rstrip('.,;:!?)"\']')
    return uri

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
    payload = payload.strip()
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
    data['ps'] = flag if flag else ps.strip()
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
        payload = uri.split('://', 1)[1]
        if '#' in payload:
            payload = payload.split('#', 1)[0]
        if len(payload) < 16:
            return False
        try:
            missing = len(payload) % 4
            if missing:
                payload += '=' * (4 - missing)
            decoded = base64.b64decode(payload)
            text = decoded.decode('utf-8', errors='ignore')
            if text.strip().startswith('{') and 'ps' in text:
                return True
            return False
        except Exception:
            return False
    if scheme == 'vless':
        return ('@' in uri and ':' in uri)
    if scheme == 'trojan':
        return len(uri) > 10 and '@' in uri
    if scheme == 'ss':
        return len(uri) > 8
    return False

def extract_configs_from_html(html: str) -> List[str]:
    found = []
    for m in URI_RE.findall(html):
        candidate = clean_uri(m)
        candidate = transform_vmess(candidate) if candidate.lower().startswith('vmess://') else candidate
        found.append(candidate)

    soup = BeautifulSoup(html, 'html.parser')
    for a in soup.find_all('a', href=True):
        href = getattr(a, 'attrs', {}).get('href', '')
        if href:
            href = str(href).strip()
            text = a.get_text(separator=' ', strip=True)
            m_href = URI_RE.search(href)
            if m_href:
                uri = clean_uri(m_href.group(0))
                if uri.lower().startswith('vmess://'):
                    uri = transform_vmess(uri)
                if '#' in text:
                    idx = text.find('#')
                    frag = text[idx: idx + 200].split('\n', 1)[0].rstrip('.,;:!?)]"\'')
                    if '#' in uri:
                        if len(frag) > len(uri.split('#', 1)[1]):
                            uri = uri.split('#', 1)[0] + frag
                    else:
                        uri = uri + frag
                found.append(uri)
                continue
            if URI_RE.search(text):
                for m in URI_RE.findall(text):
                    uri = clean_uri(m)
                    if uri.lower().startswith('vmess://'):
                        uri = transform_vmess(uri)
                    found.append(uri)

    for tagname in ('pre', 'code', 'p', 'li', 'div', 'span'):
        for node in soup.find_all(tagname):
            txt = node.get_text(separator=' ', strip=True)
            if not txt:
                continue
            for m in URI_RE.findall(txt):
                uri = clean_uri(m)
                if uri.lower().startswith('vmess://'):
                    uri = transform_vmess(uri)
                found.append(uri)

    visible_text = soup.get_text(separator=' ', strip=True)
    for m in URI_RE.findall(visible_text):
        uri = clean_uri(m)
        if uri.lower().startswith('vmess://'):
            uri = transform_vmess(uri)
        found.append(uri)

    valid_found = []
    for uri in found:
        if not uri:
            continue
        if uri.lower().startswith('vless://') and ('@' not in uri or ':' not in uri):
            continue
        try:
            if validate_uri_basic(uri):
                valid_found.append(uri)
        except Exception:
            pass
    return list(dict.fromkeys(valid_found))

def fetch_with_anti_block(session: requests.Session, url: str, max_403_attempts: int = MAX_403_ATTEMPTS) -> Optional[str]:
    attempt = 0
    slow_mode = False
    while attempt < max_403_attempts:
        attempt += 1
        proxy = choose_proxy(attempt)
        if proxy:
            session.proxies.update({'http': proxy, 'https': proxy})
        headers = build_headers()
        try:
            random_sleep(0.1, 0.6)
            resp = session.get(url, headers=headers, timeout=REQUEST_TIMEOUT, allow_redirects=True)
            status = resp.status_code
            if status == 200:
                return resp.text
            if status == 403:
                # Log detailed info including the fake IP header used
                print(f"[WARN] 403 on {url} (attempt {attempt}/{max_403_attempts}), proxy={proxy}, ua={headers.get('User-Agent')}", file=sys.stderr)
                print(f"[WARN] headers sample: X-Forwarded-For={headers.get('X-Forwarded-For')}, X-Real-IP={headers.get('X-Real-IP')}", file=sys.stderr)
                if attempt >= 2:
                    slow_mode = True
                sleep_for = (2 ** attempt) + random.uniform(0.5, 2.0)
                if slow_mode:
                    sleep_for *= 1.5
                time.sleep(sleep_for)
                continue
            if 500 <= status < 600 or status == 429:
                print(f"[WARN] transient status {status} for {url} (attempt {attempt})", file=sys.stderr)
                time.sleep((1 + attempt) * 0.6)
                continue
            print(f"[WARN] unexpected status {status} for {url}", file=sys.stderr)
            return None
        except requests.RequestException as e:
            print(f"[WARN] request exception for {url}: {e} (attempt {attempt})", file=sys.stderr)
            time.sleep((1 + attempt) * 0.5)
            continue
    print(f"[WARN] exhausted attempts for {url}, giving up.", file=sys.stderr)
    return None

def extract_from_server(server_url: str) -> List[str]:
    session = make_session()
    html = fetch_with_anti_block(session, server_url)
    if not html:
        return []
    html = html.replace('\r\n', '\n').replace('\r', '\n')
    return extract_configs_from_html(html)

def scrape(base_url: str = BASE_URL, pages: int = PAGES_TO_SCRAPE) -> List[str]:
    def fetch_index_page(page: int) -> List[str]:
        page_url = f"{base_url}/?page={page}"
        session = make_session()
        html = fetch_with_anti_block(session, page_url)
        if not html:
            return []
        soup = BeautifulSoup(html, 'html.parser')
        server_links = []
        for a in soup.find_all('a', href=True):
            href = getattr(a, 'attrs', {}).get('href', '')
            if href:
                href = str(href).strip()
                if re.match(r'^/servers/\d+/?', href):
                    server_links.append(href)
        return server_links

    attempted_bases = [base_url] + ALTERNATIVE_BASES
    all_server_links = []
    for base_candidate in attempted_bases:
        print(f"[INFO] trying base URL: {base_candidate}")
        with ThreadPoolExecutor(max_workers=min(MAX_WORKERS_DEFAULT, 6)) as executor:
            page_results = list(executor.map(fetch_index_page, range(1, pages + 1)))
        links = []
        for lst in page_results:
            links.extend(lst)
        links = list(dict.fromkeys(links))
        if links:
            print(f"[INFO] found {len(links)} server links on {base_candidate}")
            base_url = base_candidate
            all_server_links = links
            break
        else:
            print(f"[WARN] no server links found on {base_candidate}, trying next mirror if available")
            time.sleep(1 + random.random() * 2)

    if not all_server_links:
        print("[WARN] total unique server links: 0")
        return []

    print(f"[INFO] total unique server links: {len(all_server_links)}")

    def fetch_server(rel: str) -> List[str]:
        server_url = base_url.rstrip('/') + rel
        return extract_from_server(server_url)

    print("[INFO] scraping server pages concurrently...")
    max_workers = min(MAX_WORKERS_DEFAULT, max(4, len(all_server_links)))
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        server_results = list(executor.map(fetch_server, all_server_links))

    results = []
    seen = set()
    for cfgs in server_results:
        for cfg in cfgs:
            if cfg not in seen:
                seen.add(cfg)
                results.append(cfg)
                print(f"    + new: {cfg[:200]}")
    return results

def save_configs(configs: List[str], out_file: Path):
    out_file.parent.mkdir(parents=True, exist_ok=True)
    text = "\n".join(configs) + ("\n" if configs else "")
    tmp = out_file.with_suffix('.tmp')
    tmp.write_text(text, encoding='utf-8')
    tmp.replace(out_file)
    print(f"[INFO] saved {len(configs)} configs to {out_file}")

if __name__ == "__main__":
    if os.environ.get("PAGES_TO_SCRAPE"):
        try:
            PAGES_TO_SCRAPE = int(os.environ.get("PAGES_TO_SCRAPE"))
        except Exception:
            pass

    configs = scrape()
    if not configs:
        print("No configs found from scraping.")
        exit(0)

    unique = []
    seen = set()
    for uri in configs:
        if uri in seen:
            continue
        seen.add(uri)
        if 'reality' in uri.lower() and 'spx=' not in uri:
            continue
        unique.append(uri)

    if not unique:
        print("No valid configurations found after basic filtering.")
        exit(0)

    save_configs(unique, OUTPUT_FILE)
    print("Done.")
