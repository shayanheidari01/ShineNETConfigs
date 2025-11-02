#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
v2ray_mining.py

This version:
- Scrapes sites (default v2nodes) for vmess/vless/trojan/ss URIs
- Performs a lightweight local validation (no external packages)
- Transforms vmess entries to normalise their 'ps' field
- Saves unique, validated URIs into configs.txt

Designed to run on Linux/Windows/Mac — no external tester required.
"""

import requests
from bs4 import BeautifulSoup
import re
import sys
from pathlib import Path
import json
import base64
from concurrent.futures import ThreadPoolExecutor
import os

# ---------------- SETTINGS ----------------
BASE_URL = "https://www.v2nodes.com"
PAGES_TO_SCRAPE = 5
REQUEST_TIMEOUT = 12
HEADERS = {
    'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120 Safari/537.36'
}
OUTPUT_FILE = Path("configs.txt")
SLEEP_BETWEEN_REQUESTS = 0.5  # polite crawling (not enforced here to keep things simple)
# ------------------------------------------

URI_RE = re.compile(
    r'(?:vless|vmess|trojan|ss)://'            # scheme
    r'[^\s\'\"<>()[\]{}]+'                     # body until a breaking char
    r'(?:#[^\n\r]{0,200})?',                  # optional fragment up to newline (max 200 chars)
    re.IGNORECASE
)

FLAG_RE = re.compile(r'[\U0001F1E6-\U0001F1FF]{2}')


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
    """Attempt to decode vmess payload, normalise 'ps' to a short flag when possible.
    If decoding/parsing fails, return original uri unchanged.
    """
    try:
        prefix, payload = uri.split('://', 1)
    except ValueError:
        return uri
    if prefix.lower() != 'vmess':
        return uri
    payload = payload.strip()
    # strip fragment for decoding
    frag = ''
    if '#' in payload:
        payload, frag = payload.split('#', 1)
    # pad base64
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
    else:
        data['ps'] = ps.strip()
    try:
        new_json = json.dumps(data, ensure_ascii=False, separators=(',', ':'))
        new_b64 = base64.b64encode(new_json.encode('utf-8')).decode('utf-8')
        return 'vmess://' + new_b64 + (('#' + frag) if frag else '')
    except Exception:
        return uri


def validate_uri_basic(uri: str) -> bool:
    """A lightweight validation that avoids external dependencies.
    - vmess: try to base64-decode JSON payload
    - vless: require '@' and ':' (basic form)
    - trojan: check minimal length
    - ss: accept (more complex SS parsing omitted)

    This intentionally errs on the side of permissiveness (to keep
    scraped configs) while blocking obvious garbage.
    """
    if not uri or '://' not in uri:
        return False
    scheme = uri.split('://', 1)[0].lower()
    if scheme not in ('vmess', 'vless', 'trojan', 'ss'):
        return False
    if scheme == 'vmess':
        payload = uri.split('://', 1)[1]
        if '#' in payload:
            payload = payload.split('#', 1)[0]
        # ensure length looks reasonable
        if len(payload) < 16:
            return False
        try:
            missing = len(payload) % 4
            if missing:
                payload += '=' * (4 - missing)
            decoded = base64.b64decode(payload)
            # check if it looks like JSON
            text = decoded.decode('utf-8', errors='ignore')
            if text.strip().startswith('{') and 'ps' in text:
                return True
            return False
        except Exception:
            return False
    if scheme == 'vless':
        # vless typically contains user@host:port or path; basic sanity
        return ('@' in uri and ':' in uri)
    if scheme == 'trojan':
        # trojan://password@host:port
        return len(uri) > 10 and '@' in uri
    if scheme == 'ss':
        # many ss links are base64 payloads; accept for now
        return len(uri) > 8
    return False


def extract_configs_from_html(html: str) -> list:
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

    # Basic validation using validate_uri_basic
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
            # be forgiving
            pass
    # preserve order and uniqueness
    return list(dict.fromkeys(valid_found))


def extract_from_server(server_url: str) -> list:
    try:
        resp = requests.get(server_url, headers=HEADERS, timeout=REQUEST_TIMEOUT)
        resp.raise_for_status()
        html = resp.text.replace('\r\n', '\n').replace('\r', '\n')
        return extract_configs_from_html(html)
    except Exception as e:
        print(f"[WARN] fetch error {server_url}: {e}", file=sys.stderr)
        return []


def scrape(base_url=BASE_URL, pages=PAGES_TO_SCRAPE):
    def fetch_page(page):
        page_url = f"{base_url}/?page={page}"
        try:
            resp = requests.get(page_url, headers=HEADERS, timeout=REQUEST_TIMEOUT)
            resp.raise_for_status()
            soup = BeautifulSoup(resp.text, 'html.parser')
            server_links = []
            for a in soup.find_all('a', href=True):
                href = getattr(a, 'attrs', {}).get('href', '')
                if href:
                    href = str(href).strip()
                    if re.match(r'^/servers/\d+/?', href):
                        server_links.append(href)
            return server_links
        except Exception as e:
            print(f"[WARN] index fetch error {page_url}: {e}", file=sys.stderr)
            return []

    print(f"[INFO] scraping {pages} index pages concurrently...")
    with ThreadPoolExecutor(max_workers=10) as executor:
        page_results = list(executor.map(fetch_page, range(1, pages + 1)))

    all_server_links = []
    for links in page_results:
        all_server_links.extend(links)
    all_server_links = list(dict.fromkeys(all_server_links))
    print(f"[INFO] total unique server links: {len(all_server_links)}")

    def fetch_server(rel):
        server_url = base_url + rel
        cfgs = extract_from_server(server_url)
        return cfgs

    print("[INFO] scraping server pages concurrently...")
    with ThreadPoolExecutor(max_workers=20) as executor:
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


def save_configs(configs: list, out_file: Path):
    out_file.parent.mkdir(parents=True, exist_ok=True)
    text = "\n".join(configs) + ("\n" if configs else "")
    tmp = out_file.with_suffix('.tmp')
    tmp.write_text(text, encoding='utf-8')
    tmp.replace(out_file)
    print(f"[INFO] saved {len(configs)} configs to {out_file}")


if __name__ == "__main__":
    configs = scrape()
    if not configs:
        print("No configs found from scraping.")
        exit(0)

    # Final dedupe + basic validation pass before saving results.
    unique = []
    seen = set()
    for uri in configs:
        if uri in seen:
            continue
        seen.add(uri)
        # Filter out 'reality' entries without spx= (same as original intent)
        if 'reality' in uri.lower() and 'spx=' not in uri:
            continue
        unique.append(uri)

    if not unique:
        print("No valid configurations found after basic filtering.")
        exit(0)

    save_configs(unique, OUTPUT_FILE)
    print("Done.")
