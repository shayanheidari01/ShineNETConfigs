#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
v2ray_mining.py
Scrapes v2nodes (or other specified base_url) for vmess/vless/trojan/ss configs
and writes unique results into configs.txt in the repo root.

Designed to be run inside CI (GitHub Actions).
"""

import requests
from bs4 import BeautifulSoup
import re
import time
import sys
from pathlib import Path
import json
import base64

# ---------------- SETTINGS ----------------
BASE_URL = "https://www.v2nodes.com"
PAGES_TO_SCRAPE = 5
REQUEST_TIMEOUT = 12
HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
}
OUTPUT_FILE = Path("configs.txt")
SLEEP_BETWEEN_REQUESTS = 0.5  # polite crawling
# ------------------------------------------

# improved regex: captures optional fragment (#...) up to newline (limit length to avoid overcapture)
URI_RE = re.compile(
    r'(?:vless|vmess|trojan|ss)://'            # scheme
    r'[^\s\'"<>()[\]{}]+'                     # body until a breaking char
    r'(?:#[^\n\r]{0,200})?',                  # optional fragment up to newline (max 200 chars)
    re.IGNORECASE
)

# pattern to find regional flag emojis (pair of regional indicator symbols)
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
    """
    Try to extract an ISO regional flag (two regional indicator symbols) from ps.
    If none found, return the original ps trimmed (or empty string if ps falsy).
    """
    if not ps:
        return ""
    m = FLAG_RE.search(ps)
    if m:
        return m.group(0)
    # fallback: try to return first few characters (trim) if no flag found
    return ps.strip()[:4]  # keep short fallback (user asked only flag; this is conservative)

def transform_vmess(uri: str) -> str:
    """
    Decode a vmess://<base64> JSON, extract a flag from 'ps' if present,
    and replace only the 'ps' field with the flag (keeping all other fields).
    If anything fails, return the original uri unchanged.
    """
    try:
        prefix, payload = uri.split('://', 1)
    except ValueError:
        return uri

    if prefix.lower() != 'vmess':
        return uri

    payload = payload.strip()
    # strip fragment if any (we won't preserve fragment)
    if '#' in payload:
        payload = payload.split('#', 1)[0]

    # fix padding
    missing_padding = len(payload) % 4
    if missing_padding:
        payload += '=' * (4 - missing_padding)

    try:
        decoded = base64.b64decode(payload).decode('utf-8', errors='replace')
        data = json.loads(decoded)
    except Exception:
        return uri

    # extract existing ps and try to find a flag
    ps = data.get('ps', '') or ''
    flag = extract_flag_from_ps(ps)
    if flag:
        data['ps'] = flag
    else:
        # no flag found: keep original ps (trimmed) — comment out this line if you want empty ps instead
        data['ps'] = ps.strip()

    try:
        new_json = json.dumps(data, ensure_ascii=False, separators=(',', ':'))
        new_b64 = base64.b64encode(new_json.encode('utf-8')).decode('utf-8')
        return 'vmess://' + new_b64
    except Exception:
        return uri

def extract_configs_from_html(html: str) -> list:
    found = []
    for m in URI_RE.findall(html):
        candidate = clean_uri(m)
        # transform vmess to keep only flag
        candidate = transform_vmess(candidate) if candidate.lower().startswith('vmess://') else candidate
        found.append(candidate)

    soup = BeautifulSoup(html, 'html.parser')
    # prefer hrefs in <a>
    for a in soup.find_all('a', href=True):
        href = a['href'].strip()
        text = a.get_text(separator=' ', strip=True)
        m_href = URI_RE.search(href)
        if m_href:
            uri = clean_uri(m_href.group(0))
            if uri.lower().startswith('vmess://'):
                uri = transform_vmess(uri)
            # attach fragment from link text if link text contains a more complete fragment
            if '#' in text:
                idx = text.find('#')
                frag = text[idx: idx + 200].split('\n', 1)[0].rstrip('.,;:!?)]"\'')
                if '#' in uri:
                    # prefer longer fragment
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

    # check common text tags
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

    # filter empties
    return [f for f in found if f]

def extract_from_server(server_url: str) -> list:
    try:
        resp = requests.get(server_url, headers=HEADERS, timeout=REQUEST_TIMEOUT)
        resp.raise_for_status()
        html = resp.text.replace('\r\n', '\n').replace('\r', '\n')
        return list(dict.fromkeys(extract_configs_from_html(html)))
    except Exception as e:
        print(f"[WARN] fetch error {server_url}: {e}", file=sys.stderr)
        return []

def scrape(base_url=BASE_URL, pages=PAGES_TO_SCRAPE):
    results = []
    seen = set()
    for page in range(1, pages + 1):
        page_url = f"{base_url}/?page={page}"
        print(f"[INFO] scraping index page {page_url}")
        try:
            resp = requests.get(page_url, headers=HEADERS, timeout=REQUEST_TIMEOUT)
            resp.raise_for_status()
            soup = BeautifulSoup(resp.text, 'html.parser')

            server_links = []
            for a in soup.find_all('a', href=True):
                href = a['href']
                if re.match(r'^/servers/\d+/?', href):
                    server_links.append(href)
            server_links = list(dict.fromkeys(server_links))
            print(f"  → found {len(server_links)} server links on page {page}")

            for rel in server_links:
                server_url = base_url + rel
                cfgs = extract_from_server(server_url)
                for cfg in cfgs:
                    if cfg not in seen:
                        seen.add(cfg)
                        results.append(cfg)
                        print(f"    + new: {cfg[:200]}")
                time.sleep(SLEEP_BETWEEN_REQUESTS)
        except Exception as e:
            print(f"[WARN] index fetch error {page_url}: {e}", file=sys.stderr)
    return results

def save_configs(configs: list, out_file: Path):
    """
    Write configs to out_file. Format: one config per line.
    Overwrites the file atomically.
    """
    out_file.parent.mkdir(parents=True, exist_ok=True)
    text = "\n".join(configs) + ("\n" if configs else "")
    tmp = out_file.with_suffix('.tmp')
    tmp.write_text(text, encoding='utf-8')
    tmp.replace(out_file)
    print(f"[INFO] saved {len(configs)} configs to {out_file}")

if __name__ == "__main__":
    configs = scrape()
    # optionally sort or keep insertion order; here keep discovered order
    save_configs(configs, OUTPUT_FILE)
