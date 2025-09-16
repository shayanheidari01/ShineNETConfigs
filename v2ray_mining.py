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

def clean_uri(uri: str) -> str:
    if not uri:
        return uri
    uri = uri.strip()
    uri = uri.strip(' \t\n\r"\'')
    while uri.startswith('(') and uri.endswith(')'):
        uri = uri[1:-1].strip()
    uri = uri.rstrip('.,;:!?)"\']')
    return uri

def extract_configs_from_html(html: str) -> list:
    found = []
    for m in URI_RE.findall(html):
        found.append(clean_uri(m))

    soup = BeautifulSoup(html, 'html.parser')
    # prefer hrefs in <a>
    for a in soup.find_all('a', href=True):
        href = a['href'].strip()
        text = a.get_text(separator=' ', strip=True)
        m_href = URI_RE.search(href)
        if m_href:
            uri = clean_uri(m_href.group(0))
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
                found.append(clean_uri(m))

    # check common text tags
    for tagname in ('pre', 'code', 'p', 'li', 'div', 'span'):
        for node in soup.find_all(tagname):
            txt = node.get_text(separator=' ', strip=True)
            if not txt:
                continue
            for m in URI_RE.findall(txt):
                found.append(clean_uri(m))

    visible_text = soup.get_text(separator=' ', strip=True)
    for m in URI_RE.findall(visible_text):
        found.append(clean_uri(m))

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
