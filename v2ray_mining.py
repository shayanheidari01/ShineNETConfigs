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
from python_v2ray.config_parser import parse_uri
from python_v2ray.downloader import BinaryDownloader
from python_v2ray.tester import ConnectionTester
from concurrent.futures import ThreadPoolExecutor

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

    # filter empties and validate using python_v2ray
    valid_found = []
    for uri in found:
        if not uri:
            continue
        # Additional check for vless: must contain '@' or ':'
        if uri.lower().startswith('vless://') and ('@' not in uri or ':' not in uri):
            continue
        try:
            if parse_uri(uri):
                valid_found.append(uri)
        except Exception:
            pass  # skip invalid configs
    return valid_found

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
    def fetch_page(page):
        page_url = f"{base_url}/?page={page}"
        try:
            resp = requests.get(page_url, headers=HEADERS, timeout=REQUEST_TIMEOUT)
            resp.raise_for_status()
            soup = BeautifulSoup(resp.text, 'html.parser')
            server_links = []
            for a in soup.find_all('a', href=True):
                href = a['href']
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
    if not configs:
        print("No configs found from scraping.")
        exit(0)

    project_root = Path(".")
    print("--- Verifying binaries ---")
    try:
        downloader = BinaryDownloader(project_root)
        downloader.ensure_all()
    except Exception as e:
        print(f"Fatal Error: {e}")
        exit(1)

    print("\n* Parsing URIs...")
    parsed_configs = []
    valid_uris = []
    for uri in configs:
        # Skip REALITY configs with empty password (missing spx=)
        if 'reality' in uri.lower() and 'spx=' not in uri:
            continue
        try:
            p = parse_uri(uri)
            if p:
                # Ensure unique tag to avoid conflicts in merged config
                if hasattr(p, 'tag'):
                    p.tag = f"config_{len(parsed_configs)}"
                elif isinstance(p, dict) and 'tag' in p:
                    p['tag'] = f"config_{len(parsed_configs)}"
                parsed_configs.append(p)
                valid_uris.append(uri)
        except Exception:
            pass
    if not parsed_configs:
        print("No valid configurations found after parsing.")
        exit(0)

    print(f"* Testing {len(parsed_configs)} configurations...")
    vendor_path = str(project_root / "vendor")
    core_engine_path = vendor_path  # Use same path for tester executable
    try:
        tester = ConnectionTester(
            vendor_path=vendor_path,
            core_engine_path=core_engine_path
        )
    except FileNotFoundError as e:
        print(f"Tester executable not found: {e}. Skipping ping test and saving all parsed configs.")
        save_configs(valid_uris, OUTPUT_FILE)
        exit(0)
    try:
        results = tester.test_uris(parsed_configs)
    except Exception as e:
        print(f"Testing failed: {e}. Saving all parsed configs without ping test.")
        save_configs(valid_uris, OUTPUT_FILE)
        exit(0)

    # Filter configs that have successful ping
    valid_configs = [uri for uri, result in zip(valid_uris, results) if result.get('status') == 'success']
    print(f"* After testing, {len(valid_configs)} valid configs with ping.")

    # Save only valid ones
    save_configs(valid_configs, OUTPUT_FILE)
