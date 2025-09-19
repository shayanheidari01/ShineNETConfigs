#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
v2ray_mining.py (robust)
Scrapes v2nodes (or other base_url) for vmess/vless/trojan/ss configs
and writes unique results into configs.txt.

This variant includes a robust routine to ensure the 'tester' executable
is present in ./core_engine (extract archives, search project, set +x, copy/rename).
Designed to run on Linux (Ubuntu) in GitHub Actions.
"""

import requests
from bs4 import BeautifulSoup
import re
import sys
from pathlib import Path
import json
import base64
from python_v2ray.config_parser import parse_uri
from python_v2ray.downloader import BinaryDownloader
from python_v2ray.tester import ConnectionTester
from concurrent.futures import ThreadPoolExecutor

# extra imports for robust handling
import os
import stat
import shutil
import zipfile
import tarfile
import fnmatch
import traceback

# ---------------- SETTINGS ----------------
BASE_URL = "https://www.v2nodes.com"
PAGES_TO_SCRAPE = 5
REQUEST_TIMEOUT = 12
HEADERS = {
    'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120 Safari/537.36'
}
OUTPUT_FILE = Path("configs.txt")
SLEEP_BETWEEN_REQUESTS = 0.5  # polite crawling
# ------------------------------------------

URI_RE = re.compile(
    r'(?:vless|vmess|trojan|ss)://'            # scheme
    r'[^\s\'"<>()[\]{}]+'                     # body until a breaking char
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
    try:
        prefix, payload = uri.split('://', 1)
    except ValueError:
        return uri
    if prefix.lower() != 'vmess':
        return uri
    payload = payload.strip()
    if '#' in payload:
        payload = payload.split('#', 1)[0]
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
        return 'vmess://' + new_b64
    except Exception:
        return uri

def extract_configs_from_html(html: str) -> list:
    found = []
    for m in URI_RE.findall(html):
        candidate = clean_uri(m)
        candidate = transform_vmess(candidate) if candidate.lower().startswith('vmess://') else candidate
        found.append(candidate)

    soup = BeautifulSoup(html, 'html.parser')
    for a in soup.find_all('a', href=True):
        href = a['href'].strip()
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
            if parse_uri(uri):
                valid_found.append(uri)
        except Exception:
            pass
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
    out_file.parent.mkdir(parents=True, exist_ok=True)
    text = "\n".join(configs) + ("\n" if configs else "")
    tmp = out_file.with_suffix('.tmp')
    tmp.write_text(text, encoding='utf-8')
    tmp.replace(out_file)
    print(f"[INFO] saved {len(configs)} configs to {out_file}")

# ---------------- robust tester ensuring for Linux (Ubuntu) ----------------
def _is_executable_file(p: Path) -> bool:
    try:
        return p.is_file() and os.access(str(p), os.X_OK)
    except Exception:
        return False

def _make_executable(p: Path):
    try:
        mode = p.stat().st_mode
        p.chmod(mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    except Exception:
        try:
            p.chmod(0o755)
        except Exception:
            pass

def _extract_archive(archive_path: Path, dest: Path) -> bool:
    try:
        if zipfile.is_zipfile(archive_path):
            print(f"[INFO] extracting zip {archive_path} -> {dest}")
            with zipfile.ZipFile(archive_path, 'r') as z:
                z.extractall(dest)
            return True
        if tarfile.is_tarfile(archive_path):
            print(f"[INFO] extracting tar {archive_path} -> {dest}")
            with tarfile.open(archive_path, 'r:*') as t:
                t.extractall(dest)
            return True
    except Exception as e:
        print(f"[WARN] failed to extract {archive_path}: {e}", file=sys.stderr)
    return False

def ensure_tester_executable_linux(project_root: Path, core_engine_dir: Path):
    project_root = Path(project_root).resolve()
    core_engine_dir = Path(core_engine_dir).resolve()
    core_engine_dir.mkdir(parents=True, exist_ok=True)
    expected = core_engine_dir / "tester"
    print(f"[CORE ENGINE] ensure tester at: {expected}")

    # quick success case
    if expected.exists() and _is_executable_file(expected):
        print(f"[CORE ENGINE] tester already exists and is executable: {expected}")
        return

    # candidate names we expect after extraction or direct download
    candidate_names = [
        "tester", "core_engine", "core-engine", "coreengine",
        "core_engine-linux-64", "core_engine_linux_64", "core-engine-linux",
        "xray", "xray-core", "xray_core"
    ]

    # 1) check inside core_engine dir for candidates
    for name in candidate_names:
        p = core_engine_dir / name
        if p.exists():
            try:
                shutil.copy2(str(p), str(expected))
                _make_executable(expected)
                print(f"[CORE ENGINE] copied candidate {p} -> {expected}")
                return
            except Exception as e:
                print(f"[WARN] failed to copy {p} -> {expected}: {e}", file=sys.stderr)

    # 2) check for any executable inside core_engine dir
    for entry in core_engine_dir.iterdir():
        if _is_executable_file(entry):
            try:
                shutil.copy2(str(entry), str(expected))
                _make_executable(expected)
                print(f"[CORE ENGINE] copied executable {entry} -> {expected}")
                return
            except Exception as e:
                print(f"[WARN] failed to copy {entry} -> {expected}: {e}", file=sys.stderr)

    # 3) if there are archives inside core_engine (zip/tar), try extracting them in-place then search again
    for entry in core_engine_dir.iterdir():
        if entry.is_file() and entry.suffix.lower() in ('.zip', '.gz', '.tgz', '.tar'):
            print(f"[CORE ENGINE] found archive inside core_engine: {entry}, trying extract")
            if _extract_archive(entry, core_engine_dir):
                # attempt to find executables again
                for sub in core_engine_dir.rglob("*"):
                    if _is_executable_file(sub):
                        try:
                            shutil.copy2(str(sub), str(expected))
                            _make_executable(expected)
                            print(f"[CORE ENGINE] extracted and copied {sub} -> {expected}")
                            return
                        except Exception as e:
                            print(f"[WARN] failed to copy extracted {sub}: {e}", file=sys.stderr)

    # 4) Deep search project_root (depth limited) for candidate files or archives
    print("[CORE ENGINE] deep searching project tree for candidates or archives (depth <= 4)...")
    max_depth = 4
    found_archive = None
    found_candidate = None
    for root, dirs, files in os.walk(str(project_root)):
        # compute depth
        rel = Path(root).relative_to(project_root)
        if len(rel.parts) > max_depth:
            dirs[:] = []
            continue
        for fname in files:
            lower = fname.lower()
            full = Path(root) / fname
            # archive candidate
            if lower.endswith(('.zip', '.tar.gz', '.tgz', '.tar')):
                print(f"[CORE ENGINE] found archive: {full}")
                # try extract into core_engine_dir
                if _extract_archive(full, core_engine_dir):
                    # after extraction try to find executables
                    for sub in core_engine_dir.rglob("*"):
                        if _is_executable_file(sub):
                            try:
                                shutil.copy2(str(sub), str(expected))
                                _make_executable(expected)
                                print(f"[CORE ENGINE] extracted archive and copied {sub} -> {expected}")
                                return
                            except Exception as e:
                                print(f"[WARN] failed to copy after extract {sub}: {e}", file=sys.stderr)
                found_archive = full
            # binary candidate by name patterns
            if any(fnmatch.fnmatch(lower, pat) for pat in ("*core*", "*engine*", "xray*", "tester*")):
                print(f"[CORE ENGINE] found candidate file anywhere: {full}")
                found_candidate = full
                break
        if found_candidate:
            break

    if found_candidate:
        try:
            shutil.copy2(str(found_candidate), str(expected))
            _make_executable(expected)
            print(f"[CORE ENGINE] copied found candidate {found_candidate} -> {expected}")
            return
        except Exception as e:
            print(f"[WARN] failed to copy found candidate {found_candidate}: {e}", file=sys.stderr)

    # fallback: if we found an archive earlier, try extracting into a temporary folder and search
    if found_archive:
        tmpdir = core_engine_dir / "tmp_extracted"
        tmpdir.mkdir(parents=True, exist_ok=True)
        print(f"[CORE ENGINE] fallback: extracting {found_archive} into tmp {tmpdir}")
        if _extract_archive(found_archive, tmpdir):
            for sub in tmpdir.rglob("*"):
                if _is_executable_file(sub):
                    try:
                        shutil.copy2(str(sub), str(expected))
                        _make_executable(expected)
                        print(f"[CORE ENGINE] copied executable from tmp {sub} -> {expected}")
                        return
                    except Exception as e:
                        print(f"[WARN] failed to copy from tmp {sub}: {e}", file=sys.stderr)

    # nothing worked - print helpful debug info
    print("[CORE ENGINE] DEBUG: Could not find tester executable. Listing relevant dirs:")
    try:
        print("Project root top-level:")
        for p in project_root.iterdir():
            print(" -", p, "(dir)" if p.is_dir() else "(file)")
    except Exception:
        pass
    try:
        print("core_engine contents:")
        if core_engine_dir.exists():
            for p in core_engine_dir.rglob("*"):
                try:
                    st = p.stat()
                    flags = "x" if os.access(str(p), os.X_OK) else "-"
                    print(f" - {p} ({'dir' if p.is_dir() else 'file'}) size={st.st_size} exec={flags}")
                except Exception:
                    print(" -", p)
        else:
            print(" core_engine does not exist")
    except Exception:
        pass

    raise FileNotFoundError("Tester executable not found and could not be created. See logs above for details.")

# -------------------------------------------------------------------

if __name__ == "__main__":
    configs = scrape()
    if not configs:
        print("No configs found from scraping.")
        exit(0)

    project_root = Path(".").resolve()
    print("--- Verifying binaries ---")
    try:
        downloader = BinaryDownloader(project_root)
        downloader.ensure_all()
    except Exception as e:
        print(f"Fatal Error during downloader.ensure_all(): {e}")
        traceback.print_exc()
        exit(1)

    # ensure 'tester' exists (robust, linux-focused)
    try:
        ensure_tester_executable_linux(project_root, project_root / "core_engine")
    except Exception as e:
        print(f"Tester executable not found: {e}. Skipping ping test and saving all parsed configs.")
        save_configs(configs, OUTPUT_FILE)
        exit(0)

    print("\n* Parsing URIs...")
    parsed_configs = []
    valid_uris = []
    for uri in configs:
        if 'reality' in uri.lower() and 'spx=' not in uri:
            continue
        try:
            p = parse_uri(uri)
            if p:
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
    core_engine_path = str(project_root / "core_engine")
    try:
        tester = ConnectionTester(
            vendor_path=vendor_path,
            core_engine_path=core_engine_path
        )
    except FileNotFoundError as e:
        print(f"ConnectionTester initialization failed: {e}. Saving parsed configs without testing.")
        save_configs(valid_uris, OUTPUT_FILE)
        exit(0)
    try:
        results = tester.test_uris(parsed_configs)
    except Exception as e:
        print(f"Testing failed: {e}. Saving all parsed configs without ping test.")
        save_configs(valid_uris, OUTPUT_FILE)
        exit(0)

    valid_configs = [uri for uri, result in zip(valid_uris, results) if result.get('status') == 'success']
    print(f"* After testing, {len(valid_configs)} valid configs with ping.")
    save_configs(valid_configs, OUTPUT_FILE)
