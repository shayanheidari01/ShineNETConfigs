#!/usr/bin/env python3
"""
filter_configs.py
==================

Takes raw V2Ray/VPN config URIs (vmess/vless/trojan/shadowsocks) and keeps
only the ones that:
  1. Use TLS (security=tls / tls transport), AND
  2. Have allowInsecure / allow_insecure explicitly set to false (0/false/absent-but-safe is NOT counted;
     we require it to be explicitly "0"/"false" OR simply not "1"/"true" — see NOTES below).

The country-flag emoji (or any text) in the "remark" part of the URI
(the part after '#') is preserved untouched, since that's where channels
usually put flags like "🇩🇪 Germany".

NOTES on allowInsecure semantics
---------------------------------
- vless / trojan: query param is usually `allowInsecure=0|1` (sometimes
  `allow_insecure`). We require it to be "0"/"false" if present. If the
  param is absent entirely, default behavior for TLS is secure (insecure
  disabled), so we treat "absent" as safe too — matching client defaults.
- vmess: the JSON payload's `tls` field must be "tls" (or "reality" is
  excluded on purpose since we only asked for tls) and the `allowInsecure`/
  `verify_cert`-style flag (Xray vmess JSON doesn't officially standardize
  this key, but many generators add `"allowInsecure"` or `"scy"`... to be
  safe we look for `allowInsecure` key in the JSON) must not be true.
- shadowsocks (ss://) has no native TLS/allowInsecure concept, so ss:// is
  always excluded from the "TLS only" output.

Usage
-----
    python filter_configs.py input_all_configs.txt configs.txt
    cat all_configs.txt | python filter_configs.py - configs.txt
"""

from __future__ import annotations

import base64
import json
import re
import sys
from typing import Optional
from urllib.parse import urlparse, parse_qs, unquote


def _decode_vmess_json(uri: str) -> Optional[dict]:
    try:
        payload = uri[len("vmess://"):]
        # strip remark if someone appended one after # (rare for vmess)
        payload = payload.split("#", 1)[0].strip()
        payload += "=" * (-len(payload) % 4)
        decoded = base64.b64decode(payload, validate=False)
        obj = json.loads(decoded)
        return obj if isinstance(obj, dict) else None
    except Exception:
        return None


def _bool_like(value) -> Optional[bool]:
    """Interpret common truthy/falsy representations found in configs."""
    if value is None:
        return None
    if isinstance(value, bool):
        return value
    s = str(value).strip().lower()
    if s in ("1", "true", "yes"):
        return True
    if s in ("0", "false", "no", ""):
        return False
    return None


def keep_vmess(uri: str) -> bool:
    obj = _decode_vmess_json(uri)
    if not obj:
        return False
    tls_field = str(obj.get("tls", "")).strip().lower()
    if tls_field != "tls":
        return False
    allow_insecure = _bool_like(
        obj.get("allowInsecure", obj.get("allow_insecure"))
    )
    # Explicit True -> reject. False or absent -> keep.
    return allow_insecure is not True


def keep_query_based(uri: str) -> bool:
    """Handles vless:// and trojan:// which use standard URL query params."""
    try:
        parsed = urlparse(uri)
        qs = parse_qs(parsed.query)
    except Exception:
        return False

    security = (qs.get("security", [""])[0] or "").strip().lower()
    if security != "tls":
        return False

    raw_insecure = qs.get("allowInsecure", qs.get("allow_insecure", [None]))[0]
    allow_insecure = _bool_like(raw_insecure)
    return allow_insecure is not True


def keep_config(uri: str) -> bool:
    if uri.startswith("vmess://"):
        return keep_vmess(uri)
    if uri.startswith(("vless://", "trojan://")):
        return keep_query_based(uri)
    # shadowsocks has no TLS concept in the same sense -> excluded
    return False


def main(argv: list[str]) -> int:
    if len(argv) < 3:
        print(f"Usage: {argv[0]} <input_file|-> <output_file>", file=sys.stderr)
        return 1

    in_path, out_path = argv[1], argv[2]

    if in_path == "-":
        raw_lines = sys.stdin.read().splitlines()
    else:
        with open(in_path, "r", encoding="utf-8") as f:
            raw_lines = f.read().splitlines()

    kept: list[str] = []
    seen: set[str] = set()

    for line in raw_lines:
        uri = line.strip()
        if not uri:
            continue
        if uri in seen:
            continue
        if keep_config(uri):
            seen.add(uri)
            kept.append(uri)  # remark/flag portion after '#' kept as-is

    with open(out_path, "w", encoding="utf-8") as f:
        f.write("\n".join(kept))
        if kept:
            f.write("\n")

    print(f"Kept {len(kept)} TLS (allowInsecure=false) configs -> {out_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
