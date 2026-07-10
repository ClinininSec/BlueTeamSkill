#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
desensitize.py — Mandatory output sanitizer for hvv-defender pipelines.

Purpose
-------
Filter sensitive identifiers from any text stream before it reaches the user:
private/public IPs, usernames, internal domains, customer / project names,
MAC addresses, emails, and `/home/<user>/...` paths. Designed to be idempotent
so re-running it does not change already-sanitized text.

Compliance & red lines
----------------------
- Pure filter. No network, no file uploads.
- Default mode is `strict` (mask everything). `relaxed` keeps public IPs.

Input
-----
  --input              file path or stdin
  --internal-domain    glob list, comma-separated (e.g. "*.corp.example.com,*.intra")
  --customer-name      customer / project name string
  --keep-public-ip     keep public IPs (e.g. red-team source IPs for attribution)
  --mode               strict (default) | relaxed

Output
------
Sanitized text to stdout or --output file.

Example
-------
  cat findings.json | desensitize.py --internal-domain '*.corp.example.com' \
      --customer-name 'XX 银行' > findings.safe.json
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
import sys
from pathlib import Path
from typing import Iterable


# ---------------------------------------------------------------------------
# Regex catalog. All compiled once.
# ---------------------------------------------------------------------------
IP_RE = re.compile(r"\b(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\b")
IPV6_RE = re.compile(r"\b([0-9A-Fa-f:]{2,39}:[0-9A-Fa-f]{1,4})\b")
MAC_RE = re.compile(r"\b([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}\b")
EMAIL_RE = re.compile(r"\b([A-Za-z0-9._%+-]+)@([A-Za-z0-9.-]+\.[A-Za-z]{2,})\b")
HOME_PATH_RE = re.compile(r"(/home/|/Users/|/root)(?P<sep>/?)(?P<user>[A-Za-z0-9_.\-]+)?")

# matches already-masked tokens so we can skip
MASKED_USER_RE = re.compile(r"^[a-zA-Z]\*{3,}$|^<user>$|^<masked>$|^<customer>$|^<internal>$|^<public-ip>$")

# JSON / YAML literals that must never be masked as usernames (v0.3-M1 hotfix:
# vendor_field_mapper.py may emit `"username": null` which USER_CONTEXT_RES[3]
# would otherwise turn into `n***` and break JSON validity).
_LITERAL_TOKENS = {"null", "None", "true", "false", "True", "False", "~", "nil"}


def _is_literal_token(name: str) -> bool:
    return name in _LITERAL_TOKENS


def _already_masked_username(name: str) -> bool:
    """Return True if `name` is already a masked token — used to guarantee
    idempotence when desensitize.py is re-run on already-sanitized text."""
    if not name:
        return True
    return bool(MASKED_USER_RE.match(name))


def is_private_ipv4(parts: tuple[int, int, int, int]) -> bool:
    a, b, c, d = parts
    return (
        a == 10
        or (a == 172 and 16 <= b <= 31)
        or (a == 192 and b == 168)
        or (a == 127)
        or (a == 169 and b == 254)
        or (a == 0)
    )


def is_link_local_or_special(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_reserved or addr.is_multicast
    except ValueError:
        return False


def mask_ip(match: re.Match, keep_public: bool) -> str:
    a, b, c, d = (int(g) for g in match.groups())
    full = f"{a}.{b}.{c}.{d}"
    parts = (a, b, c, d)
    if is_private_ipv4(parts):
        return f"{a}.{b}.{c}.xxx"
    # public
    if keep_public:
        return full
    return "<public-ip>"


def mask_mac(match: re.Match) -> str:
    s = match.group(0)
    return s[:8] + ":xx:xx:xx"


def mask_email(match: re.Match, domain_filters: list[str], customer_filters: list[str], keep_public: bool) -> str:
    user, dom = match.group(1), match.group(2)
    masked_user = user[0] + "***" if len(user) > 1 else "<u>"
    # apply domain masking on dom
    masked_dom = mask_domain(dom, domain_filters, customer_filters)
    return f"{masked_user}@{masked_dom}"


def mask_domain(host: str, internal: list[str], customer: list[str]) -> str:
    h = host.lower()
    for pat in internal:
        if _glob_match(pat, h):
            return "<internal>"
    for c in customer:
        if c and c.lower() in h:
            return "<customer>"
    return host


def _glob_match(pattern: str, value: str) -> bool:
    # very small glob: supports leading *. and *
    p = pattern.lower()
    v = value.lower()
    if p.startswith("*."):
        return v.endswith(p[1:]) or v == p[2:]
    if "*" in p:
        # fnmatch without import: build regex
        rx = re.escape(p).replace(r"\*", ".*")
        return re.fullmatch(rx, v) is not None
    return p == v


def mask_username(name: str) -> str:
    if not name:
        return name
    if MASKED_USER_RE.match(name):
        return name
    if len(name) <= 3:
        return "<user>"
    return name[0] + "*" * (len(name) - 1)


def mask_home_path(match: re.Match) -> str:
    prefix = match.group(1)
    sep = match.group("sep") or ""
    user = match.group("user")
    if not user or prefix == "/root":
        return match.group(0)
    return f"{prefix}{sep}{mask_username(user)}"


# context-aware username masking is keyed by surrounding text:
#  - "user=foo" / "for foo from" / "by foo"
# The captured name class also accepts `*` and `<>` so that already-masked
# tokens (e.g. `z*******`, `<user>`) are recognized by the context regex and
# passed to mask_username, which then no-ops via _already_masked_username.
USER_CONTEXT_RES = [
    re.compile(r"\b(user|User|USER)\s*[=:]\s*([A-Za-z0-9_.\-*<>]+)"),
    re.compile(r"\bfor\s+(invalid user\s+)?([A-Za-z0-9_.\-*<>]+)\s+from\b"),
    # `\b` is a word/non-word transition, which trips on trailing `*` in
    # already-masked tokens like `a****`. Using a lookahead for whitespace /
    # end-of-string / punctuation keeps such tokens whole so idempotence works.
    re.compile(r"\bby\s+([A-Za-z0-9_.\-*<>]+)(?=\s|$|[,.;:!?)\]])"),
    re.compile(r"\busername[\"']?\s*[:=]\s*[\"']?([A-Za-z0-9_.\-*<>]+)"),
]


def mask_user_contexts(text: str) -> str:
    def _repl_user_assign(m):
        name = m.group(2)
        if _already_masked_username(name) or _is_literal_token(name):
            return m.group(0)
        return f"{m.group(1)}={mask_username(name)}"

    def _repl_for(m):
        invalid = m.group(1) or ""
        name = m.group(2)
        if _already_masked_username(name) or _is_literal_token(name):
            return m.group(0)
        return f"for {invalid}{mask_username(name)} from"

    def _repl_by(m):
        name = m.group(1)
        if _already_masked_username(name) or _is_literal_token(name):
            return m.group(0)
        return f"by {mask_username(name)}"

    def _repl_uname_key(m):
        # rewrite preserving original prefix
        whole = m.group(0)
        name = m.group(1)
        if _already_masked_username(name) or _is_literal_token(name):
            return whole
        masked = mask_username(name)
        return whole.replace(name, masked)

    text = USER_CONTEXT_RES[0].sub(_repl_user_assign, text)
    text = USER_CONTEXT_RES[1].sub(_repl_for, text)
    text = USER_CONTEXT_RES[2].sub(_repl_by, text)
    text = USER_CONTEXT_RES[3].sub(_repl_uname_key, text)
    return text


def mask_domain_in_text(text: str, internal: list[str], customer: list[str]) -> str:
    if not internal and not customer:
        return text
    # crude domain detection: dotted hostname token
    def repl(m):
        host = m.group(0)
        return mask_domain(host, internal, customer)
    return re.sub(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b", repl, text)


def mask_customer_in_text(text: str, customer: list[str]) -> str:
    for name in customer:
        if not name:
            continue
        text = text.replace(name, "<customer>")
    return text


# ---------------------------------------------------------------------------
# Top-level sanitizer
# ---------------------------------------------------------------------------
def sanitize(text: str, args) -> str:
    keep_public = args.keep_public_ip
    internal = [d.strip() for d in (args.internal_domain or "").split(",") if d.strip()]
    customer_env = os.environ.get("HVV_CUSTOMER", "")
    customer = [c.strip() for c in (args.customer_name or customer_env or "").split(",") if c.strip()]

    if args.mode == "relaxed":
        # keep IPs, mask users / email / customer only
        text = mask_user_contexts(text)
        text = EMAIL_RE.sub(lambda m: mask_email(m, internal, customer, keep_public), text)
        text = mask_customer_in_text(text, customer)
        return text

    # strict
    text = IP_RE.sub(lambda m: mask_ip(m, keep_public), text)
    text = MAC_RE.sub(mask_mac, text)
    text = HOME_PATH_RE.sub(mask_home_path, text)
    text = EMAIL_RE.sub(lambda m: mask_email(m, internal, customer, keep_public), text)
    text = mask_user_contexts(text)
    text = mask_domain_in_text(text, internal, customer)
    text = mask_customer_in_text(text, customer)
    return text


# ---------------------------------------------------------------------------
# IO loop
# ---------------------------------------------------------------------------
def main(argv=None) -> int:
    args = parse_args(argv)
    if args.input and args.input != "-":
        try:
            text = Path(args.input).read_text(encoding="utf-8", errors="replace")
        except FileNotFoundError:
            print(f"[ERROR] not found: {args.input}", file=sys.stderr)
            return 1
    else:
        text = sys.stdin.read()
    try:
        out_text = sanitize(text, args)
    except Exception as e:
        print(f"[ERROR] sanitize failed: {e}", file=sys.stderr)
        return 2

    if args.output and args.output != "-":
        Path(args.output).write_text(out_text, encoding="utf-8")
    else:
        sys.stdout.write(out_text)
        if not out_text.endswith("\n"):
            sys.stdout.write("\n")
    return 0


def parse_args(argv=None):
    p = argparse.ArgumentParser(description="Mandatory output sanitizer")
    p.add_argument("--input", default="-", help="Input file or - for stdin")
    p.add_argument("--output", default="-", help="Output file or - for stdout")
    p.add_argument("--internal-domain", dest="internal_domain", default="",
                   help="Glob list, comma-separated (e.g. '*.corp.example.com,*.intra')")
    p.add_argument("--customer-name", dest="customer_name", default="",
                   help="Customer / project name (or env HVV_CUSTOMER)")
    p.add_argument("--keep-public-ip", dest="keep_public_ip", action="store_true",
                   help="Keep public IPs (red-team source attribution use-cases)")
    p.add_argument("--mode", default="strict", choices=["strict", "relaxed"],
                   help="strict masks everything; relaxed keeps IPs")
    p.add_argument("-q", "--quiet", action="store_true")
    p.add_argument("-v", "--verbose", action="store_true")
    return p.parse_args(argv)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
    except Exception as e:
        print(f"[ERROR] runtime: {e}", file=sys.stderr)
        sys.exit(2)
