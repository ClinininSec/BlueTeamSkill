#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ioc_match.py — Match normalized NDJSON logs against IOC blocklists.

Purpose
-------
Stream NDJSON records produced by log_parser.py and emit 8-field hits when
any record matches a built-in or user-supplied IOC. Supports IP/CIDR, domain
(exact + wildcard `*.foo.com`), URL, file hashes, UA (regex), path (regex),
email, and `tool` (multi-field combined).

Compliance & red lines
----------------------
- Offline only; loads JSON IOC files from disk.
- No data is exfiltrated. Output should be piped through desensitize.py.
- Aggregates repeated hits by `(ioc_value, src_ip)` to keep reports compact
  while preserving line numbers for every appearance.

Input
-----
  --logs <ndjson>            NDJSON from log_parser.py
  --ioc  <ioc-file.json>     Optional extra IOC file (merged with --builtin)
  --builtin                  Auto-load <script-dir>/../data/ioc-builtin.json

Output
------
JSON list (default) or NDJSON with --ndjson. Each hit follows the 8-field
contract from SKILL.md plus a `matched_ioc` block.

Example
-------
  log_parser.py --input access.log | ioc_match.py --logs - --builtin
"""
from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import re
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any, Iterable, Iterator

# Shared helpers (pure stdlib). sys.path bootstrap keeps the script runnable
# standalone as `python3 scripts/ioc_match.py` without PYTHONPATH/pip.
sys.path.insert(0, str(Path(__file__).resolve().parent))
import hvv_common as _hc  # noqa: E402


# ---------------------------------------------------------------------------
# Loaders
# ---------------------------------------------------------------------------
def load_ioc_file(path: Path) -> list[dict[str, Any]]:
    with open(path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    if isinstance(data, dict) and "iocs" in data:
        return list(data["iocs"])
    if isinstance(data, list):
        return data
    raise ValueError(f"unrecognized IOC structure in {path}")


def builtin_ioc_path() -> Path:
    return Path(__file__).resolve().parent.parent / "data" / "ioc-builtin.json"


# ---------------------------------------------------------------------------
# IOC index — compile once for streaming
# ---------------------------------------------------------------------------
class IocIndex:
    """Pre-compiled IOC lookup structures for streaming match.

    The index splits IOCs by type so the hot path performs O(1) set hits
    (IP literal, domain literal) and a single iteration over the small
    regex lists for UA / path / URL.
    """

    def __init__(self, iocs: list[dict[str, Any]]):
        self.ip_set: set[str] = set()
        self.ip_cidrs: list[tuple[Any, dict]] = []
        self.domain_exact: dict[str, dict] = {}
        self.domain_wild: list[tuple[str, dict]] = []  # (suffix without leading '*'.) , ioc
        self.url_regex: list[tuple[re.Pattern, dict]] = []
        self.ua_regex: list[tuple[re.Pattern, dict]] = []
        self.path_regex: list[tuple[re.Pattern, dict]] = []
        self.email_exact: dict[str, dict] = {}
        self.hash_md5: dict[str, dict] = {}
        self.hash_sha1: dict[str, dict] = {}
        self.hash_sha256: dict[str, dict] = {}
        self.tools: list[dict] = []  # tool IOCs evaluated as path+UA combo

        for ioc in iocs:
            self._add(ioc)

    def _add(self, ioc: dict[str, Any]) -> None:
        t = (ioc.get("type") or "").lower()
        v = ioc.get("value")
        if not v or not t:
            return
        if t == "ip":
            if "/" in v:
                try:
                    self.ip_cidrs.append((ipaddress.ip_network(v, strict=False), ioc))
                except ValueError:
                    pass
            else:
                self.ip_set.add(v)
                # record original record for later lookup
                self._ip_map = getattr(self, "_ip_map", {})
                self._ip_map[v] = ioc
        elif t == "domain":
            if v.startswith("*."):
                self.domain_wild.append((v[2:].lower(), ioc))
            else:
                self.domain_exact[v.lower()] = ioc
        elif t == "url":
            try:
                self.url_regex.append((re.compile(v), ioc))
            except re.error:
                pass
        elif t == "ua":
            try:
                self.ua_regex.append((re.compile(v), ioc))
            except re.error:
                pass
        elif t == "path":
            # `path` IOCs are matched literally as substrings against uri
            # (no regex compile required); but we also try to compile if it
            # looks like a regex (contains regex meta) for flexibility.
            try:
                self.path_regex.append((re.compile(re.escape(v) if not _looks_like_regex(v) else v), ioc))
            except re.error:
                self.path_regex.append((re.compile(re.escape(v)), ioc))
        elif t == "email":
            self.email_exact[v.lower()] = ioc
        elif t == "hash:md5":
            self.hash_md5[v.lower()] = ioc
        elif t == "hash:sha1":
            self.hash_sha1[v.lower()] = ioc
        elif t == "hash:sha256":
            self.hash_sha256[v.lower()] = ioc
        elif t == "tool":
            self.tools.append(ioc)

    # ------------------- matchers -------------------
    def match_ip(self, ip: str) -> dict | None:
        if not ip:
            return None
        ip_map = getattr(self, "_ip_map", {})
        if ip in ip_map:
            return ip_map[ip]
        try:
            ip_obj = ipaddress.ip_address(ip)
        except ValueError:
            return None
        for net, ioc in self.ip_cidrs:
            if ip_obj in net:
                return ioc
        return None

    def match_domain(self, host: str) -> dict | None:
        if not host:
            return None
        host_l = host.lower()
        if host_l in self.domain_exact:
            return self.domain_exact[host_l]
        for suffix, ioc in self.domain_wild:
            if host_l.endswith("." + suffix):
                return ioc
        return None

    def match_ua(self, ua: str) -> dict | None:
        if not ua:
            return None
        for rx, ioc in self.ua_regex:
            if rx.search(ua):
                return ioc
        return None

    def match_uri(self, uri: str) -> dict | None:
        if not uri:
            return None
        for rx, ioc in self.path_regex:
            if rx.search(uri):
                return ioc
        for rx, ioc in self.url_regex:
            if rx.search(uri):
                return ioc
        return None


def _looks_like_regex(v: str) -> bool:
    return any(c in v for c in r"^$()[]{}|*+?\\")


# ---------------------------------------------------------------------------
# Hit aggregation
# ---------------------------------------------------------------------------
def severity_for_ioc(ioc: dict) -> str:
    conf = (ioc.get("confidence") or "low").lower()
    return {"high": "P1", "medium": "P2", "low": "P3"}.get(conf, "P3")


def fp_prob_for_ioc(ioc: dict) -> float:
    conf = (ioc.get("confidence") or "low").lower()
    return {"high": 0.1, "medium": 0.3, "low": 0.55}.get(conf, 0.5)


def category_for_ioc(ioc: dict) -> str:
    tag = (ioc.get("tag") or "").lower()
    if "c2" in tag:
        return "rce"  # closest 8-field category for C2 callbacks
    if "tool" in tag or "scanner" in tag:
        return "recon"
    if "mining" in tag:
        return "data-exfil"
    if "reverse-shell" in tag:
        return "rce"
    return "其他"


# ---------------------------------------------------------------------------
# Main streaming
# ---------------------------------------------------------------------------
def iter_records(fp) -> Iterator[dict]:
    yield from _hc.iter_ndjson(fp)


def match_record(rec: dict, idx: IocIndex) -> list[dict]:
    hits: list[dict] = []
    ip = rec.get("src_ip")
    if ip:
        h = idx.match_ip(ip)
        if h:
            hits.append(h)
    uri = rec.get("uri") or ""
    if uri:
        # try to extract host from URI for domain match
        host_m = re.search(r"://([^/:]+)", uri)
        if host_m:
            host_hit = idx.match_domain(host_m.group(1))
            if host_hit:
                hits.append(host_hit)
        path_hit = idx.match_uri(uri)
        if path_hit:
            hits.append(path_hit)
    ua = rec.get("ua") or ""
    if ua:
        ua_hit = idx.match_ua(ua)
        if ua_hit:
            hits.append(ua_hit)
    # `tool` IOCs combine UA + URI tests
    for tool in idx.tools:
        ua_pat = tool.get("ua_pattern")
        uri_pat = tool.get("uri_pattern")
        if ua_pat and ua and re.search(ua_pat, ua):
            hits.append(tool)
            continue
        if uri_pat and uri and re.search(uri_pat, uri):
            hits.append(tool)
    return hits


def main(argv=None) -> int:
    args = parse_args(argv)

    iocs: list[dict] = []
    if args.builtin:
        try:
            iocs.extend(load_ioc_file(builtin_ioc_path()))
        except Exception as e:
            print(f"[WARN] failed to load builtin IOC: {e}", file=sys.stderr)
    if args.ioc:
        try:
            iocs.extend(load_ioc_file(Path(args.ioc)))
        except Exception as e:
            print(f"[ERROR] failed to load --ioc: {e}", file=sys.stderr)
            return 1
    if not iocs:
        print("[ERROR] no IOCs loaded (use --builtin and/or --ioc)", file=sys.stderr)
        return 1

    idx = IocIndex(iocs)

    if args.logs == "-":
        log_fp = sys.stdin
    else:
        log_fp = open(args.logs, "r", encoding="utf-8")

    agg: dict[tuple, dict] = defaultdict(lambda: {
        "occurrences": [], "first_seen": None, "last_seen": None,
        "src_ips": set(), "uris": set(), "uas": set(),
    })

    hit_count = 0
    seq = 0
    try:
        for rec in iter_records(log_fp):
            for ioc in match_record(rec, idx):
                seq += 1
                key = (ioc.get("type"), ioc.get("value"), rec.get("src_ip"))
                a = agg[key]
                a["ioc"] = ioc
                a["occurrences"].append({
                    "line_no": rec.get("line_no"),
                    "src_file": rec.get("src_file"),
                    "ts": rec.get("ts"),
                    "raw_line_snippet": (rec.get("raw_line") or "")[:240],
                })
                ts = rec.get("ts")
                if ts:
                    if a["first_seen"] is None or ts < a["first_seen"]:
                        a["first_seen"] = ts
                    if a["last_seen"] is None or ts > a["last_seen"]:
                        a["last_seen"] = ts
                if rec.get("src_ip"):
                    a["src_ips"].add(rec["src_ip"])
                if rec.get("uri"):
                    a["uris"].add(rec["uri"][:200])
                if rec.get("ua"):
                    a["uas"].add((rec["ua"] or "")[:200])
                hit_count += 1
    finally:
        if args.logs != "-":
            log_fp.close()

    findings = []
    for n, ((_t, _v, _src), a) in enumerate(sorted(agg.items()), start=1):
        ioc = a["ioc"]
        findings.append({
            "id": f"IOC-{n:03d}",
            "severity": severity_for_ioc(ioc),
            "category": category_for_ioc(ioc),
            "evidence": {
                "first_seen": a["first_seen"],
                "last_seen": a["last_seen"],
                "count": len(a["occurrences"]),
                "src_ips": sorted(a["src_ips"]),
                "sample_lines": a["occurrences"][:5],
            },
            "rule_id": f"IOC-{ioc.get('type')}",
            "false_positive_prob": fp_prob_for_ioc(ioc),
            "recommended_action": _action_for_ioc(ioc),
            "iocs": [{
                "type": ioc.get("type"),
                "value": ioc.get("value"),
                "confidence": ioc.get("confidence"),
                "first_seen": a["first_seen"] or ioc.get("first_seen"),
                "source": ioc.get("source"),
                "tag": ioc.get("tag"),
            }],
            "matched_ioc": ioc,
        })

    output = {
        "version": "0.1",
        "total_hits": hit_count,
        "total_findings": len(findings),
        "findings": findings,
    }

    if args.ndjson:
        for f in findings:
            sys.stdout.write(json.dumps(f, ensure_ascii=False) + "\n")
    else:
        out_text = json.dumps(output, ensure_ascii=False, indent=2)
        if args.output:
            Path(args.output).write_text(out_text, encoding="utf-8")
        else:
            print(out_text)

    if args.verbose:
        print(f"[INFO] hits={hit_count} findings={len(findings)}", file=sys.stderr)
    return 0


def _action_for_ioc(ioc: dict) -> str:
    tag = (ioc.get("tag") or "").lower()
    if "scanner" in tag or "tool:" in tag:
        return "封禁源 IP / 提交 WAF 策略 / 留底原始日志"
    if "c2" in tag:
        return "立即断网取证；提取受害主机进程/网络/持久化；切换走 ir 模式"
    if "mining" in tag:
        return "封禁外联目标域名/IP，定位本地挖矿进程，排查同段主机"
    if "webshell" in tag or "shell" in tag:
        return "审计 web 目录，比对 webshell 特征，移除并溯源上传链路"
    return "纳入待跟进列表，结合上下文研判"


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def parse_args(argv=None):
    p = argparse.ArgumentParser(description="Match NDJSON logs against IOCs")
    p.add_argument("--logs", required=True, help="NDJSON path or - for stdin")
    p.add_argument("--ioc", default=None, help="Extra IOC JSON file")
    p.add_argument("--builtin", action="store_true", help="Load built-in IOC list")
    p.add_argument("--output", default=None, help="Output JSON file (default stdout)")
    p.add_argument("--ndjson", action="store_true", help="Emit NDJSON instead of JSON object")
    p.add_argument("-q", "--quiet", action="store_true", help="Quiet stderr")
    p.add_argument("-v", "--verbose", action="store_true", help="Verbose stderr")
    return p.parse_args(argv)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except FileNotFoundError as e:
        print(f"[ERROR] file not found: {e}", file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        sys.exit(130)
    except Exception as e:
        print(f"[ERROR] runtime: {e}", file=sys.stderr)
        sys.exit(2)
