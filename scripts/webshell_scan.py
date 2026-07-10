#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
webshell_scan.py — Static scanner for webshells in a target directory.

Purpose
-------
Walk a web root and match each .php/.jsp/.aspx/.* file against the rule
library in data/webshell-patterns.json. Combines rule severity with entropy
and structural cues (tiny + eval, single-letter name, base64 wrappers) to
produce a per-file suspicion score and 8-field finding rows.

Compliance & red lines
----------------------
- Offline only; pattern library is local.
- READ-ONLY: never modifies, moves, or deletes files. Findings include
  full paths so an operator can act manually.
- Never executes file content. Patterns are *signatures*, not payloads.

Input
-----
  --path     web root or single file
  --patterns optional override of data/webshell-patterns.json
  --ext      comma-separated extension whitelist

Output
------
JSON (default) or NDJSON with 8-field findings.

Example
-------
  webshell_scan.py --path /var/www --ext php,jsp,aspx
"""
from __future__ import annotations

import argparse
import json
import math
import os
import re
import sys
from collections import Counter
from pathlib import Path
from typing import Any, Iterable, Iterator


DEFAULT_EXTS = (
    ".php", ".phtml", ".php3", ".php4", ".php5",
    ".jsp", ".jspx", ".jspf",
    ".asp", ".aspx", ".ashx", ".asmx",
    ".cer", ".cdx",
)
SKIP_DIRS = {"node_modules", "vendor", ".git", "dist", "build", "__pycache__"}
MAX_FILE_BYTES = 5 * 1024 * 1024


def builtin_patterns_path() -> Path:
    return Path(__file__).resolve().parent.parent / "data" / "webshell-patterns.json"


def load_patterns(path: Path) -> list[dict[str, Any]]:
    data = json.loads(path.read_text(encoding="utf-8"))
    rules = data.get("rules", data) if isinstance(data, dict) else data
    compiled = []
    for r in rules:
        try:
            r["_re"] = re.compile(r["pattern"], re.MULTILINE | re.DOTALL)
            compiled.append(r)
        except re.error as e:
            print(f"[WARN] skip rule {r.get('id')}: {e}", file=sys.stderr)
    return compiled


def iter_files(root: Path, ext_filter: set[str]) -> Iterator[Path]:
    if root.is_file():
        if not ext_filter or root.suffix.lower() in ext_filter:
            yield root
        return
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for fn in filenames:
            ext = os.path.splitext(fn)[1].lower()
            if ext_filter and ext not in ext_filter:
                continue
            yield Path(dirpath) / fn


def entropy(text: str) -> float:
    if not text:
        return 0.0
    counts = Counter(text)
    total = len(text)
    s = 0.0
    for c in counts.values():
        p = c / total
        s -= p * math.log2(p)
    return round(s, 3)


SEVERITY_WEIGHT = {"high": 5, "medium": 2, "low": 1}


def score_findings(matches: list[dict], size: int, ent: float, fname: str) -> int:
    score = 0
    for m in matches:
        score += SEVERITY_WEIGHT.get((m.get("severity") or "low").lower(), 1)
    # tiny + eval / system → strong shell suspicion
    if size < 200 and any(_has_eval(m.get("pattern", "")) for m in matches):
        score += 4
    if ent > 5.5:
        score += 1
    if ent > 6.0:
        score += 2
    # name heuristics
    base = os.path.splitext(os.path.basename(fname))[0]
    if re.match(r"^[a-z0-9]$", base):  # single char
        score += 2
    if re.fullmatch(r"[0-9]{8,}", base):  # timestamp-ish
        score += 1
    if base.isupper() and len(base) >= 4:
        score += 1
    return score


def _has_eval(pattern: str) -> bool:
    return any(k in pattern.lower() for k in ("eval", "assert", "system", "exec", "passthru", "runtime"))


def severity_for_score(s: int, has_high: bool) -> str:
    if has_high and s >= 6:
        return "P0"
    if has_high or s >= 6:
        return "P1"
    if s >= 3:
        return "P2"
    return "P3"


def fp_prob(matches: list[dict], score: int) -> float:
    # higher score and high-severity hits → lower fp
    if any((m.get("severity") or "").lower() == "high" for m in matches) and score >= 6:
        return 0.05
    if any((m.get("severity") or "").lower() == "high" for m in matches):
        return 0.2
    if score >= 4:
        return 0.35
    return 0.55


def scan_file(path: Path, patterns: list[dict], verbose: bool = False) -> dict | None:
    try:
        size = path.stat().st_size
        if size > MAX_FILE_BYTES:
            return None
        text = path.read_text(encoding="utf-8", errors="replace")
    except Exception as e:
        if verbose:
            print(f"[WARN] read {path}: {e}", file=sys.stderr)
        return None

    hits = []
    for rule in patterns:
        m = rule["_re"].search(text)
        if m:
            line_no = text.count("\n", 0, m.start()) + 1
            excerpt = text[max(0, m.start() - 40): m.end() + 40].replace("\n", " ")[:240]
            hits.append({
                "id": rule.get("id"),
                "lang": rule.get("lang"),
                "severity": rule.get("severity"),
                "description": rule.get("description"),
                "line_no": line_no,
                "excerpt": excerpt,
            })
    if not hits:
        return None

    ent = entropy(text[:65536])
    score = score_findings(hits, size, ent, str(path))
    has_high = any((h.get("severity") or "").lower() == "high" for h in hits)
    return {
        "path": str(path),
        "size": size,
        "entropy": ent,
        "score": score,
        "hits": hits,
        "severity": severity_for_score(score, has_high),
        "fp_prob": fp_prob(hits, score),
    }


def build_finding(res: dict, seq: int) -> dict:
    primary_rule = res["hits"][0]["id"]
    rule_ids = ",".join(h["id"] for h in res["hits"][:5])
    evidence_lines = [
        f"{h['id']} L{h['line_no']}: {h['excerpt']}"
        for h in res["hits"][:5]
    ]
    iocs = [{
        "type": "path",
        "value": res["path"],
        "confidence": "high" if res["severity"] in ("P0", "P1") else "medium",
        "first_seen": None,
        "source": f"webshell_scan:{primary_rule}",
        "tag": "webshell",
    }]
    return {
        "id": f"WS-{seq:03d}",
        "severity": res["severity"],
        "category": "webshell",
        "evidence": {
            "path": res["path"],
            "size": res["size"],
            "entropy": res["entropy"],
            "score": res["score"],
            "lines": evidence_lines,
        },
        "rule_id": rule_ids,
        "false_positive_prob": res["fp_prob"],
        "recommended_action": (
            "立即对该文件 hash + 备份，断开 web 进程对其的访问，"
            "审计 web 服务器最近上传/写入路径与对应账号，移除前留 IOC。"
        ),
        "iocs": iocs,
    }


def main(argv=None) -> int:
    args = parse_args(argv)
    root = Path(args.path)
    if not root.exists():
        print(f"[ERROR] not found: {root}", file=sys.stderr)
        return 1

    if args.ext:
        ext_filter = {("." + e.strip().lstrip(".")).lower() for e in args.ext.split(",") if e.strip()}
    else:
        ext_filter = set(DEFAULT_EXTS)

    patterns_path = Path(args.patterns) if args.patterns else builtin_patterns_path()
    if not patterns_path.exists():
        print(f"[ERROR] patterns not found: {patterns_path}", file=sys.stderr)
        return 1
    patterns = load_patterns(patterns_path)
    if args.verbose:
        print(f"[INFO] loaded {len(patterns)} rules", file=sys.stderr)

    findings = []
    scanned = 0
    suspicious = 0
    for fpath in iter_files(root, ext_filter):
        scanned += 1
        res = scan_file(fpath, patterns, args.verbose)
        if res is None:
            continue
        suspicious += 1
        findings.append(build_finding(res, suspicious))

    if args.verbose:
        print(f"[INFO] scanned={scanned} suspicious={suspicious}", file=sys.stderr)

    output = {
        "version": "0.1",
        "scanned_files": scanned,
        "suspicious_files": suspicious,
        "findings": findings,
    }

    text = json.dumps(output, ensure_ascii=False, indent=2)
    if args.output:
        Path(args.output).write_text(text, encoding="utf-8")
    else:
        print(text)
    return 0


def parse_args(argv=None):
    p = argparse.ArgumentParser(description="Static webshell scanner")
    p.add_argument("--path", required=True, help="Web root or single file")
    p.add_argument("--ext", default=None, help="Comma-separated extension filter (default: common web exts)")
    p.add_argument("--patterns", default=None, help="Override webshell-patterns.json path")
    p.add_argument("--output", default=None, help="Output JSON file (default stdout)")
    p.add_argument("-q", "--quiet", action="store_true", help="Quiet stderr")
    p.add_argument("-v", "--verbose", action="store_true", help="Verbose stderr")
    return p.parse_args(argv)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
    except FileNotFoundError as e:
        print(f"[ERROR] {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"[ERROR] runtime: {e}", file=sys.stderr)
        sys.exit(2)
