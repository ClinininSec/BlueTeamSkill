#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
nginx_anomaly.py — Aggregate anomalies from normalized nginx-access NDJSON.

Purpose
-------
Read an NDJSON stream of nginx-access records produced by log_parser.py and
emit 8-field findings for ten anomaly families:
  R-NGX-001  Known scanner UAs
  R-NGX-002  4xx burst from single IP (>=50 in 5 min)
  R-NGX-003  Sensitive path access (.git, .env, actuator, etc.)
  R-NGX-004  Long URL (>1000 chars)
  R-NGX-005  Unusual HTTP method (PUT/PATCH/TRACE/CONNECT)
  R-NGX-006  Path traversal markers
  R-NGX-007  Classic SQLi keyword cluster
  R-NGX-008  RCE / JNDI / fastjson trigger strings
  R-NGX-009  Large response body (>10 MiB single request) - if `bytes`
              field present in raw_line, derived
  R-NGX-010  Abnormal UA (empty / very short / pure-symbol)

Compliance & red lines
----------------------
- Detection only. We identify the *presence* of attack signatures; we never
  reproduce a working payload. Snippets are truncated.
- Offline. No outbound calls.

Input
-----
  --input    NDJSON (nginx-access). Use `-` for stdin.
  --patterns tool-signatures.json path (default ../data/tool-signatures.json)

Output
------
JSON list of 8-field findings.

Example
-------
  log_parser.py --input access.log | nginx_anomaly.py --input -
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter, defaultdict, deque
from datetime import datetime, timedelta
from pathlib import Path
from typing import Iterator

# Shared helpers (pure stdlib). sys.path bootstrap keeps the script runnable
# standalone as `python3 scripts/nginx_anomaly.py` without PYTHONPATH/pip.
sys.path.insert(0, str(Path(__file__).resolve().parent))
import hvv_common as _hc  # noqa: E402


SENSITIVE_PATH_RX = re.compile(
    r"(?i)/(\.git/|\.env(?:\.|$|/|\?)|wp-admin|wp-login\.php|actuator(?:/|$)|swagger|"
    r"\.ssh/|/etc/passwd|/proc/self|phpinfo\.php|phpmyadmin|console/login|"
    r"manager/html|jmx-console|web-console)"
)
TRAVERSAL_RX = re.compile(r"(?:\.\./|\.\.%2f|%2e%2e/|\.\.%5c|\.\.\\|\.\.\\\\)", re.IGNORECASE)
SQLI_RX = re.compile(
    r"(?i)(\bunion\s+(?:all\s+)?select\b|\bsleep\(\s*\d+\s*\)|\bbenchmark\(\s*\d+|"
    r"'\s*or\s*'1|\"\s*or\s*\"1|\bextractvalue\b|\bupdatexml\b|\bload_file\b|"
    r"information_schema\.tables)"
)
RCE_RX = re.compile(
    r"(?i)(\$\{jndi:|Runtime\.getRuntime|java\.lang\.Runtime|ProcessBuilder|"
    r"@type[\"']\s*:\s*[\"']com\.|fastjson|TemplatesImpl|cmd\.exe|/bin/(?:sh|bash)\b|"
    # Generic OS command injection markers in URLs (decoded or encoded forms)
    r"[?&](?:cmd|exec|command|c)=(?:cat|ls|whoami|id|uname|wget|curl|nc|bash|sh)\b|"
    r"%20(?:/etc/(?:passwd|shadow|hosts)|/proc/self)|"
    r";(?:cat|ls|whoami|id|wget|curl|nc)\s|"
    r"\|(?:cat|ls|whoami|id|wget|curl|nc)\s|"
    r"`(?:cat|ls|whoami|id|wget|curl)\s|"
    r"\$\((?:cat|ls|whoami|id|wget|curl)\s)"
)
UNUSUAL_METHODS = {"PUT", "PATCH", "TRACE", "CONNECT", "DELETE", "PROPFIND", "MOVE"}
PURE_SYMBOL_RX = re.compile(r"^[\W_]+$")


def load_signatures(path: Path | None) -> list[dict]:
    if not path:
        return []
    if not path.exists():
        return []
    data = json.loads(path.read_text(encoding="utf-8"))
    sigs = data.get("signatures", data) if isinstance(data, dict) else data
    out = []
    for s in sigs:
        if (s.get("category") or "").lower() != "ua":
            continue
        try:
            s["_re"] = re.compile(s["pattern"])
            out.append(s)
        except re.error:
            continue
    return out


def parse_ts(s: str | None) -> datetime | None:
    return _hc.parse_ts(s)


def severity_p(rule_id: str) -> str:
    if rule_id in ("R-NGX-008", "R-NGX-007"):
        return "P1"
    if rule_id in ("R-NGX-002", "R-NGX-006", "R-NGX-009"):
        return "P2"
    return "P3"


def category_for(rule_id: str) -> str:
    return {
        "R-NGX-001": "recon",
        "R-NGX-002": "recon",
        "R-NGX-003": "recon",
        "R-NGX-004": "其他",
        "R-NGX-005": "其他",
        "R-NGX-006": "rce",
        "R-NGX-007": "sqli",
        "R-NGX-008": "rce",
        "R-NGX-009": "data-exfil",
        "R-NGX-010": "recon",
    }.get(rule_id, "其他")


def fp_prob(rule_id: str) -> float:
    return {
        "R-NGX-001": 0.10,
        "R-NGX-002": 0.20,
        "R-NGX-003": 0.30,
        "R-NGX-004": 0.40,
        "R-NGX-005": 0.35,
        "R-NGX-006": 0.10,
        "R-NGX-007": 0.10,
        "R-NGX-008": 0.05,
        "R-NGX-009": 0.30,
        "R-NGX-010": 0.45,
    }.get(rule_id, 0.4)


def action_for(rule_id: str) -> str:
    return {
        "R-NGX-001": "封禁源 IP；导出该 IP 全量行为时间线；联动 WAF 规则",
        "R-NGX-002": "5min 5xx/4xx 阈值告警；阻断该 IP；检查是否为弱口令爆破",
        "R-NGX-003": "敏感路径暴露排查；下线静态文件；审计是否被泄露",
        "R-NGX-004": "评估是否触达解析栈缓冲区；查 WAF 限制；留底",
        "R-NGX-005": "排查 webdav / restful API 是否对外开放；如非业务请阻断",
        "R-NGX-006": "审计目标接口对应控制器是否做过路径校验；同源 IP 全量行为查",
        "R-NGX-007": "审计被请求接口是否参数化查询；备份当时 DB 状态",
        "R-NGX-008": "立即切走 ir 模式；先封 IP 再溯源；查 JVM 进程与外联",
        "R-NGX-009": "判断是否为数据外发；查响应方向 IP 与历史；必要时抓包复盘",
        "R-NGX-010": "结合该 IP 其他规则命中评估；纳入待跟进",
    }.get(rule_id, "纳入待跟进")


def emit(findings: list[dict], rule_id: str, rec: dict, extra: dict) -> None:
    _hc.emit_finding(
        findings,
        id_prefix="NGX",
        severity=severity_p(rule_id),
        category=category_for(rule_id),
        evidence={
            "ts": rec.get("ts"),
            "src_ip": rec.get("src_ip"),
            "uri": (rec.get("uri") or "")[:300],
            "method": rec.get("method"),
            "status": rec.get("status"),
            "ua": (rec.get("ua") or "")[:200],
            "src_file": rec.get("src_file"),
            "line_no": rec.get("line_no"),
            **extra,
        },
        rule_id=rule_id,
        fp_prob=fp_prob(rule_id),
        action=action_for(rule_id),
        iocs=_iocs_from(rec, rule_id),
    )


def _iocs_from(rec: dict, rule_id: str) -> list[dict]:
    out = []
    if rec.get("src_ip"):
        out.append({"type": "ip", "value": rec["src_ip"], "confidence": "medium",
                    "first_seen": rec.get("ts"), "source": f"{rule_id}@{rec.get('src_file')}:{rec.get('line_no')}",
                    "tag": f"rule:{rule_id}"})
    if rule_id == "R-NGX-001" and rec.get("ua"):
        out.append({"type": "ua", "value": (rec.get("ua") or "")[:200], "confidence": "high",
                    "first_seen": rec.get("ts"), "source": rule_id, "tag": "tool"})
    return out


def detect(records: Iterator[dict], ua_sigs: list[dict]) -> list[dict]:
    findings: list[dict] = []

    # rolling-window state for R-NGX-002
    burst_window = timedelta(minutes=5)
    ip_4xx: dict[str, deque] = defaultdict(deque)
    ip_burst_emitted: set[str] = set()

    for rec in records:
        ts = parse_ts(rec.get("ts"))
        uri = rec.get("uri") or ""
        ua = rec.get("ua") or ""
        method = (rec.get("method") or "").upper()
        status = rec.get("status")

        # R-NGX-001 scanner UA
        if ua:
            for s in ua_sigs:
                if s["_re"].search(ua):
                    emit(findings, "R-NGX-001", rec, {"tool": s.get("tool"), "sig_id": s.get("id")})
                    break  # one hit is enough

        # R-NGX-002 4xx burst
        if status and 400 <= status < 500 and rec.get("src_ip") and ts:
            ip = rec["src_ip"]
            dq = ip_4xx[ip]
            dq.append(ts)
            while dq and (ts - dq[0]) > burst_window:
                dq.popleft()
            if len(dq) >= 50 and ip not in ip_burst_emitted:
                emit(findings, "R-NGX-002", rec, {"4xx_count_5min": len(dq)})
                ip_burst_emitted.add(ip)

        # R-NGX-003 sensitive path
        if uri and SENSITIVE_PATH_RX.search(uri):
            emit(findings, "R-NGX-003", rec, {})

        # R-NGX-004 long URL
        if uri and len(uri) > 1000:
            emit(findings, "R-NGX-004", rec, {"uri_len": len(uri)})

        # R-NGX-005 unusual method
        if method and method in UNUSUAL_METHODS:
            emit(findings, "R-NGX-005", rec, {"method": method})

        # R-NGX-006 traversal
        if uri and TRAVERSAL_RX.search(uri):
            emit(findings, "R-NGX-006", rec, {})

        # R-NGX-007 sqli
        if uri and SQLI_RX.search(uri):
            emit(findings, "R-NGX-007", rec, {})

        # R-NGX-008 rce / jndi / fastjson
        if uri and RCE_RX.search(uri):
            emit(findings, "R-NGX-008", rec, {})

        # R-NGX-009 large response body — derive from raw_line if combined log
        raw = rec.get("raw_line") or ""
        if raw:
            # nginx combined: "<method> <uri> HTTP/x.x" <status> <bytes>
            m = re.search(r'\"\s+\d{3}\s+(\d+)\s+\"', raw)
            if m:
                try:
                    body = int(m.group(1))
                    if body > 10 * 1024 * 1024:
                        emit(findings, "R-NGX-009", rec, {"body_bytes": body})
                except Exception:
                    pass

        # R-NGX-010 abnormal UA
        if ua is not None:
            if ua == "" or ua == "-" or len(ua) < 5 or PURE_SYMBOL_RX.match(ua):
                emit(findings, "R-NGX-010", rec, {"ua_repr": repr(ua)[:80]})
    return findings


def iter_ndjson_or_stdin(path: str) -> Iterator[dict]:
    yield from _hc.iter_ndjson(path, log_type=("nginx-access", "apache-access"))


def main(argv=None) -> int:
    args = parse_args(argv)
    sig_path = Path(args.patterns) if args.patterns else \
        (Path(__file__).resolve().parent.parent / "data" / "tool-signatures.json")
    ua_sigs = load_signatures(sig_path)
    if args.verbose:
        print(f"[INFO] loaded {len(ua_sigs)} UA signatures", file=sys.stderr)

    findings = detect(iter_ndjson_or_stdin(args.input), ua_sigs)

    output = {
        "version": "0.1",
        "total": len(findings),
        "findings": findings,
    }
    text = json.dumps(output, ensure_ascii=False, indent=2)
    if args.output:
        Path(args.output).write_text(text, encoding="utf-8")
    else:
        print(text)
    if args.verbose:
        c = Counter(f["rule_id"] for f in findings)
        print(f"[INFO] by_rule={dict(c)}", file=sys.stderr)
    return 0


def parse_args(argv=None):
    p = argparse.ArgumentParser(description="nginx access log anomaly detector")
    p.add_argument("--input", required=True, help="NDJSON (use - for stdin)")
    p.add_argument("--patterns", default=None, help="Override tool-signatures.json")
    p.add_argument("--output", default=None, help="Output JSON file")
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
