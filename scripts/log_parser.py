#!/usr/bin/env python3.11
# -*- coding: utf-8 -*-
"""
log_parser.py — Normalize heterogeneous logs into a unified NDJSON schema.

Purpose
-------
Parse nginx-access (combined / JSON), apache-combined, Linux auth.log / secure,
syslog, JSON alert lists, and CSV alert exports into one canonical schema so
downstream scripts (ioc_match, nginx_anomaly, auth_log_audit, timeline_build)
can consume them uniformly.

Compliance & red lines
----------------------
- Offline only. Never makes network calls.
- No third-party libraries; stdlib only.
- Does not modify input files. Output is the only side-effect.
- Output should still be piped through desensitize.py before user-facing display.

Input
-----
A single log file, a directory (recursively scanned), or a stream. Plain or .gz.

Output
------
NDJSON to stdout (one JSON object per line) or --output file. Each record:
  {ts, log_type, src_ip, dst_ip, user, method, uri, status, ua, msg,
   raw_line, line_no, src_file}

Example
-------
  log_parser.py --input /var/log/nginx/access.log --type nginx
  log_parser.py --input ./alerts.json --type json --output normalized.ndjson
"""
from __future__ import annotations

import argparse
import csv
import gzip
import io
import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Iterator, Optional

# Shared helpers (pure stdlib). sys.path bootstrap keeps the script runnable
# standalone as `python3.11 scripts/log_parser.py` without PYTHONPATH/pip.
sys.path.insert(0, str(Path(__file__).resolve().parent))
import hvv_common as _hc  # noqa: E402


# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------
SCHEMA_FIELDS = (
    "ts", "log_type", "src_ip", "dst_ip", "user", "method", "uri",
    "status", "ua", "msg", "raw_line", "line_no", "src_file",
)


def empty_record() -> dict[str, Any]:
    return {k: None for k in SCHEMA_FIELDS}


# ---------------------------------------------------------------------------
# Time parsing helpers
# ---------------------------------------------------------------------------
MONTHS = {m: i for i, m in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun",
     "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], start=1)}


def parse_nginx_time(s: str) -> Optional[str]:
    """[10/Oct/2025:13:55:36 +0800] -> ISO8601 string."""
    try:
        # strip brackets if any
        s = s.strip().strip("[]")
        # 10/Oct/2025:13:55:36 +0800
        m = re.match(r"^(\d{1,2})/(\w{3})/(\d{4}):(\d{2}):(\d{2}):(\d{2})\s*([+-]\d{4})?$", s)
        if not m:
            return None
        d, mon, y, hh, mm, ss, tz = m.groups()
        month = MONTHS.get(mon)
        if not month:
            return None
        dt = datetime(int(y), month, int(d), int(hh), int(mm), int(ss))
        if tz:
            sign = 1 if tz[0] == "+" else -1
            hours = int(tz[1:3]); mins = int(tz[3:5])
            offset_min = sign * (hours * 60 + mins)
            return dt.isoformat() + f"{tz[0]}{tz[1:3]}:{tz[3:5]}"
        return dt.isoformat()
    except Exception:
        return None


def parse_syslog_time(s: str, year_hint: int | None = None) -> Optional[str]:
    """'Oct 10 13:55:36' -> ISO8601 (year inferred)."""
    try:
        m = re.match(r"^(\w{3})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})$", s.strip())
        if not m:
            return None
        mon, d, hh, mm, ss = m.groups()
        month = MONTHS.get(mon)
        if not month:
            return None
        year = year_hint if year_hint is not None else datetime.now().year
        dt = datetime(year, month, int(d), int(hh), int(mm), int(ss))
        return dt.isoformat()
    except Exception:
        return None


def parse_iso_any(s: str) -> Optional[str]:
    """Try to parse generic ISO-ish timestamp, return as-is if it looks ISO."""
    if not s:
        return None
    s = s.strip()
    # cheap sniff: contains T or -
    if re.match(r"^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}", s):
        return s
    return None


# ---------------------------------------------------------------------------
# File iteration
# ---------------------------------------------------------------------------
def open_text(path: Path) -> io.TextIOBase:
    if path.suffix == ".gz":
        return gzip.open(str(path), mode="rt", encoding="utf-8", errors="replace")
    return open(str(path), mode="r", encoding="utf-8", errors="replace")


def iter_files(input_path: Path) -> Iterator[Path]:
    if input_path.is_file():
        yield input_path
        return
    if input_path.is_dir():
        for p in sorted(input_path.rglob("*")):
            if p.is_file():
                yield p
        return
    raise FileNotFoundError(str(input_path))


# ---------------------------------------------------------------------------
# Type detection
# ---------------------------------------------------------------------------
def detect_type(path: Path, first_line: str | None) -> str:
    name = path.name.lower()
    if name.endswith(".json") or (first_line and first_line.lstrip().startswith(("{", "["))):
        # could be json log file or array — sniff
        try:
            stripped = (first_line or "").lstrip()
            if stripped.startswith("{") and '"type"' in stripped and '"data"' not in stripped[:200]:
                # likely an alert blob
                return "json-alert"
            if stripped.startswith("["):
                return "json-alert"
            if stripped.startswith("{"):
                return "json-alert"
        except Exception:
            pass
    if name.endswith(".csv"):
        return "csv-alert"
    if "auth.log" in name or "secure" in name:
        return "linux-auth"
    if "access" in name and ("nginx" in name or name.endswith((".log", ".log.gz")) or "access" in name):
        return "nginx-access"
    if "apache" in name:
        return "apache-access"
    if "syslog" in name or "messages" in name:
        return "syslog"
    # default
    if first_line and re.search(r'\] "(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH) ', first_line):
        return "nginx-access"
    if first_line and re.search(r"sshd\[\d+\]:", first_line):
        return "linux-auth"
    return "syslog"


# ---------------------------------------------------------------------------
# Parsers
# ---------------------------------------------------------------------------
NGINX_COMBINED_RE = re.compile(
    r'^(?P<src_ip>\S+)\s+\S+\s+(?P<user>\S+)\s+\[(?P<ts>[^\]]+)\]\s+'
    r'"(?P<method>[A-Z]+)\s+(?P<uri>.*?)\s+HTTP/[\d.]+"\s+(?P<status>\d{3})\s+(?P<bytes>\S+)\s+'
    r'"(?P<referer>[^"]*)"\s+"(?P<ua>[^"]*)"'
)


def parse_nginx_line(line: str) -> dict[str, Any] | None:
    m = NGINX_COMBINED_RE.match(line)
    if m:
        rec = empty_record()
        rec["ts"] = parse_nginx_time(m.group("ts"))
        rec["log_type"] = "nginx-access"
        rec["src_ip"] = m.group("src_ip")
        u = m.group("user")
        rec["user"] = None if u in ("-", "") else u
        rec["method"] = m.group("method")
        rec["uri"] = m.group("uri")
        try:
            rec["status"] = int(m.group("status"))
        except Exception:
            rec["status"] = None
        rec["ua"] = m.group("ua")
        rec["msg"] = f'{m.group("method")} {m.group("uri")} {m.group("status")}'
        return rec
    # try JSON log line
    if line.lstrip().startswith("{"):
        try:
            d = json.loads(line)
            rec = empty_record()
            rec["log_type"] = "nginx-access"
            rec["ts"] = d.get("time") or d.get("ts") or d.get("@timestamp")
            rec["src_ip"] = d.get("remote_addr") or d.get("client_ip") or d.get("src_ip")
            rec["method"] = d.get("request_method") or d.get("method")
            rec["uri"] = d.get("request_uri") or d.get("uri")
            try:
                rec["status"] = int(d.get("status") or 0) or None
            except Exception:
                rec["status"] = None
            rec["ua"] = d.get("http_user_agent") or d.get("user_agent")
            rec["msg"] = json.dumps({"method": rec["method"], "uri": rec["uri"], "status": rec["status"]}, ensure_ascii=False)
            return rec
        except Exception:
            return None
    return None


SSHD_RE_FAIL = re.compile(
    r"(?P<ts>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}).*sshd\[\d+\]:\s+"
    r"Failed (password|publickey)\s+for\s+(invalid user\s+)?(?P<user>\S+)\s+from\s+"
    r"(?P<src_ip>\S+)\s+port\s+\d+"
)
SSHD_RE_OK = re.compile(
    r"(?P<ts>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}).*sshd\[\d+\]:\s+"
    r"Accepted (password|publickey)\s+for\s+(?P<user>\S+)\s+from\s+(?P<src_ip>\S+)\s+port\s+\d+"
)
GENERIC_SYSLOG_RE = re.compile(
    r"^(?P<ts>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+(?P<proc>[^:]+):\s*(?P<msg>.*)$"
)


def parse_auth_line(line: str, year_hint: int | None) -> dict[str, Any] | None:
    rec = empty_record()
    rec["log_type"] = "linux-auth"
    m = SSHD_RE_FAIL.search(line)
    if m:
        rec["ts"] = parse_syslog_time(m.group("ts"), year_hint)
        rec["src_ip"] = m.group("src_ip")
        rec["user"] = m.group("user")
        rec["msg"] = "ssh-fail"
        return rec
    m = SSHD_RE_OK.search(line)
    if m:
        rec["ts"] = parse_syslog_time(m.group("ts"), year_hint)
        rec["src_ip"] = m.group("src_ip")
        rec["user"] = m.group("user")
        rec["msg"] = "ssh-success"
        return rec
    # sudo / useradd / passwd / new account
    m = GENERIC_SYSLOG_RE.match(line)
    if m:
        rec["ts"] = parse_syslog_time(m.group("ts"), year_hint)
        proc = m.group("proc") or ""
        body = m.group("msg") or ""
        rec["msg"] = f"{proc}: {body}"
        ip_m = re.search(r"\bfrom\s+([\d\.:a-fA-F]+)", body)
        if ip_m:
            rec["src_ip"] = ip_m.group(1)
        user_m = re.search(r"\b(user|by)\s+(\S+)", body)
        if user_m:
            rec["user"] = user_m.group(2)
        return rec
    return None


def parse_syslog_line(line: str, year_hint: int | None) -> dict[str, Any] | None:
    m = GENERIC_SYSLOG_RE.match(line)
    if not m:
        return None
    rec = empty_record()
    rec["log_type"] = "syslog"
    rec["ts"] = parse_syslog_time(m.group("ts"), year_hint)
    rec["msg"] = f'{m.group("proc")}: {m.group("msg")}'
    ip_m = re.search(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b", line)
    if ip_m:
        rec["src_ip"] = ip_m.group(1)
    return rec


SRC_IP_KEYS = ("src_ip", "srcip", "source_ip", "clientip", "client_ip", "remote_addr", "remote_ip", "src", "ip")
DST_IP_KEYS = ("dst_ip", "dstip", "dest_ip", "destination_ip", "dst", "server_ip")
USER_KEYS = ("user", "username", "user_name", "account", "uid")
TS_KEYS = ("ts", "time", "@timestamp", "timestamp", "event_time", "createTime", "create_time")
URI_KEYS = ("uri", "url", "request_uri", "path")
METHOD_KEYS = ("method", "http_method", "request_method")
UA_KEYS = ("ua", "user_agent", "http_user_agent", "useragent")
STATUS_KEYS = ("status", "http_status", "response_code", "resp_code")
MSG_KEYS = ("msg", "message", "description", "alert", "title", "name")


def map_json_record(obj: dict[str, Any]) -> dict[str, Any]:
    rec = empty_record()
    rec["log_type"] = "json-alert"

    def first(keys):
        for k in keys:
            if k in obj and obj[k] not in (None, ""):
                return obj[k]
        return None

    rec["ts"] = first(TS_KEYS)
    rec["src_ip"] = first(SRC_IP_KEYS)
    rec["dst_ip"] = first(DST_IP_KEYS)
    rec["user"] = first(USER_KEYS)
    rec["uri"] = first(URI_KEYS)
    rec["method"] = first(METHOD_KEYS)
    rec["ua"] = first(UA_KEYS)
    s = first(STATUS_KEYS)
    if s is not None:
        try:
            rec["status"] = int(s)
        except Exception:
            rec["status"] = None
    rec["msg"] = first(MSG_KEYS) or json.dumps(obj, ensure_ascii=False)[:500]
    return rec


# ---------------------------------------------------------------------------
# Dispatcher
# ---------------------------------------------------------------------------
def parse_text_stream(stream: Iterable[str], log_type: str, src_file: str,
                      year_hint: int | None) -> Iterator[dict[str, Any]]:
    for line_no, raw in enumerate(stream, start=1):
        line = raw.rstrip("\n")
        if not line.strip():
            continue
        rec: dict[str, Any] | None = None
        if log_type in ("nginx-access", "apache-access"):
            rec = parse_nginx_line(line)
            if rec and log_type == "apache-access":
                rec["log_type"] = "apache-access"
        elif log_type == "linux-auth":
            rec = parse_auth_line(line, year_hint)
        elif log_type == "syslog":
            rec = parse_syslog_line(line, year_hint)
        elif log_type == "json-alert":
            try:
                obj = json.loads(line)
                rec = map_json_record(obj) if isinstance(obj, dict) else None
            except Exception:
                rec = None
        if rec is None:
            continue
        rec["raw_line"] = line[:2000]
        rec["line_no"] = line_no
        rec["src_file"] = src_file
        yield rec


def parse_csv_file(path: Path) -> Iterator[dict[str, Any]]:
    with open_text(path) as f:
        reader = csv.DictReader(f)
        for line_no, row in enumerate(reader, start=2):  # row 2 because header is row 1
            rec = map_json_record({k: v for k, v in row.items() if v is not None})
            rec["log_type"] = "csv-alert"
            rec["raw_line"] = ",".join(str(v) for v in row.values())[:2000]
            rec["line_no"] = line_no
            rec["src_file"] = str(path)
            yield rec


def parse_json_array_file(path: Path) -> Iterator[dict[str, Any]]:
    """Handle whole-file JSON array of alerts, or a dict wrapping an array
    under common keys like 'alerts', 'data', 'events', 'results', 'items'."""
    with open_text(path) as f:
        try:
            data = json.load(f)
        except Exception:
            return
    items: list[Any] = []
    if isinstance(data, list):
        items = data
    elif isinstance(data, dict):
        # Try common wrapper keys
        for k in ("alerts", "data", "events", "results", "items", "records", "logs"):
            v = data.get(k)
            if isinstance(v, list):
                items = v
                break
        if not items:
            # treat the dict itself as one record
            items = [data]
    for i, obj in enumerate(items, start=1):
        if isinstance(obj, dict):
            rec = map_json_record(obj)
            rec["raw_line"] = json.dumps(obj, ensure_ascii=False)[:2000]
            rec["line_no"] = i
            rec["src_file"] = str(path)
            yield rec


# ---------------------------------------------------------------------------
# Filtering
# ---------------------------------------------------------------------------
def in_window(ts: str | None, since: str | None, until: str | None) -> bool:
    return _hc.in_window(ts, since, until)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def parse_args(argv=None):
    p = argparse.ArgumentParser(
        description="Normalize logs into NDJSON for downstream HVV-defender scripts."
    )
    p.add_argument("--input", required=True, help="File or directory")
    p.add_argument("--type", default="auto",
                   choices=["auto", "nginx", "apache", "auth", "syslog", "json", "csv"],
                   help="Log type; auto detects per file")
    p.add_argument("--output", default=None, help="Output NDJSON file (default stdout)")
    p.add_argument("--since", default=None, help="ISO timestamp lower bound (inclusive)")
    p.add_argument("--until", default=None, help="ISO timestamp upper bound (inclusive)")
    p.add_argument("--year", default=None, type=int,
                   help="Year hint for syslog-style timestamps lacking year")
    p.add_argument("-q", "--quiet", action="store_true", help="Suppress stderr progress")
    p.add_argument("-v", "--verbose", action="store_true", help="Verbose stderr logging")
    return p.parse_args(argv)


def log(stream, msg, quiet=False):
    if quiet:
        return
    print(msg, file=stream)


def normalize_type(short: str) -> str:
    return {
        "nginx": "nginx-access", "apache": "apache-access", "auth": "linux-auth",
        "syslog": "syslog", "json": "json-alert", "csv": "csv-alert",
    }.get(short, short)


def main(argv=None) -> int:
    args = parse_args(argv)
    in_path = Path(args.input)
    if not in_path.exists():
        print(f"[ERROR] input not found: {in_path}", file=sys.stderr)
        return 1

    out_fp = open(args.output, "w", encoding="utf-8") if args.output else sys.stdout
    total = 0
    try:
        for fpath in iter_files(in_path):
            try:
                first_line = None
                if args.type == "auto" and fpath.suffix not in (".csv",):
                    try:
                        with open_text(fpath) as fh:
                            first_line = fh.readline()
                    except Exception:
                        first_line = None
                    log_type = detect_type(fpath, first_line)
                elif args.type == "auto":
                    log_type = detect_type(fpath, None)
                else:
                    log_type = normalize_type(args.type)

                if args.verbose:
                    log(sys.stderr, f"[INFO] {fpath} -> {log_type}", args.quiet)

                if log_type == "csv-alert":
                    record_iter = parse_csv_file(fpath)
                elif log_type == "json-alert" and fpath.suffix == ".json":
                    record_iter = parse_json_array_file(fpath)
                else:
                    fh = open_text(fpath)
                    record_iter = parse_text_stream(fh, log_type, str(fpath), args.year)

                for rec in record_iter:
                    if not in_window(rec.get("ts"), args.since, args.until):
                        continue
                    out_fp.write(json.dumps(rec, ensure_ascii=False) + "\n")
                    total += 1
            except Exception as e:
                log(sys.stderr, f"[WARN] failed on {fpath}: {e}", args.quiet)
                continue
        log(sys.stderr, f"[INFO] total records: {total}", args.quiet)
    except Exception as e:
        print(f"[ERROR] runtime: {e}", file=sys.stderr)
        return 2
    finally:
        if args.output:
            out_fp.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
