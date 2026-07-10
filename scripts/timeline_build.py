#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
timeline_build.py — Merge multiple NDJSON log streams into a sorted timeline.

Purpose
-------
Stream-merge several NDJSON files produced by log_parser.py, ordered by `ts`,
optionally filtered by time window / src_ip / user / src_file, and optionally
bucketed (e.g. 5 minutes) to surface event-rate spikes.

Compliance & red lines
----------------------
- Offline. No network. Only reads provided files.
- Output should be piped through desensitize.py before sharing.

Input
-----
  --inputs   one or more NDJSON paths

Output
------
CSV (default) or NDJSON, or bucket aggregation summary.

Example
-------
  timeline_build.py --inputs auth.ndjson web.ndjson --output timeline.csv
  timeline_build.py --inputs *.ndjson --bucket 5m --output spikes.json
"""
from __future__ import annotations

import argparse
import csv
import heapq
import json
import re
import sys
from collections import Counter
from datetime import datetime, timedelta
from pathlib import Path
from typing import Iterator

# Shared helpers (pure stdlib). sys.path bootstrap keeps the script runnable
# standalone as `python3 scripts/timeline_build.py` without PYTHONPATH/pip.
sys.path.insert(0, str(Path(__file__).resolve().parent))
import hvv_common as _hc  # noqa: E402


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def parse_bucket(s: str) -> timedelta:
    m = re.fullmatch(r"(\d+)([smhd])", s.strip().lower())
    if not m:
        raise ValueError(f"bad bucket spec: {s}")
    n, unit = int(m.group(1)), m.group(2)
    return {
        "s": timedelta(seconds=n),
        "m": timedelta(minutes=n),
        "h": timedelta(hours=n),
        "d": timedelta(days=n),
    }[unit]


def parse_ts(ts: str | None) -> datetime | None:
    return _hc.parse_ts(ts)


def iter_ndjson(path: Path) -> Iterator[dict]:
    yield from _hc.iter_ndjson(path)


def merge_sorted(streams: list[Iterator[dict]]) -> Iterator[dict]:
    """Streaming heapq merge by ts. Records lacking ts go last."""
    # heap items: (sort_key, counter, rec, stream_idx)
    heap: list[tuple] = []
    counter = 0
    iters = [iter(s) for s in streams]
    for i, it in enumerate(iters):
        try:
            rec = next(it)
            key = rec.get("ts") or "￿"
            heapq.heappush(heap, (key, counter, rec, i))
            counter += 1
        except StopIteration:
            pass

    while heap:
        _, _, rec, i = heapq.heappop(heap)
        yield rec
        try:
            nxt = next(iters[i])
            key = nxt.get("ts") or "￿"
            heapq.heappush(heap, (key, counter, nxt, i))
            counter += 1
        except StopIteration:
            continue


# ---------------------------------------------------------------------------
# Filters
# ---------------------------------------------------------------------------
def in_window(ts: str | None, since: str | None, until: str | None) -> bool:
    return _hc.in_window(ts, since, until)


def passes_filters(rec: dict, args) -> bool:
    if not in_window(rec.get("ts"), args.since, args.until):
        return False
    if args.filter_ip and rec.get("src_ip") != args.filter_ip:
        return False
    if args.filter_user and rec.get("user") != args.filter_user:
        return False
    if args.filter_file:
        sf = rec.get("src_file") or ""
        if args.filter_file not in sf:
            return False
    return True


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------
def write_csv(records: Iterator[dict], output, columns: list[str]) -> int:
    n = 0
    writer = csv.writer(output)
    writer.writerow(columns)
    for rec in records:
        row = [rec.get(c, "") if rec.get(c) is not None else "" for c in columns]
        writer.writerow(row)
        n += 1
    return n


def write_ndjson(records: Iterator[dict], output) -> int:
    n = 0
    for rec in records:
        output.write(json.dumps(rec, ensure_ascii=False) + "\n")
        n += 1
    return n


def bucket_aggregate(records: Iterator[dict], delta: timedelta) -> dict:
    """Group events into time buckets; return summary."""
    buckets: dict[str, Counter] = {}
    total = 0
    for rec in records:
        ts = parse_ts(rec.get("ts"))
        if ts is None:
            continue
        epoch = int(ts.timestamp())
        slot = epoch - (epoch % int(delta.total_seconds()))
        slot_iso = datetime.fromtimestamp(slot).isoformat()
        b = buckets.setdefault(slot_iso, Counter())
        b["total"] += 1
        if rec.get("src_ip"):
            b[f"ip:{rec['src_ip']}"] += 1
        if rec.get("log_type"):
            b[f"type:{rec['log_type']}"] += 1
        total += 1
    sorted_buckets = sorted(buckets.items())
    summary = []
    for slot, c in sorted_buckets:
        top_ips = sorted(((k[3:], v) for k, v in c.items() if k.startswith("ip:")),
                         key=lambda x: -x[1])[:5]
        summary.append({
            "bucket": slot,
            "total": c["total"],
            "top_src_ips": [{"src_ip": ip, "count": v} for ip, v in top_ips],
        })
    return {"total_events": total, "buckets": summary}


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main(argv=None) -> int:
    args = parse_args(argv)
    streams = []
    for inp in args.inputs:
        p = Path(inp)
        if not p.exists():
            print(f"[ERROR] not found: {p}", file=sys.stderr)
            return 1
        streams.append(iter_ndjson(p))

    merged = (rec for rec in merge_sorted(streams) if passes_filters(rec, args))

    if args.bucket:
        try:
            delta = parse_bucket(args.bucket)
        except ValueError as e:
            print(f"[ERROR] {e}", file=sys.stderr)
            return 1
        result = bucket_aggregate(merged, delta)
        text = json.dumps(result, ensure_ascii=False, indent=2)
        if args.output:
            Path(args.output).write_text(text, encoding="utf-8")
        else:
            print(text)
        return 0

    fmt = (args.format or "csv").lower()
    if args.output:
        out = open(args.output, "w", encoding="utf-8", newline="")
    else:
        out = sys.stdout

    try:
        if fmt == "csv":
            cols = args.columns.split(",") if args.columns else \
                ["ts", "log_type", "src_ip", "user", "msg", "src_file", "line_no"]
            n = write_csv(merged, out, cols)
        elif fmt in ("ndjson", "jsonl"):
            n = write_ndjson(merged, out)
        else:
            print(f"[ERROR] unknown format: {fmt}", file=sys.stderr)
            return 1
        if args.verbose:
            print(f"[INFO] wrote {n} records", file=sys.stderr)
    finally:
        if args.output:
            out.close()
    return 0


def parse_args(argv=None):
    p = argparse.ArgumentParser(description="Merge NDJSON logs into a sorted timeline")
    p.add_argument("--inputs", nargs="+", required=True, help="NDJSON files to merge")
    p.add_argument("--since", default=None, help="ISO timestamp lower bound")
    p.add_argument("--until", default=None, help="ISO timestamp upper bound")
    p.add_argument("--filter-ip", dest="filter_ip", default=None, help="Only keep this src_ip")
    p.add_argument("--filter-user", dest="filter_user", default=None, help="Only keep this user")
    p.add_argument("--filter-file", dest="filter_file", default=None, help="Substring of src_file")
    p.add_argument("--bucket", default=None, help="Aggregate per bucket window (e.g. 5m, 1h)")
    p.add_argument("--output", default=None, help="Output file (default stdout)")
    p.add_argument("--format", default="csv", choices=["csv", "ndjson", "jsonl"], help="Output format")
    p.add_argument("--columns", default=None, help="CSV column order, comma-separated")
    p.add_argument("-q", "--quiet", action="store_true", help="Quiet stderr")
    p.add_argument("-v", "--verbose", action="store_true", help="Verbose stderr")
    return p.parse_args(argv)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
    except Exception as e:
        print(f"[ERROR] runtime: {e}", file=sys.stderr)
        sys.exit(2)
