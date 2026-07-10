#!/usr/bin/env python3.11
# -*- coding: utf-8 -*-
"""
pcap_parser.py — tshark wrapper that normalizes pcap/pcapng into NDJSON.

Purpose
-------
Call `tshark` to extract six views (http / dns / tls / flow / creds / conn)
from a user-provided pcap or pcapng file and emit a single NDJSON stream
that downstream rule engines (traffic_anomaly.py, ioc_match.py) can consume.

Red lines:
  - Offline only. pcap files must be provided by user; no live capture.
  - No stream reassembly, no full-body capture, only headers + strings.
  - Passwords / secrets are masked as "***<len>" before emit.
  - No outbound network calls to threat-intel APIs.
  - Detection features only; NO reproducible attack payloads.

Unified NDJSON schema (per line):
  {
    "ts": "ISO8601 UTC",
    "view": "http|dns|tls|flow|creds|conn",
    "src_ip": "...", "dst_ip": "...",
    "src_port": int|null, "dst_port": int|null,
    "proto": "tcp|udp|icmp|other",
    "stream_id": int|null,
    "raw": { ...view specific... },
    "src_file": "path/to.pcap",
    "line_no": int  # tshark line index for backtrace
  }

Example
-------
  pcap_parser.py --input capture.pcap --output flows.ndjson
  pcap_parser.py --input capture.pcapng --views http,dns --full -v
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator

TSHARK_TIMEOUT_S = 600
FIELD_SEP = "|"
INSTALL_HINT = (
    "tshark not found on PATH. Install it first:\n"
    "  Debian/Ubuntu: sudo apt install -y tshark\n"
    "  macOS (brew) : brew install wireshark\n"
    "  RHEL/CentOS  : sudo dnf install -y wireshark-cli\n"
    "Then re-run this script."
)

DEFAULT_VIEWS = ["http", "dns", "tls", "flow", "creds"]
ALL_VIEWS = ["http", "dns", "tls", "flow", "creds", "conn"]


def _log(msg: str, quiet: bool = False) -> None:
    if not quiet:
        print(f"[pcap_parser] {msg}", file=sys.stderr)


def _iso_ts(epoch_str: str | None) -> str | None:
    if not epoch_str:
        return None
    try:
        return datetime.fromtimestamp(float(epoch_str), tz=timezone.utc).isoformat()
    except (TypeError, ValueError):
        return None


def _to_int(s: str | None) -> int | None:
    if s is None or s == "":
        return None
    try:
        return int(s)
    except (TypeError, ValueError):
        try:
            return int(float(s))
        except (TypeError, ValueError):
            return None


def _mask_password(pw: str | None) -> str | None:
    if pw is None:
        return None
    return f"***<{len(pw)}>"


def _truncate(s: str | None, n: int) -> str | None:
    if s is None:
        return None
    return s if len(s) <= n else s[:n]


def check_tshark() -> str:
    path = shutil.which("tshark")
    if not path:
        print(INSTALL_HINT, file=sys.stderr)
        sys.exit(1)
    return path


def _run_tshark(tshark: str, pcap: Path, filt: str, fields: list[str],
                quiet: bool, extra_args: list[str] | None = None) -> list[str]:
    cmd = [
        tshark, "-n", "-r", str(pcap),
        "-Y", filt,
        "-T", "fields",
        "-E", f"separator={FIELD_SEP}",
        "-E", "quote=n",
        "-E", "occurrence=f",
    ]
    for f in fields:
        cmd.extend(["-e", f])
    if extra_args:
        cmd.extend(extra_args)
    try:
        proc = subprocess.run(
            cmd,
            check=False,
            capture_output=True,
            text=True,
            timeout=TSHARK_TIMEOUT_S,
        )
    except subprocess.TimeoutExpired:
        _log(f"timeout running tshark filter={filt!r}", quiet)
        return []
    except FileNotFoundError:
        _log("tshark disappeared mid-run", quiet)
        return []
    if proc.returncode not in (0, 1):
        _log(f"tshark rc={proc.returncode} filt={filt!r}: {proc.stderr.strip()[:200]}", quiet)
    return [line for line in proc.stdout.splitlines() if line.strip()]


def _split(line: str, n: int) -> list[str]:
    parts = line.split(FIELD_SEP)
    if len(parts) < n:
        parts += [""] * (n - len(parts))
    return parts[:n]


def _norm(view: str, ts: str | None, src_ip: str, dst_ip: str, src_port,
          dst_port, proto: str, stream_id, raw: dict, src_file: str,
          line_no: int) -> dict:
    return {
        "ts": ts,
        "view": view,
        "src_ip": src_ip or None,
        "dst_ip": dst_ip or None,
        "src_port": _to_int(src_port),
        "dst_port": _to_int(dst_port),
        "proto": proto,
        "stream_id": _to_int(stream_id),
        "raw": raw,
        "src_file": src_file,
        "line_no": line_no,
    }


def view_http(tshark: str, pcap: Path, quiet: bool) -> Iterator[dict]:
    fields = [
        "frame.time_epoch", "ip.src", "ip.dst", "tcp.srcport", "tcp.dstport",
        "tcp.stream", "http.request.method", "http.host", "http.request.uri",
        "http.response.code", "http.user_agent", "http.referer",
        "http.content_type", "http.content_length", "http.request.line",
    ]
    lines = _run_tshark(tshark, pcap, "http.request or http.response", fields, quiet)
    _log(f"view=http tshark_lines={len(lines)}", quiet)
    for i, line in enumerate(lines, 1):
        p = _split(line, len(fields))
        (t, sip, dip, sp, dp, stream, method, host, uri, status, ua, ref,
         ctype, clen, req_line) = p
        raw_line_excerpt = _truncate(req_line or "", 300)
        yield _norm(
            "http", _iso_ts(t), sip, dip, sp, dp, "tcp", stream,
            {
                "host": host or None,
                "method": (method or "").upper() or None,
                "uri": uri or None,
                "status": _to_int(status),
                "ua": ua or None,
                "referer": ref or None,
                "content_type": ctype or None,
                "content_length": _to_int(clen),
                "request_line_excerpt": raw_line_excerpt,
            },
            str(pcap), i,
        )


def view_dns(tshark: str, pcap: Path, quiet: bool) -> Iterator[dict]:
    fields = [
        "frame.time_epoch", "ip.src", "ip.dst", "udp.srcport", "udp.dstport",
        "dns.qry.name", "dns.qry.type", "dns.flags.rcode", "dns.a",
    ]
    lines = _run_tshark(tshark, pcap, "dns", fields, quiet)
    _log(f"view=dns tshark_lines={len(lines)}", quiet)
    for i, line in enumerate(lines, 1):
        t, sip, dip, sp, dp, qname, qtype, rcode, ans = _split(line, len(fields))
        yield _norm(
            "dns", _iso_ts(t), sip, dip, sp, dp, "udp", None,
            {
                "qname": qname or None,
                "qtype": qtype or None,
                "rcode": _to_int(rcode),
                "response_ip": ans or None,
            },
            str(pcap), i,
        )


def view_tls(tshark: str, pcap: Path, quiet: bool) -> Iterator[dict]:
    fields = [
        "frame.time_epoch", "ip.src", "ip.dst", "tcp.srcport", "tcp.dstport",
        "tcp.stream",
        "tls.handshake.extensions_server_name",
        "tls.handshake.version",
        "tls.handshake.ciphersuite",
        "tls.handshake.ja3",
        "tls.handshake.ja3s",
    ]
    lines = _run_tshark(tshark, pcap, "tls.handshake.type == 1", fields, quiet)
    _log(f"view=tls_client_hello tshark_lines={len(lines)}", quiet)
    seen_streams: set[str] = set()
    out_records: list[dict] = []
    for i, line in enumerate(lines, 1):
        (t, sip, dip, sp, dp, stream, sni, ver, cipher, ja3, ja3s) = _split(line, len(fields))
        seen_streams.add(stream or "")
        out_records.append(_norm(
            "tls", _iso_ts(t), sip, dip, sp, dp, "tcp", stream,
            {
                "sni": sni or None,
                "cert_cn": None,
                "cert_issuer": None,
                "version": ver or None,
                "cipher": cipher or None,
                "ja3": ja3 or None,
                "ja3s": ja3s or None,
            },
            str(pcap), i,
        ))

    # Second pass: server-side certificate (Cert message) to fill CN/issuer.
    cert_fields = [
        "frame.time_epoch", "tcp.stream",
        "x509sat.uTF8String", "x509sat.printableString",
        "x509ce.dNSName",
    ]
    cert_lines = _run_tshark(
        tshark, pcap, "tls.handshake.type == 11", cert_fields, quiet
    )
    cert_by_stream: dict[str, dict] = {}
    for line in cert_lines:
        _, stream, u8, pr, dnsn = _split(line, len(cert_fields))
        cn = u8 or pr or dnsn or None
        if stream and stream not in cert_by_stream and cn:
            cert_by_stream[stream] = {"cert_cn": cn}
    for rec in out_records:
        sid = str(rec.get("stream_id")) if rec.get("stream_id") is not None else ""
        if sid in cert_by_stream:
            rec["raw"]["cert_cn"] = cert_by_stream[sid].get("cert_cn")
        yield rec


def view_flow(tshark: str, pcap: Path, quiet: bool) -> Iterator[dict]:
    # Use conv,tcp for a compact stream summary.
    cmd = [tshark, "-n", "-r", str(pcap), "-q", "-z", "conv,tcp"]
    try:
        proc = subprocess.run(cmd, check=False, capture_output=True,
                              text=True, timeout=TSHARK_TIMEOUT_S)
    except subprocess.TimeoutExpired:
        _log("timeout on conv,tcp", quiet)
        return
    text = proc.stdout or ""
    lines = text.splitlines()
    _log(f"view=flow raw_lines={len(lines)}", quiet)
    # conv,tcp format: <A> <-> <B> frames_a frames_b bytes_a bytes_b frames bytes rel_start duration
    row_rx = re.compile(
        r"^\s*(\S+):(\d+)\s+<->\s+(\S+):(\d+)"
        r"\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+"
        r"([\d.]+)\s+([\d.]+)"
    )
    i = 0
    for raw in lines:
        m = row_rx.match(raw)
        if not m:
            continue
        i += 1
        (a_ip, a_port, b_ip, b_port, frames_a, frames_b, bytes_a, bytes_b,
         frames_total, bytes_total, rel_start, duration) = m.groups()
        yield _norm(
            "flow", None, a_ip, b_ip, a_port, b_port, "tcp", None,
            {
                "duration_s": float(duration),
                "bytes_total": int(bytes_total),
                "packets_total": int(frames_total),
                "bytes_a2b": int(bytes_a),
                "bytes_b2a": int(bytes_b),
                "packets_a2b": int(frames_a),
                "packets_b2a": int(frames_b),
                "rel_start": float(rel_start),
            },
            str(pcap), i,
        )


def view_creds(tshark: str, pcap: Path, quiet: bool) -> Iterator[dict]:
    # Basic auth via HTTP Authorization
    ba_fields = [
        "frame.time_epoch", "ip.src", "ip.dst", "tcp.srcport", "tcp.dstport",
        "http.authbasic",
    ]
    ba_lines = _run_tshark(
        tshark, pcap, "http.authorization contains \"Basic\"", ba_fields, quiet
    )
    i = 0
    for line in ba_lines:
        t, sip, dip, sp, dp, auth = _split(line, len(ba_fields))
        i += 1
        user = None
        pw = None
        if auth and ":" in auth:
            user, pw = auth.split(":", 1)
        yield _norm(
            "creds", _iso_ts(t), sip, dip, sp, dp, "tcp", None,
            {
                "auth_type": "http-basic",
                "username": user,
                "password_masked": _mask_password(pw),
            },
            str(pcap), i,
        )

    # FTP USER / PASS
    ftp_fields = [
        "frame.time_epoch", "ip.src", "ip.dst", "tcp.srcport", "tcp.dstport",
        "ftp.request.command", "ftp.request.arg",
    ]
    ftp_lines = _run_tshark(
        tshark, pcap,
        "ftp.request.command == \"USER\" or ftp.request.command == \"PASS\"",
        ftp_fields, quiet,
    )
    for line in ftp_lines:
        t, sip, dip, sp, dp, cmd, arg = _split(line, len(ftp_fields))
        i += 1
        cmd_u = (cmd or "").upper()
        if cmd_u == "USER":
            yield _norm(
                "creds", _iso_ts(t), sip, dip, sp, dp, "tcp", None,
                {"auth_type": "ftp-user", "username": arg or None,
                 "password_masked": None},
                str(pcap), i,
            )
        elif cmd_u == "PASS":
            yield _norm(
                "creds", _iso_ts(t), sip, dip, sp, dp, "tcp", None,
                {"auth_type": "ftp-pass", "username": None,
                 "password_masked": _mask_password(arg or "")},
                str(pcap), i,
            )

    # Telnet login prompts (heuristic — telnet.data contains "login:")
    tel_fields = [
        "frame.time_epoch", "ip.src", "ip.dst", "tcp.srcport", "tcp.dstport",
        "telnet.data",
    ]
    tel_lines = _run_tshark(
        tshark, pcap,
        "telnet.data contains \"login:\" or telnet.data contains \"Password:\"",
        tel_fields, quiet,
    )
    for line in tel_lines:
        t, sip, dip, sp, dp, data = _split(line, len(tel_fields))
        i += 1
        yield _norm(
            "creds", _iso_ts(t), sip, dip, sp, dp, "tcp", None,
            {"auth_type": "telnet-prompt", "username": None,
             "password_masked": _mask_password("") if not data else None},
            str(pcap), i,
        )


def view_conn(tshark: str, pcap: Path, quiet: bool) -> Iterator[dict]:
    fields = [
        "frame.time_epoch", "ip.src", "ip.dst",
        "tcp.srcport", "tcp.dstport", "udp.srcport", "udp.dstport",
        "ip.proto", "frame.len", "tcp.seq", "tcp.ack", "tcp.flags",
    ]
    lines = _run_tshark(tshark, pcap, "ip", fields, quiet)
    _log(f"view=conn tshark_lines={len(lines)}", quiet)
    for i, line in enumerate(lines, 1):
        (t, sip, dip, tsp, tdp, usp, udp, ipproto, flen, seq, ack, flags) = _split(
            line, len(fields)
        )
        sp = tsp or usp
        dp = tdp or udp
        proto = "tcp" if tsp else ("udp" if usp else "other")
        yield _norm(
            "conn", _iso_ts(t), sip, dip, sp, dp, proto, None,
            {
                "seq": _to_int(seq),
                "ack": _to_int(ack),
                "flags": flags or None,
                "length": _to_int(flen),
            },
            str(pcap), i,
        )


VIEW_FUNCS = {
    "http": view_http,
    "dns": view_dns,
    "tls": view_tls,
    "flow": view_flow,
    "creds": view_creds,
    "conn": view_conn,
}


def parse_args(argv=None):
    p = argparse.ArgumentParser(
        description="pcap/pcapng -> NDJSON normalizer (tshark wrapper)"
    )
    p.add_argument("--input", required=True,
                   help="Path to pcap or pcapng file")
    p.add_argument("--output", default=None,
                   help="Output NDJSON path (default: stdout)")
    p.add_argument("--views", default=",".join(DEFAULT_VIEWS),
                   help=f"Comma-separated views. Default: {','.join(DEFAULT_VIEWS)}")
    p.add_argument("--full", action="store_true",
                   help="Include per-packet conn view (large output)")
    p.add_argument("-q", "--quiet", action="store_true",
                   help="Suppress stderr progress")
    p.add_argument("-v", "--verbose", action="store_true",
                   help="More stderr detail")
    return p.parse_args(argv)


def main(argv=None) -> int:
    args = parse_args(argv)
    tshark = check_tshark()

    pcap = Path(args.input)
    if not pcap.exists():
        print(f"[ERROR] input not found: {pcap}", file=sys.stderr)
        return 1
    if pcap.stat().st_size == 0:
        _log("empty pcap, nothing to emit", args.quiet)
        return 0

    views = [v.strip() for v in args.views.split(",") if v.strip()]
    if args.full and "conn" not in views:
        views.append("conn")
    views = [v for v in views if v in VIEW_FUNCS]
    if not views:
        print("[ERROR] no valid views selected", file=sys.stderr)
        return 1

    out_fh = open(args.output, "w", encoding="utf-8") if args.output else sys.stdout
    n_records = 0
    counts: dict[str, int] = {}
    try:
        for v in views:
            if args.verbose:
                _log(f"begin view={v}", args.quiet)
            fn = VIEW_FUNCS[v]
            try:
                for rec in fn(tshark, pcap, args.quiet):
                    out_fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
                    n_records += 1
                    counts[v] = counts.get(v, 0) + 1
            except Exception as e:  # noqa: BLE001
                _log(f"view={v} error: {e}", args.quiet)
                continue
    finally:
        if args.output:
            out_fh.close()
    _log(f"done records={n_records} by_view={counts}", args.quiet)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
    except Exception as e:  # noqa: BLE001
        print(f"[ERROR] runtime: {e}", file=sys.stderr)
        sys.exit(2)
