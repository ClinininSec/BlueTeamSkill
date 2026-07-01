#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
auth_log_audit.py — Linux auth/secure log audit (ssh / sudo / accounts).

Purpose
-------
Consume normalized NDJSON (log_type=linux-auth) and emit 8-field findings
for eight detection rules:
  R-AUTH-001  Bruteforce burst       — same src_ip ≥ 20 fails in 5 minutes
  R-AUTH-002  Bruteforce success      — burst followed by Accepted (P0)
  R-AUTH-003  Suspicious root login   — root login from new src_ip /24
  R-AUTH-004  New account created     — useradd / adduser markers
  R-AUTH-005  sudo abuse              — high-frequency sudo from one user
  R-AUTH-006  First-time login user   — user never seen before in input
  R-AUTH-007  Re-appearance of user   — markers of deleted user reappearing
  R-AUTH-008  Pubkey login w/o baseline — pubkey login by user absent from
              user-supplied --pubkey-baseline file

Compliance & red lines
----------------------
- Offline, no shell exec.
- Results should still be desensitized before sharing.

Input
-----
  --input    NDJSON path or `-` for stdin
  --pubkey-baseline   optional file listing user=fingerprint pairs

Output
------
JSON list of 8-field findings.
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import re
import sys
from collections import Counter, defaultdict, deque
from datetime import datetime, timedelta
from pathlib import Path
from typing import Iterator


BRUTE_WINDOW = timedelta(minutes=5)
BRUTE_THRESHOLD = 20
# R-AUTH-002 has a lower threshold than R-AUTH-001: even a few failed attempts
# immediately followed by a successful login is a strong intrusion signal.
BRUTE_SUCCESS_THRESHOLD = 5
SUDO_BURST_WINDOW = timedelta(minutes=5)
SUDO_BURST_THRESHOLD = 10


def parse_ts(s: str | None) -> datetime | None:
    if not s:
        return None
    s = s.replace("Z", "+00:00")
    try:
        return datetime.fromisoformat(s)
    except Exception:
        try:
            return datetime.fromisoformat(s.split("+")[0])
        except Exception:
            return None


def severity(rule_id: str) -> str:
    return {
        "R-AUTH-001": "P2",
        "R-AUTH-002": "P0",
        "R-AUTH-003": "P1",
        "R-AUTH-004": "P1",
        "R-AUTH-005": "P2",
        "R-AUTH-006": "P3",
        "R-AUTH-007": "P1",
        "R-AUTH-008": "P1",
    }.get(rule_id, "P3")


def category(rule_id: str) -> str:
    return {
        "R-AUTH-001": "brute-force",
        "R-AUTH-002": "brute-force",
        "R-AUTH-003": "lateral",
        "R-AUTH-004": "lateral",
        "R-AUTH-005": "lateral",
        "R-AUTH-006": "lateral",
        "R-AUTH-007": "lateral",
        "R-AUTH-008": "lateral",
    }.get(rule_id, "其他")


def fp_prob(rule_id: str) -> float:
    return {
        "R-AUTH-001": 0.15,
        "R-AUTH-002": 0.05,
        "R-AUTH-003": 0.25,
        "R-AUTH-004": 0.10,
        "R-AUTH-005": 0.30,
        "R-AUTH-006": 0.45,
        "R-AUTH-007": 0.20,
        "R-AUTH-008": 0.20,
    }.get(rule_id, 0.4)


def action(rule_id: str) -> str:
    return {
        "R-AUTH-001": "封禁源 IP；启用 fail2ban；确认是否对外暴露 22 端口",
        "R-AUTH-002": "立即转 ir 模式：抓 last/lastlog、bash_history、authorized_keys、运行进程、网络连接；强制改密、轮换密钥；评估 SSH 是否需要禁用密码登录",
        "R-AUTH-003": "向客户确认是否运维操作；如非授权，立即冻结账户并改密",
        "R-AUTH-004": "确认创建账户的用户是否授权；审计 useradd/passwd 时间线；如非授权，禁用并溯源",
        "R-AUTH-005": "审计该用户被授予 sudo 权限的原因；如非业务必要请收回",
        "R-AUTH-006": "纳入待跟进：首次出现不一定是恶意，但需结合主机基线判定",
        "R-AUTH-007": "立即调查：已删除账户重新出现是高度可疑信号",
        "R-AUTH-008": "立即审计：未备案密钥登录可能是攻击者植入；备份 authorized_keys 后剔除",
    }.get(rule_id, "纳入待跟进")


def emit(findings: list[dict], rule_id: str, rec: dict, extra: dict) -> None:
    n = len(findings) + 1
    findings.append({
        "id": f"AUTH-{n:03d}",
        "severity": severity(rule_id),
        "category": category(rule_id),
        "evidence": {
            "ts": rec.get("ts"),
            "src_ip": rec.get("src_ip"),
            "user": rec.get("user"),
            "msg": (rec.get("msg") or "")[:240],
            "src_file": rec.get("src_file"),
            "line_no": rec.get("line_no"),
            **extra,
        },
        "rule_id": rule_id,
        "false_positive_prob": fp_prob(rule_id),
        "recommended_action": action(rule_id),
        "iocs": _iocs(rec),
    })


def _iocs(rec: dict) -> list[dict]:
    out = []
    if rec.get("src_ip"):
        out.append({
            "type": "ip", "value": rec["src_ip"], "confidence": "medium",
            "first_seen": rec.get("ts"),
            "source": f"{rec.get('src_file')}:{rec.get('line_no')}", "tag": "auth",
        })
    return out


def ip_subnet(ip: str | None) -> str | None:
    if not ip:
        return None
    try:
        addr = ipaddress.ip_address(ip)
        if isinstance(addr, ipaddress.IPv4Address):
            return str(ipaddress.ip_network(f"{ip}/24", strict=False))
        return str(ipaddress.ip_network(f"{ip}/64", strict=False))
    except ValueError:
        return None


def load_pubkey_baseline(path: Path) -> set[str]:
    """Each non-empty, non-comment line is treated as `user=fingerprint` or just `user`.
    Returns the set of users whose pubkey logins are considered authorized.
    """
    out = set()
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" in line:
            user = line.split("=", 1)[0].strip()
        else:
            user = line
        if user:
            out.add(user)
    return out


def iter_ndjson(path: str) -> Iterator[dict]:
    fh = sys.stdin if path == "-" else open(path, "r", encoding="utf-8")
    try:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            if rec.get("log_type") == "linux-auth":
                yield rec
    finally:
        if path != "-":
            fh.close()


def detect(records: Iterator[dict], pubkey_baseline: set[str] | None) -> list[dict]:
    findings: list[dict] = []
    fail_window: dict[str, deque] = defaultdict(deque)
    burst_emitted: dict[str, datetime] = {}
    sudo_window: dict[str, deque] = defaultdict(deque)
    sudo_emitted: set[str] = set()

    known_users: set[str] = set()
    root_subnet_history: set[str] = set()
    deleted_users: set[str] = set()

    for rec in records:
        ts = parse_ts(rec.get("ts"))
        msg = rec.get("msg") or ""
        ip = rec.get("src_ip")
        user = rec.get("user")

        # R-AUTH-001 brute force
        if msg.startswith("ssh-fail") or "Failed password" in msg or "Failed publickey" in msg:
            if ip and ts:
                dq = fail_window[ip]
                dq.append(ts)
                while dq and (ts - dq[0]) > BRUTE_WINDOW:
                    dq.popleft()
                if len(dq) >= BRUTE_THRESHOLD and ip not in burst_emitted:
                    burst_emitted[ip] = ts
                    emit(findings, "R-AUTH-001", rec, {"fail_count_5min": len(dq)})

        # R-AUTH-002 brute success — triggers on the burst threshold (≥20)
        # already promoting the IP into burst_emitted, OR a softer condition
        # of ≥5 recent failures from the same IP immediately preceding a
        # successful login (the latter is a strong intrusion signal even at
        # low volumes — e.g. credential-spray followed by the right password).
        if msg.startswith("ssh-success") or "Accepted" in msg:
            if ts and ip:
                soft_trigger = False
                window_start_dt = None
                if ip in burst_emitted:
                    window_start_dt = burst_emitted[ip]
                    if ts - window_start_dt <= timedelta(minutes=30):
                        soft_trigger = True
                else:
                    dq = fail_window.get(ip)
                    if dq and len(dq) >= BRUTE_SUCCESS_THRESHOLD:
                        # purge old entries first
                        while dq and (ts - dq[0]) > BRUTE_WINDOW:
                            dq.popleft()
                        if len(dq) >= BRUTE_SUCCESS_THRESHOLD:
                            window_start_dt = dq[0]
                            soft_trigger = True
                if soft_trigger:
                    emit(findings, "R-AUTH-002", rec, {
                        "brute_start": window_start_dt.isoformat() if window_start_dt else None,
                        "auth_method": "password/publickey",
                        "fails_before_success": len(fail_window.get(ip, [])),
                    })

            # R-AUTH-003 root login from new /24
            if user == "root" and ip:
                subnet = ip_subnet(ip)
                if subnet:
                    if root_subnet_history and subnet not in root_subnet_history:
                        emit(findings, "R-AUTH-003", rec, {"new_subnet": subnet})
                    root_subnet_history.add(subnet)

            # R-AUTH-006 first time login user
            if user and user not in known_users:
                emit(findings, "R-AUTH-006", rec, {"first_login": True})
                known_users.add(user)

            # R-AUTH-007 deleted user reappearance
            if user and user in deleted_users:
                emit(findings, "R-AUTH-007", rec, {"reappearance": True})

            # R-AUTH-008 pubkey without baseline
            if "publickey" in msg and pubkey_baseline is not None:
                if user and user not in pubkey_baseline:
                    emit(findings, "R-AUTH-008", rec, {"unauthorized_pubkey_login": True})

        # R-AUTH-004 new account
        if re.search(r"\b(useradd|adduser|new user|new group)\b", msg):
            m = re.search(r"name=([\w\-\.]+)", msg) or re.search(r"new user:\s*name=([\w\-\.]+)", msg)
            name = m.group(1) if m else user
            emit(findings, "R-AUTH-004", rec, {"new_user": name})

        # account deletion tracker for R-AUTH-007
        if re.search(r"\b(userdel|deluser|remove user)\b", msg):
            m = re.search(r"\b(userdel|deluser).+?\b([A-Za-z0-9_\-\.]+)\s*$", msg)
            if m:
                deleted_users.add(m.group(2))
            elif user:
                deleted_users.add(user)

        # R-AUTH-005 sudo abuse
        if "sudo" in msg and "COMMAND=" in msg:
            actor = user or "unknown"
            if ts:
                dq = sudo_window[actor]
                dq.append(ts)
                while dq and (ts - dq[0]) > SUDO_BURST_WINDOW:
                    dq.popleft()
                if len(dq) >= SUDO_BURST_THRESHOLD and actor not in sudo_emitted:
                    sudo_emitted.add(actor)
                    emit(findings, "R-AUTH-005", rec, {"sudo_count_5min": len(dq), "actor": actor})

    return findings


def main(argv=None) -> int:
    args = parse_args(argv)
    pubkey_baseline = None
    if args.pubkey_baseline:
        p = Path(args.pubkey_baseline)
        if p.exists():
            pubkey_baseline = load_pubkey_baseline(p)
            if args.verbose:
                print(f"[INFO] pubkey baseline users={len(pubkey_baseline)}", file=sys.stderr)
        else:
            print(f"[WARN] pubkey baseline not found: {p}", file=sys.stderr)

    findings = detect(iter_ndjson(args.input), pubkey_baseline)

    out = {"version": "0.1", "total": len(findings), "findings": findings}
    text = json.dumps(out, ensure_ascii=False, indent=2)
    if args.output:
        Path(args.output).write_text(text, encoding="utf-8")
    else:
        print(text)
    if args.verbose:
        c = Counter(f["rule_id"] for f in findings)
        print(f"[INFO] by_rule={dict(c)}", file=sys.stderr)
    return 0


def parse_args(argv=None):
    p = argparse.ArgumentParser(description="Linux auth log auditor")
    p.add_argument("--input", required=True, help="NDJSON (use - for stdin)")
    p.add_argument("--pubkey-baseline", default=None,
                   help="File listing authorized pubkey users (one per line or user=fp)")
    p.add_argument("--output", default=None, help="Output JSON file")
    p.add_argument("-q", "--quiet", action="store_true")
    p.add_argument("-v", "--verbose", action="store_true")
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
