#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
remote_collect.py -- hvv-defender remote mode collect orchestration.

Chains four steps into one command, so remote IR can be driven with a single
authorization + audit trail:
    1. upload the local collect script (linux_quick_check.sh or
       windows_quick_check.ps1) to the target's --remote-workdir via scp.
    2. execute the collect script by invoking ssh_probe.py with the
       whitelisted cmd_id 'run-linux-collect' or 'run-windows-collect'.
    3. scp the produced tarball/zip back to --local-output.
    4. invoke ssh_probe.py with cmd_id 'cleanup-collect-artifacts' to remove
       the uploaded script + produced archive from the remote host.

Compliance:
    * --authorized-by MANDATORY (inherited requirement -- passed through to
      ssh_probe for each step).
    * All 4 sub-steps share one session_id and each writes one audit line.
    * --dry-run walks the whole plan without touching the remote host.

Dependencies:
    Python 3.8+ stdlib only. Delegates all ssh/scp invocations to subprocess.
"""

import argparse
import datetime
import json
import os
import pathlib
import subprocess
import sys
import time
import uuid

VERSION = "0.4-M0"

EXIT_OK = 0
EXIT_STEP_ERR = 1
EXIT_COMPLIANCE = 2
EXIT_PREREQ = 4

DEFAULT_AUDIT_LOG = "~/.hvv-defender/audit.jsonl"
DEFAULT_LINUX_WORKDIR = "/tmp"
DEFAULT_WINDOWS_WORKDIR = "C:\\Temp"


def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)


def now_iso() -> str:
    return datetime.datetime.now().astimezone().isoformat(timespec="seconds")


def expand_path(p: str) -> str:
    return os.path.abspath(os.path.expanduser(p))


def compact_ts() -> str:
    return datetime.datetime.now().strftime("%Y%m%dT%H%M%S")


def parse_target(target: str):
    if "@" not in target:
        return None, None, None
    user, rest = target.split("@", 1)
    if ":" in rest:
        host, port_s = rest.rsplit(":", 1)
        try:
            port = int(port_s)
        except ValueError:
            return None, None, None
        return user, host, port
    return user, rest, None


def append_audit(audit_path: str, record: dict):
    p = pathlib.Path(expand_path(audit_path))
    p.parent.mkdir(parents=True, exist_ok=True)
    with open(p, "a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False) + "\n")


def build_scp_cmd(args, direction: str, src: str, dst: str):
    """direction: 'upload' or 'download'."""
    scp = [
        "scp",
        "-o", "BatchMode=yes",
        "-o", "StrictHostKeyChecking=accept-new",
        "-o", "ConnectTimeout=10",
        "-o", "LogLevel=ERROR",
    ]
    if args.identity:
        scp += ["-i", expand_path(args.identity)]
    if args.port and args.port != 22:
        scp += ["-P", str(args.port)]
    if args.proxy_jump:
        scp += ["-J", args.proxy_jump]
    scp += [src, dst]
    return scp


def _ssh_probe_path():
    here = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(here, "ssh_probe.py")


def run_ssh_probe_step(args, cmd_id: str, session_id: str, step_label: str):
    """Invoke ssh_probe.py as a subprocess for a whitelisted command step."""
    probe = _ssh_probe_path()
    if not os.path.isfile(probe):
        eprint(f"[prereq] ssh_probe.py not found next to remote_collect.py at {probe}")
        return 127, "", ""
    argv = [
        sys.executable, probe,
        "--target", args.target,
        "--command", cmd_id,
        "--authorized-by", f"{args.authorized_by} [session={session_id}, step={step_label}]",
        "--os", args.os,
        "--audit-log", args.audit_log,
    ]
    if args.identity:
        argv += ["--identity", args.identity]
    if args.port and args.port != 22:
        argv += ["--port", str(args.port)]
    if args.proxy_jump:
        argv += ["--proxy-jump", args.proxy_jump]
    if args.whitelist:
        argv += ["--whitelist", args.whitelist]
    if args.dry_run:
        argv += ["--dry-run"]
    if args.verbose or args.dry_run:
        eprint("[step] " + step_label + " ssh_probe argv:")
        for a in argv:
            eprint(f"  {a}")
    if args.dry_run:
        return 0, "", ""
    proc = subprocess.run(argv, capture_output=True)
    return proc.returncode, proc.stdout.decode("utf-8", "replace"), proc.stderr.decode("utf-8", "replace")


def run_scp_step(args, session_id: str, step_label: str, direction: str, src: str, dst: str):
    scp_cmd = build_scp_cmd(args, direction, src, dst)
    audit_rec = {
        "ts": now_iso(),
        "action": "remote_collect_scp",
        "session_id": session_id,
        "step": step_label,
        "direction": direction,
        "src": src,
        "dst": dst,
        "target": args.target,
        "authorized_by": args.authorized_by,
        "dry_run": bool(args.dry_run),
        "audit_log_version": VERSION,
    }
    if args.verbose or args.dry_run:
        eprint(f"[step] {step_label} scp argv:")
        for a in scp_cmd:
            eprint(f"  {a}")
    if args.dry_run:
        audit_rec["exit_code"] = 0
        append_audit(args.audit_log, audit_rec)
        return 0, "", ""
    t0 = time.time()
    try:
        proc = subprocess.run(scp_cmd, capture_output=True, timeout=600)
        rc = proc.returncode
        so = proc.stdout.decode("utf-8", "replace")
        se = proc.stderr.decode("utf-8", "replace")
    except FileNotFoundError:
        rc, so, se = 127, "", "scp binary missing"
    except subprocess.TimeoutExpired:
        rc, so, se = 124, "", "scp timeout after 600s"
    audit_rec["exit_code"] = rc
    audit_rec["duration_ms"] = int((time.time() - t0) * 1000)
    if se:
        audit_rec["stderr_tail"] = se[-2048:]
    append_audit(args.audit_log, audit_rec)
    if se:
        sys.stderr.write(se)
    return rc, so, se


def build_parser():
    p = argparse.ArgumentParser(
        prog="remote_collect.py",
        description="Orchestrate remote IR collect: upload -> execute -> download -> cleanup.",
        epilog="All 4 sub-steps share one session_id. Each writes one audit line.",
    )
    p.add_argument("--target", required=True, help="user@host or user@host:port")
    p.add_argument("--os", choices=["linux", "windows"], required=True)
    p.add_argument("--authorized-by", required=True, help="MANDATORY authorization reference")
    p.add_argument("--proxy-jump", default=None)
    p.add_argument("--identity", default=None)
    p.add_argument("--port", type=int, default=22)
    p.add_argument("--remote-workdir", default=None,
                   help="linux default /tmp; windows default C:\\Temp")
    p.add_argument("--local-output", default=None,
                   help="local path for the returned archive (default ./hvv-collect-<host>-<ts>.tar.gz)")
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("--verbose", action="store_true")
    p.add_argument("--audit-log", default=DEFAULT_AUDIT_LOG)
    p.add_argument("--whitelist", default=None,
                   help="pass through to ssh_probe.py --whitelist")
    p.add_argument("--collect-script", default=None,
                   help="path to local collect script (overrides autodetect)")
    p.add_argument("--remote-archive-glob", default=None,
                   help="override the remote path glob used at scp-back step")
    p.add_argument("--version", action="version", version=f"remote_collect.py {VERSION}")
    return p


def autodetect_collect_script(os_name: str):
    """Return absolute path to the local collect script, walking up scripts/ tree."""
    here = os.path.dirname(os.path.abspath(__file__))
    # scripts/remote/ -> scripts/
    parent = os.path.dirname(here)
    if os_name == "linux":
        cand = os.path.join(parent, "linux_quick_check.sh")
    else:
        cand = os.path.join(parent, "windows_quick_check.ps1")
    return cand if os.path.isfile(cand) else None


def default_remote_workdir(os_name: str) -> str:
    return DEFAULT_LINUX_WORKDIR if os_name == "linux" else DEFAULT_WINDOWS_WORKDIR


def default_local_output(host: str, ts: str, os_name: str) -> str:
    ext = "tar.gz" if os_name == "linux" else "zip"
    return f"./hvv-collect-{host}-{ts}.{ext}"


def compute_remote_paths(os_name: str, workdir: str, script_basename: str):
    """Return (remote_script_path, remote_archive_glob)."""
    if os_name == "linux":
        return f"{workdir}/{script_basename}", f"{workdir}/hvv-collect-*.tar.gz"
    else:
        # windows: use backslashes
        sep = "\\" if workdir.endswith("\\") is False else ""
        rp = workdir.rstrip("\\") + "\\" + script_basename
        arch = workdir.rstrip("\\") + "\\hvv-collect-*.zip"
        return rp, arch


def main():
    parser = build_parser()
    args = parser.parse_args()

    if not args.authorized_by or not args.authorized_by.strip():
        eprint("[compliance] --authorized-by is MANDATORY.")
        sys.exit(EXIT_COMPLIANCE)

    user, host, port_in_target = parse_target(args.target)
    if not user or not host:
        eprint(f"[compliance] --target format invalid: {args.target!r}")
        sys.exit(EXIT_COMPLIANCE)
    if port_in_target is not None:
        args.port = port_in_target
        args.target = f"{user}@{host}"

    if not args.remote_workdir:
        args.remote_workdir = default_remote_workdir(args.os)

    # Locate collect script.
    script_path = args.collect_script or autodetect_collect_script(args.os)
    if not script_path or not os.path.isfile(script_path):
        eprint(f"[prereq] collect script not found for os={args.os}. Looked for scripts/{'linux_quick_check.sh' if args.os=='linux' else 'windows_quick_check.ps1'}. Pass --collect-script to override.")
        sys.exit(EXIT_PREREQ)

    script_basename = os.path.basename(script_path)
    ts = compact_ts()
    session_id = f"remote-collect-{host}-{ts}-{uuid.uuid4().hex[:6]}"

    if not args.local_output:
        args.local_output = default_local_output(host, ts, args.os)

    remote_script_path, remote_archive_glob = compute_remote_paths(args.os, args.remote_workdir, script_basename)
    if args.remote_archive_glob:
        remote_archive_glob = args.remote_archive_glob

    # Session-start audit sentinel
    append_audit(args.audit_log, {
        "ts": now_iso(),
        "action": "remote_collect_session_start",
        "session_id": session_id,
        "target": host,
        "os": args.os,
        "remote_workdir": args.remote_workdir,
        "local_output": args.local_output,
        "authorized_by": args.authorized_by,
        "dry_run": bool(args.dry_run),
        "audit_log_version": VERSION,
    })

    if args.verbose or args.dry_run:
        eprint(f"[plan] session_id={session_id}")
        eprint(f"[plan] script       -> {script_path}")
        eprint(f"[plan] remote_path  -> {remote_script_path}")
        eprint(f"[plan] archive_glob -> {remote_archive_glob}")
        eprint(f"[plan] local_output -> {args.local_output}")

    steps_ok = True

    # Step 1: upload.
    upload_dst = f"{args.target}:{remote_script_path}"
    rc, _, _ = run_scp_step(args, session_id, "1-upload", "upload", script_path, upload_dst)
    if rc != 0:
        eprint(f"[step 1-upload] failed rc={rc}")
        steps_ok = False

    # Step 2: execute via ssh_probe with whitelisted collect cmd_id.
    if steps_ok:
        cmd_id = "run-linux-collect" if args.os == "linux" else "run-windows-collect"
        rc, _, _ = run_ssh_probe_step(args, cmd_id, session_id, "2-execute")
        if rc != 0:
            eprint(f"[step 2-execute] failed rc={rc}")
            steps_ok = False

    # Step 3: download.
    if steps_ok:
        download_src = f"{args.target}:{remote_archive_glob}"
        rc, _, _ = run_scp_step(args, session_id, "3-download", "download", download_src, args.local_output)
        if rc != 0:
            eprint(f"[step 3-download] failed rc={rc}")
            steps_ok = False

    # Step 4: cleanup. Attempt even on partial failure (best effort), but record the outcome.
    rc, _, _ = run_ssh_probe_step(args, "cleanup-collect-artifacts", session_id, "4-cleanup")
    if rc != 0:
        eprint(f"[step 4-cleanup] cleanup exit rc={rc} (continuing)")

    # Session-end audit sentinel
    append_audit(args.audit_log, {
        "ts": now_iso(),
        "action": "remote_collect_session_end",
        "session_id": session_id,
        "target": host,
        "overall_ok": bool(steps_ok),
        "dry_run": bool(args.dry_run),
        "local_output": args.local_output,
        "audit_log_version": VERSION,
    })

    if not steps_ok:
        sys.exit(EXIT_STEP_ERR)
    sys.exit(EXIT_OK)


if __name__ == "__main__":
    main()
