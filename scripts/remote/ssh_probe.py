#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ssh_probe.py -- hvv-defender remote mode primary SSH executor.

Purpose:
    Execute a whitelisted command against a remote host over SSH, with strict
    compliance gates, full session recording, and per-invocation audit logging.

Compliance ("红线 4" 修订版 -- 授权+白名单+审计+录制):
    1. AUTHORIZED-BY 强制必填: caller must pass --authorized-by "<ticket>" or
       equivalent traceable reference. Missing --authorized-by => exit code 2.
    2. WHITELIST: --command must be a cmd_id present in data/remote-command-whitelist.json.
       Unknown cmd_id or Tier-3 command without --allow-mutating => exit code 3.
    3. AUDIT: every invocation appends one JSONL line to ~/.hvv-defender/audit.jsonl
       (success AND failure), containing target, cmd_id, expanded command, tier,
       authorized_by, allow_mutating, exit_code, byte counts, duration, and the
       session_log path.
    4. RECORDING: every invocation writes a session log
       (~/.hvv-defender/sessions/<host>-<ts>.log) via in-process tee, capturing
       both stdout and stderr streamed from ssh.

Authentication (v0.4-M0.1):
    Default:  public-key (BatchMode=yes, no password prompt).
    Optional: password auth via expect(1) wrapper when caller provides
              --password / --password-env / --password-file. Requires expect
              binary present at /usr/bin/expect or in PATH. Password is NEVER
              written to disk beyond the expect script (which we place in a
              mkstemp file with mode 0600 and delete after exec). The password
              value is NEVER logged in audit.jsonl or session_log.

Dependencies:
    Python 3.8+ stdlib only. No paramiko / fabric / pexpect / PyYAML / requests.
    Uses subprocess.Popen against the system ssh(1) binary.
    For --password mode, additionally requires expect(1) (macOS/Linux stock).

Whitelist contract (data/remote-command-whitelist.json):
    See file header. Each entry has cmd_id, tier (1/2/3), template,
    windows_template, required_args, and per-tier risk_note. This executor
    NEVER expands a command whose id is absent from the whitelist and NEVER
    permits shell metachars in --arg values.

Desensitization:
    This executor DOES NOT redact stdout/stderr. Raw forensic capture is preserved.
    Downstream, run scripts/desensitize.py on the session_log before delivery.
"""

import argparse
import hashlib
import json
import os
import pathlib
import re
import shlex
import shutil
import stat as _stat
import subprocess
import sys
import tempfile
import threading
import time

# Shared helpers (pure stdlib). remote/ scripts sit one level below scripts/,
# so bootstrap points at parent to find hvv_common.py. Keeps the script
# runnable standalone as `python3 scripts/remote/ssh_probe.py`.
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
import hvv_common as _hc  # noqa: E402

VERSION = "0.4-M0.1"

# Exit codes -- documented in whitelist header and CLI --help.
EXIT_OK = 0
EXIT_SSH_ERR = 1
EXIT_COMPLIANCE = 2  # missing --authorized-by, shell metachar in arg
EXIT_WHITELIST = 3  # unknown cmd_id, tier3 without --allow-mutating
EXIT_WHITELIST_LOAD = 4  # whitelist file missing / parse error

DEFAULT_WHITELIST = "data/remote-command-whitelist.json"
DEFAULT_AUDIT_LOG = "~/.hvv-defender/audit.jsonl"
DEFAULT_SESSION_DIR = "~/.hvv-defender/sessions"

# Metachar denylist for user-supplied --arg values (post-shlex.quote we still
# refuse these characters to keep operators from smuggling shell syntax into
# a whitelisted template).
FORBIDDEN_METACHARS = ["|", ";", "&", "`", "$(", "$(", ">", "<", "\n", "\r", "\\"]

# Placeholder syntax: <name>
PLACEHOLDER_RE = re.compile(r"<([a-zA-Z_][a-zA-Z0-9_]*)>")

STDOUT_TRUNCATE_BYTES = 100 * 1024  # 100 KB


# Shared helpers reused from hvv_common.
eprint = _hc.eprint
now_iso = _hc.now_iso
compact_ts = _hc.compact_ts
expand_path = _hc.expand_path


def load_whitelist(path: str):
    p = expand_path(path)
    if not os.path.isfile(p):
        eprint(f"[compliance] whitelist not found: {p}")
        sys.exit(EXIT_WHITELIST_LOAD)
    try:
        with open(p, "r", encoding="utf-8") as f:
            wl = json.load(f)
    except Exception as e:
        eprint(f"[compliance] whitelist parse error: {e}")
        sys.exit(EXIT_WHITELIST_LOAD)
    if "commands" not in wl or not isinstance(wl["commands"], list):
        eprint("[compliance] whitelist schema invalid: missing 'commands' array")
        sys.exit(EXIT_WHITELIST_LOAD)
    return wl


def index_whitelist(wl):
    idx = {}
    for c in wl["commands"]:
        cid = c.get("cmd_id")
        if not cid:
            continue
        if cid in idx:
            eprint(f"[compliance] duplicate cmd_id in whitelist: {cid}")
            sys.exit(EXIT_WHITELIST_LOAD)
        idx[cid] = c
    return idx


parse_target = _hc.parse_target


def validate_arg_value(name: str, value: str, patterns: dict):
    """Return (ok, reason). Rejects shell metachars unconditionally."""
    for meta in FORBIDDEN_METACHARS:
        if meta in value:
            return False, f"value for '{name}' contains forbidden metachar {meta!r}"
    pat = patterns.get(f"<{name}>")
    if pat:
        try:
            if not re.match(pat, value):
                return False, f"value for '{name}' does not match pattern {pat!r}"
        except re.error as e:
            return False, f"invalid pattern for '{name}': {e}"
    if len(value) > 512:
        return False, f"value for '{name}' exceeds 512 chars"
    return True, ""


def parse_kv_args(kv_list):
    out = {}
    for kv in kv_list or []:
        if "=" not in kv:
            eprint(f"[compliance] --arg must be key=value, got: {kv!r}")
            sys.exit(EXIT_COMPLIANCE)
        k, v = kv.split("=", 1)
        k = k.strip()
        if not k:
            eprint(f"[compliance] --arg key empty: {kv!r}")
            sys.exit(EXIT_COMPLIANCE)
        out[k] = v
    return out


def expand_template(template: str, args_map: dict, required: list, patterns: dict):
    """Replace <name> tokens with shlex.quote(value). Return (expanded, missing, invalid)."""
    missing = [r for r in required if r not in args_map]
    if missing:
        return None, missing, None
    used_names = set()

    def repl(m):
        name = m.group(1)
        used_names.add(name)
        value = args_map.get(name)
        if value is None:
            return m.group(0)  # will be flagged below
        ok, reason = validate_arg_value(name, value, patterns)
        if not ok:
            raise ValueError(reason)
        return shlex.quote(value)

    try:
        expanded = PLACEHOLDER_RE.sub(repl, template)
    except ValueError as e:
        return None, None, str(e)

    # Any placeholder still present means we lacked a value not in required list.
    remaining = PLACEHOLDER_RE.findall(expanded)
    if remaining:
        return None, remaining, None
    return expanded, None, None


def build_ssh_cmd(args, remote_command: str, password_mode: bool = False):
    """Compose the ssh argv. No shell interpolation.

    When password_mode is True, BatchMode is dropped and PubkeyAuthentication is
    disabled so ssh falls through to the keyboard-interactive/password prompt
    that expect() will answer. StrictHostKeyChecking=accept-new is preserved so
    first-time hosts still get pinned to known_hosts.
    """
    ssh = ["ssh"]
    if password_mode:
        # Allow the password prompt to appear; expect will feed it.
        ssh += [
            "-o", "BatchMode=no",
            "-o", "PubkeyAuthentication=no",
            "-o", "PreferredAuthentications=password,keyboard-interactive",
            "-o", "NumberOfPasswordPrompts=1",
        ]
    else:
        ssh += ["-o", "BatchMode=yes"]
    ssh += [
        "-o", "StrictHostKeyChecking=accept-new",
        "-o", "ConnectTimeout=10",
        "-o", "ServerAliveInterval=30",
        "-o", "ServerAliveCountMax=3",
        "-o", "LogLevel=ERROR",
    ]
    if args.identity:
        ssh += ["-i", expand_path(args.identity)]
    if args.port and args.port != 22:
        ssh += ["-p", str(args.port)]
    if args.proxy_jump:
        ssh += ["-J", args.proxy_jump]
    ssh += [args.target, remote_command]
    return ssh


def resolve_password(args):
    """Return (password:str|None, source:str|None). Priority:

        1. --password <literal>              (discouraged: leaks in ps)
        2. --password-env <VAR>              (reads os.environ[VAR])
        3. --password-file <path>            (first non-empty line, strip \\r\\n)

    Returns (None, None) if none provided.
    """
    if getattr(args, "password", None):
        return args.password, "cli"
    env_var = getattr(args, "password_env", None)
    if env_var:
        val = os.environ.get(env_var)
        if val is None:
            eprint(f"[compliance] --password-env {env_var!r} is not set in environment.")
            return None, "env-missing"
        return val, f"env:{env_var}"
    pw_file = getattr(args, "password_file", None)
    if pw_file:
        try:
            with open(expand_path(pw_file), "r", encoding="utf-8") as f:
                for line in f:
                    line = line.rstrip("\r\n")
                    if line:
                        return line, f"file:{pw_file}"
        except OSError as e:
            eprint(f"[compliance] --password-file read error: {e}")
            return None, "file-error"
    return None, None


def build_expect_wrapper(ssh_argv, password: str):
    """Write a minimal expect(1) script that spawns ssh_argv and feeds password.

    Returns (wrapper_path, expect_bin). Wrapper file is mode 0600 and gets
    unlinked by the caller. Password is passed via a here-doc in TCL and is NOT
    stored anywhere else. Note: the password appears in the wrapper file for
    the duration of the exec, protected by 0600 perms in the user's tmpdir --
    this is the standard workaround when the platform has no sshpass.
    """
    expect_bin = shutil.which("expect") or (
        "/usr/bin/expect" if os.path.exists("/usr/bin/expect") else None
    )
    if not expect_bin:
        return None, None

    # TCL-quote the password: escape backslash, brackets, dollar, quotes.
    def tcl_quote(s: str) -> str:
        out = []
        for ch in s:
            if ch in ("\\", "[", "]", "$", "\"", "{", "}"):
                out.append("\\" + ch)
            else:
                out.append(ch)
        return "".join(out)

    quoted_pw = tcl_quote(password)
    # Argv for spawn: each element as a separate {…} list item so expect
    # doesn't reinterpret shell metachars.
    spawn_args = " ".join("{" + a.replace("}", "\\}") + "}" for a in ssh_argv)

    script = (
        "#!/usr/bin/env expect -f\n"
        "# hvv-defender ssh_probe expect wrapper (auto-generated, will be deleted)\n"
        "set timeout 30\n"
        "log_user 1\n"
        "match_max 100000\n"
        f"spawn -noecho {spawn_args}\n"
        "expect {\n"
        '  -re "(?i)password:" {\n'
        f'    send -- "{quoted_pw}\\r"\n'
        "    exp_continue\n"
        "  }\n"
        '  -re "(?i)passphrase for" {\n'
        f'    send -- "{quoted_pw}\\r"\n'
        "    exp_continue\n"
        "  }\n"
        '  -re "(yes/no|fingerprint)" {\n'
        '    send -- "yes\\r"\n'
        "    exp_continue\n"
        "  }\n"
        '  -re "Permission denied" {\n'
        '    puts stderr "[ssh_probe] permission denied (bad password or auth method)"\n'
        "    exit 5\n"
        "  }\n"
        '  -re "Connection (refused|closed|timed out|reset)" {\n'
        '    puts stderr "[ssh_probe] connection failed"\n'
        "    exit 255\n"
        "  }\n"
        "  eof\n"
        "}\n"
        "catch wait result\n"
        "exit [lindex $result 3]\n"
    )
    fd, wrapper = tempfile.mkstemp(prefix="hvv-expect-", suffix=".exp")
    try:
        os.write(fd, script.encode("utf-8"))
    finally:
        os.close(fd)
    os.chmod(wrapper, 0o600)
    return wrapper, expect_bin


def _reader(stream, sinks, done_evt):
    """Drain a byte stream into a list of sinks (files or lists). Runs in a thread."""
    try:
        while True:
            chunk = stream.read(4096)
            if not chunk:
                break
            for s in sinks:
                try:
                    s.write(chunk)
                except Exception:
                    pass
    finally:
        done_evt.set()


class _BufSink:
    """Byte buffer with a hard cap; tracks overflow bytes."""
    def __init__(self, cap: int):
        self.cap = cap
        self.buf = bytearray()
        self.total = 0

    def write(self, chunk: bytes):
        self.total += len(chunk)
        room = self.cap - len(self.buf)
        if room > 0:
            self.buf.extend(chunk[:room])


def run_ssh_with_recording(ssh_argv, session_log_path: str, capture_only: bool):
    """Run ssh, tee stdout+stderr to session_log, and return (rc, stdout_bytes, stderr_bytes, duration_ms, truncated_stdout, stderr_bytes_bytes)."""
    session_p = pathlib.Path(session_log_path)
    session_p.parent.mkdir(parents=True, exist_ok=True)

    stdout_sink = _BufSink(STDOUT_TRUNCATE_BYTES)
    stderr_sink = _BufSink(STDOUT_TRUNCATE_BYTES)

    t0 = time.time()
    with open(session_log_path, "wb") as sess:
        sess.write(f"# hvv-defender ssh session log\n".encode())
        sess.write(f"# ts_start: {now_iso()}\n".encode())
        sess.write(f"# argv: {json.dumps(ssh_argv)}\n".encode())
        sess.write(b"# --- begin stream ---\n")
        sess.flush()

        proc = subprocess.Popen(
            ssh_argv,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            bufsize=0,
        )

        # stdout: session_log + stdout_sink + (real stdout unless capture_only)
        real_stdout = None if capture_only else sys.stdout.buffer
        stdout_sinks = [sess, stdout_sink]
        if real_stdout is not None:
            stdout_sinks.append(real_stdout)
        # stderr: session_log + stderr_sink + real stderr always
        stderr_sinks = [sess, stderr_sink, sys.stderr.buffer]

        done_out = threading.Event()
        done_err = threading.Event()
        t_out = threading.Thread(target=_reader, args=(proc.stdout, stdout_sinks, done_out), daemon=True)
        t_err = threading.Thread(target=_reader, args=(proc.stderr, stderr_sinks, done_err), daemon=True)
        t_out.start()
        t_err.start()

        rc = proc.wait()
        # give threads a moment to drain
        t_out.join(timeout=2.0)
        t_err.join(timeout=2.0)

        sess.write(b"\n# --- end stream ---\n")
        sess.write(f"# ts_end: {now_iso()}\n".encode())
        sess.write(f"# exit_code: {rc}\n".encode())

    duration_ms = int((time.time() - t0) * 1000)
    return rc, stdout_sink.total, stderr_sink.total, duration_ms, bytes(stdout_sink.buf), bytes(stderr_sink.buf)


append_audit = _hc.append_audit


def build_parser():
    p = argparse.ArgumentParser(
        prog="ssh_probe.py",
        description="hvv-defender remote mode SSH executor (authorized + whitelisted + audited + recorded).",
        epilog=(
            "Exit codes: 0=ok, 1=ssh error, 2=compliance violation "
            "(missing --authorized-by or metachar in arg), "
            "3=whitelist violation (unknown cmd_id or tier3 without --allow-mutating), "
            "4=whitelist load error."
        ),
    )
    p.add_argument("--target", help="user@host or user@host:port")
    p.add_argument("--command", help="whitelisted cmd_id from remote-command-whitelist.json")
    p.add_argument("--proxy-jump", help="user@bastion (SSH -J)")
    p.add_argument("--identity", help="path to SSH private key")
    p.add_argument("--port", type=int, default=22, help="SSH port (default 22)")
    p.add_argument("--os", choices=["linux", "windows", "auto"], default="auto",
                   help="target OS; picks template vs windows_template (default auto)")
    p.add_argument("--authorized-by", help="MANDATORY: traceable authorization reference (ticket, ChangeReq, etc.)")
    p.add_argument("--allow-mutating", action="store_true",
                   help="required to run Tier 3 (mutating/disposal) commands")
    p.add_argument("--arg", action="append", default=[],
                   help="template variable, key=value (repeatable). Values are shlex.quote'd; shell metachars rejected.")
    # v0.4-M0.1 password auth (via expect wrapper). Precedence: --password > --password-env > --password-file.
    # Prefer --password-env or --password-file in production; --password puts the secret in ps output.
    p.add_argument("--password",
                   help="SSH password (uses expect wrapper). WARNING: appears in `ps` output. "
                        "Prefer --password-env or --password-file.")
    p.add_argument("--password-env",
                   help="Read SSH password from this environment variable (e.g. HVV_SSH_PASS).")
    p.add_argument("--password-file",
                   help="Read SSH password from first non-empty line of this file (mode 0600 recommended).")
    p.add_argument("--session-log-dir", default=DEFAULT_SESSION_DIR)
    p.add_argument("--audit-log", default=DEFAULT_AUDIT_LOG)
    p.add_argument("--whitelist", default=DEFAULT_WHITELIST)
    p.add_argument("--dry-run", action="store_true",
                   help="print ssh argv, audit entry, and session_log path; do NOT invoke ssh")
    p.add_argument("--capture-only", action="store_true",
                   help="do NOT print stdout locally; only write to session_log and audit")
    p.add_argument("--verbose", action="store_true")
    p.add_argument("--self-test", action="store_true", help="run internal 3-case self test and exit")
    p.add_argument("--version", action="version", version=f"ssh_probe.py {VERSION}")
    return p


def pick_template(entry: dict, os_hint: str):
    """Return (template, effective_os) or (None, reason)."""
    if os_hint == "linux":
        t = entry.get("template")
        if t:
            return t, "linux"
        return None, f"cmd_id {entry['cmd_id']!r} has no linux template"
    if os_hint == "windows":
        t = entry.get("windows_template")
        if t:
            return t, "windows"
        return None, f"cmd_id {entry['cmd_id']!r} has no windows_template"
    # auto: prefer linux, fall back to windows if only that is defined
    if entry.get("template"):
        return entry["template"], "linux"
    if entry.get("windows_template"):
        return entry["windows_template"], "windows"
    return None, f"cmd_id {entry['cmd_id']!r} has no template at all"


def resolve_command(entry: dict, os_hint: str, args_map: dict, patterns: dict):
    """Return (expanded_command, effective_os, error_str_or_None)."""
    if entry.get("os") == "linux" and os_hint == "windows":
        return None, None, f"cmd_id {entry['cmd_id']!r} is linux-only"
    if entry.get("os") == "windows" and os_hint == "linux":
        return None, None, f"cmd_id {entry['cmd_id']!r} is windows-only"
    tmpl, eff = pick_template(entry, os_hint)
    if tmpl is None:
        return None, None, eff  # eff carries reason
    expanded, missing, invalid = expand_template(tmpl, args_map, entry.get("required_args", []) or [], patterns)
    if missing:
        return None, None, f"missing required --arg(s): {missing}"
    if invalid:
        return None, None, invalid
    return expanded, eff, None


def do_invocation(args, wl, wl_idx, patterns) -> int:
    # Compliance gate 1: --authorized-by mandatory
    if not args.authorized_by or not args.authorized_by.strip():
        eprint("[compliance] --authorized-by is MANDATORY. Provide a traceable ticket/ChangeReq reference.")
        eprint("[compliance] Refusing execution. exit=2.")
        return EXIT_COMPLIANCE

    # Compliance gate 2: --target present + parseable
    if not args.target:
        eprint("[compliance] --target is required (user@host or user@host:port).")
        return EXIT_COMPLIANCE
    user, host, port_in_target = parse_target(args.target)
    if not user or not host:
        eprint(f"[compliance] --target format invalid: {args.target!r}. Expect user@host or user@host:port.")
        return EXIT_COMPLIANCE
    if port_in_target is not None:
        args.port = port_in_target
        args.target = f"{user}@{host}"

    # Compliance gate 3: --command whitelisted
    if not args.command:
        eprint("[compliance] --command is required.")
        return EXIT_COMPLIANCE
    entry = wl_idx.get(args.command)
    if not entry:
        eprint(f"[whitelist] cmd_id {args.command!r} not in whitelist. exit=3.")
        return EXIT_WHITELIST

    tier = int(entry.get("tier", 0))
    if tier == 3 and not args.allow_mutating:
        eprint(f"[whitelist] cmd_id {args.command!r} is Tier 3 (mutating). "
               "Requires --allow-mutating + written customer authorization + oral second confirmation. exit=3.")
        return EXIT_WHITELIST

    # Argument expansion (validates metachars + patterns).
    kv_map = parse_kv_args(args.arg)
    os_hint = args.os if args.os != "auto" else "auto"
    expanded, eff_os, err = resolve_command(entry, os_hint, kv_map, patterns)
    if err:
        # metachar / missing arg / os mismatch -> compliance
        eprint(f"[compliance] {err}")
        return EXIT_COMPLIANCE

    # Session log path
    ts = compact_ts()
    session_dir = expand_path(args.session_log_dir)
    session_log = os.path.join(session_dir, f"{host}-{ts}.log")

    # Resolve optional SSH password (v0.4-M0.1).
    password, pw_source = resolve_password(args)
    # If the caller asked for password auth but resolution failed, refuse rather
    # than silently falling back to pubkey (which is what pw_source == None means).
    if pw_source in ("env-missing", "file-error"):
        eprint("[compliance] password source specified but could not be read. Refusing execution. exit=2.")
        return EXIT_COMPLIANCE
    password_mode = password is not None
    expect_wrapper = None
    expect_bin = None
    if password_mode:
        expect_wrapper, expect_bin = build_expect_wrapper([], password)  # provisional; rebuilt below
        if not expect_bin:
            eprint("[compliance] password auth requested but expect(1) not found in PATH or /usr/bin/expect.")
            eprint("[compliance] Install expect (macOS: `brew install expect`; Debian: `apt install expect`).")
            return EXIT_COMPLIANCE
        # Remove the provisional wrapper; we'll rebuild once we have the real ssh_argv.
        try:
            os.unlink(expect_wrapper)
        except OSError:
            pass
        expect_wrapper = None

    # Build ssh argv (password_mode drops BatchMode and disables pubkey).
    ssh_argv = build_ssh_cmd(args, expanded, password_mode=password_mode)

    # If password_mode, wrap under expect. exec_argv is what we actually run.
    if password_mode:
        expect_wrapper, expect_bin = build_expect_wrapper(ssh_argv, password)
        if not expect_wrapper:
            eprint("[compliance] failed to build expect wrapper (expect binary missing).")
            return EXIT_COMPLIANCE
        exec_argv = [expect_bin, expect_wrapper]
    else:
        exec_argv = ssh_argv

    # Audit record base
    record = {
        "ts": now_iso(),
        "action": "ssh_probe",
        "target": host,
        "user": user,
        "port": args.port,
        "proxy_jump": args.proxy_jump,
        "cmd_id": args.command,
        "cmd_tier": tier,
        "cmd_expanded": expanded,
        "cmd_expanded_sha256": hashlib.sha256(expanded.encode("utf-8", "replace")).hexdigest(),
        "effective_os": eff_os,
        "authorized_by": args.authorized_by,
        "allow_mutating": bool(args.allow_mutating),
        "auth_method": "password" if password_mode else "pubkey",
        "auth_source": pw_source if password_mode else None,  # NEVER the raw password
        "dry_run": bool(args.dry_run),
        "session_log": session_log,
        "audit_log_version": VERSION,
        "desensitized": False,
    }

    if args.verbose or args.dry_run:
        eprint("[ssh_argv]")
        for a in ssh_argv:
            eprint(f"  {a}")
        if password_mode:
            eprint(f"[auth] password_mode=True source={pw_source} expect={expect_bin}")
        eprint(f"[session_log] {session_log}")
        # Redact any auth_source that might contain a raw literal path so audit_entry preview is safe
        eprint(f"[audit_entry] {json.dumps(record, ensure_ascii=False)}")

    if args.dry_run:
        record["exit_code"] = 0
        record["stdout_bytes"] = 0
        record["stderr_bytes"] = 0
        record["duration_ms"] = 0
        # Clean up expect wrapper if any (dry-run doesn't need it).
        if expect_wrapper and os.path.exists(expect_wrapper):
            try:
                os.unlink(expect_wrapper)
            except OSError:
                pass
        append_audit(args.audit_log, record)
        return EXIT_OK

    # Real run.
    try:
        rc, so_bytes, se_bytes, dur_ms, so_buf, se_buf = run_ssh_with_recording(
            exec_argv, session_log, args.capture_only
        )
    except FileNotFoundError:
        eprint("[ssh] ssh/expect binary not found in PATH.")
        record["exit_code"] = 127
        record["stdout_bytes"] = 0
        record["stderr_bytes"] = 0
        record["duration_ms"] = 0
        record["error"] = "ssh/expect binary missing"
        append_audit(args.audit_log, record)
        _safe_unlink(expect_wrapper)
        return EXIT_SSH_ERR
    except Exception as e:
        eprint(f"[ssh] execution error: {e}")
        record["exit_code"] = -1
        record["stdout_bytes"] = 0
        record["stderr_bytes"] = 0
        record["duration_ms"] = 0
        record["error"] = str(e)
        append_audit(args.audit_log, record)
        _safe_unlink(expect_wrapper)
        return EXIT_SSH_ERR

    # Always clean up expect wrapper after real run, success or failure.
    _safe_unlink(expect_wrapper)

    record["exit_code"] = rc
    record["stdout_bytes"] = so_bytes
    record["stderr_bytes"] = se_bytes
    record["duration_ms"] = dur_ms
    append_audit(args.audit_log, record)

    if rc != 0:
        return EXIT_SSH_ERR
    return EXIT_OK


def _safe_unlink(path):
    """Best-effort unlink; used to clean expect wrapper containing password."""
    if not path:
        return
    try:
        if os.path.exists(path):
            os.unlink(path)
    except OSError:
        pass


# ---------- self test ----------

def _self_test():
    """Three-case internal test. Uses the shipped whitelist if present, else a minimal in-memory stand-in."""
    passed = 0
    total = 3
    failures = []

    wl_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "data", "remote-command-whitelist.json")
    wl_path = os.path.abspath(wl_path)
    if not os.path.isfile(wl_path):
        # fallback: locate near cwd
        cand = expand_path(DEFAULT_WHITELIST)
        if os.path.isfile(cand):
            wl_path = cand

    if not os.path.isfile(wl_path):
        # in-memory stand-in
        _wl = {
            "commands": [
                {"cmd_id": "list-processes", "os": "linux", "tier": 1, "template": "ps -eo pid,user | head -5", "windows_template": None, "required_args": []},
                {"cmd_id": "kill-pid", "os": "linux", "tier": 3, "template": "kill <pid>", "windows_template": None, "required_args": ["pid"], "risk_note": "Tier 3 disposal placeholder for self test."},
            ],
            "placeholder_patterns": {"<pid>": r"^[0-9]{1,7}$"},
        }
        wl = _wl
    else:
        wl = load_whitelist(wl_path)

    patterns = wl.get("placeholder_patterns", {})
    idx = index_whitelist(wl)

    tmp_audit = os.path.join("/tmp", f"ssh_probe_selftest_audit_{os.getpid()}.jsonl")
    tmp_sess_dir = os.path.join("/tmp", f"ssh_probe_selftest_sessions_{os.getpid()}")

    # test1: Tier 1 --dry-run
    class NS:
        pass
    a = NS()
    a.target = "root@testhost"
    a.command = "list-processes"
    a.proxy_jump = None
    a.identity = None
    a.port = 22
    a.os = "linux"
    a.authorized_by = "selftest-ticket-#1"
    a.allow_mutating = False
    a.arg = []
    a.session_log_dir = tmp_sess_dir
    a.audit_log = tmp_audit
    a.whitelist = wl_path
    a.dry_run = True
    a.capture_only = False
    a.verbose = False

    rc1 = do_invocation(a, wl, idx, patterns)
    if rc1 == EXIT_OK and os.path.isfile(tmp_audit):
        with open(tmp_audit, "r") as f:
            last = f.readlines()[-1]
            row = json.loads(last)
            if row.get("dry_run") is True and row.get("cmd_id") == "list-processes":
                passed += 1
            else:
                failures.append(f"test1: audit row shape unexpected: {row}")
    else:
        failures.append(f"test1: expected EXIT_OK+audit file, got rc={rc1} audit_exists={os.path.isfile(tmp_audit)}")

    # test2: Tier 3 without --allow-mutating -> exit 3
    a2 = NS()
    a2.target = "root@testhost"
    a2.command = "kill-pid"
    a2.proxy_jump = None
    a2.identity = None
    a2.port = 22
    a2.os = "linux"
    a2.authorized_by = "selftest-ticket-#2"
    a2.allow_mutating = False
    a2.arg = ["pid=1234"]
    a2.session_log_dir = tmp_sess_dir
    a2.audit_log = tmp_audit
    a2.whitelist = wl_path
    a2.dry_run = True
    a2.capture_only = False
    a2.verbose = False
    rc2 = do_invocation(a2, wl, idx, patterns)
    if rc2 == EXIT_WHITELIST:
        passed += 1
    else:
        failures.append(f"test2: expected EXIT_WHITELIST(3), got {rc2}")

    # test3: missing --authorized-by -> exit 2
    a3 = NS()
    a3.target = "root@testhost"
    a3.command = "list-processes"
    a3.proxy_jump = None
    a3.identity = None
    a3.port = 22
    a3.os = "linux"
    a3.authorized_by = None
    a3.allow_mutating = False
    a3.arg = []
    a3.session_log_dir = tmp_sess_dir
    a3.audit_log = tmp_audit
    a3.whitelist = wl_path
    a3.dry_run = True
    a3.capture_only = False
    a3.verbose = False
    rc3 = do_invocation(a3, wl, idx, patterns)
    if rc3 == EXIT_COMPLIANCE:
        passed += 1
    else:
        failures.append(f"test3: expected EXIT_COMPLIANCE(2), got {rc3}")

    # cleanup
    try:
        if os.path.isfile(tmp_audit):
            os.remove(tmp_audit)
    except Exception:
        pass

    print(f"[self-test] {passed}/{total} PASS")
    for f in failures:
        print(f"[self-test] FAIL: {f}")
    return 0 if passed == total else 1


def main():
    parser = build_parser()
    args = parser.parse_args()

    if args.self_test:
        sys.exit(_self_test())

    # Load whitelist first (needed by all real invocations).
    wl = load_whitelist(args.whitelist)
    patterns = wl.get("placeholder_patterns", {})
    idx = index_whitelist(wl)

    sys.exit(do_invocation(args, wl, idx, patterns))


if __name__ == "__main__":
    main()
