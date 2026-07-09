#!/usr/bin/env bash
# session_recorder.sh -- hvv-defender remote mode auxiliary session recorder.
#
# Purpose: ssh_probe.py already records single-command sessions via Python
# tee-fork. This script is the AUXILIARY path when an operator needs to run a
# free-form interactive SSH session and record every character transmitted
# for later desensitization + audit.
#
# Compliance:
#   * --authorized-by MANDATORY (matches ssh_probe.py contract).
#   * Every invocation appends one line to ~/.hvv-defender/audit.jsonl.
#   * Recording relies on script(1); syntax differs between macOS BSD and
#     GNU/Linux, so the invocation branches on `uname -s`.
#   * The produced log is PLAINTEXT. Run scripts/desensitize.py on it before
#     delivering to the customer.
#
# Exit codes: 0 ok / 2 compliance / 3 script(1) missing / other = passthrough.

set -o pipefail
VERSION="0.4-M0"
AUDIT_LOG="${HVV_AUDIT_LOG:-$HOME/.hvv-defender/audit.jsonl}"
SESSION_DIR="${HVV_SESSION_DIR:-$HOME/.hvv-defender/sessions}"

print_help() {
    cat <<'EOF'
session_recorder.sh -- interactive SSH session recorder

Usage:
  session_recorder.sh --target user@host --authorized-by "ticket-#123" \
      [--proxy-jump user@bastion] [--identity ~/.ssh/id_ed25519] [--port 22] \
      [--help]

Options:
  --target         user@host or user@host:port (required)
  --authorized-by  MANDATORY traceable authorization reference
  --proxy-jump     SSH -J bastion spec
  --identity       SSH private key path
  --port           SSH port (default 22)
  --help           print this help

Notes:
  * Recording uses script(1). BSD (macOS) and GNU syntax differ; the script
    branches on uname -s.
  * The produced log is PLAINTEXT. Run scripts/desensitize.py on it before
    delivering to the customer.
  * Audit log line format matches ssh_probe.py so downstream tooling can
    consume both uniformly.
EOF
}

TARGET=""
AUTHORIZED_BY=""
PROXY_JUMP=""
IDENTITY=""
PORT="22"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --target) TARGET="$2"; shift 2 ;;
        --authorized-by) AUTHORIZED_BY="$2"; shift 2 ;;
        --proxy-jump) PROXY_JUMP="$2"; shift 2 ;;
        --identity) IDENTITY="$2"; shift 2 ;;
        --port) PORT="$2"; shift 2 ;;
        --help|-h) print_help; exit 0 ;;
        --version) echo "session_recorder.sh $VERSION"; exit 0 ;;
        *) echo "[compliance] unknown flag: $1" >&2; exit 2 ;;
    esac
done

if [[ -z "$AUTHORIZED_BY" ]]; then
    echo "[compliance] --authorized-by is MANDATORY. exit=2" >&2
    exit 2
fi
if [[ -z "$TARGET" ]]; then
    echo "[compliance] --target is required. exit=2" >&2
    exit 2
fi
if ! command -v script >/dev/null 2>&1; then
    echo "[prereq] script(1) not found. Install util-linux (Linux) or use system default (macOS). exit=3" >&2
    exit 3
fi

mkdir -p "$SESSION_DIR"
mkdir -p "$(dirname "$AUDIT_LOG")"

HOST_PART="${TARGET#*@}"
HOST_PART="${HOST_PART%%:*}"
TS_COMPACT="$(date +%Y%m%dT%H%M%S)"
SESSION_LOG="$SESSION_DIR/${HOST_PART}-${TS_COMPACT}-interactive.log"

# Build ssh argv (same option baseline as ssh_probe.py).
SSH_ARGV=(ssh -o BatchMode=no -o StrictHostKeyChecking=accept-new -o ConnectTimeout=10 -o ServerAliveInterval=30 -o LogLevel=ERROR)
if [[ -n "$IDENTITY" ]]; then SSH_ARGV+=(-i "$IDENTITY"); fi
if [[ -n "$PORT" && "$PORT" != "22" ]]; then SSH_ARGV+=(-p "$PORT"); fi
if [[ -n "$PROXY_JUMP" ]]; then SSH_ARGV+=(-J "$PROXY_JUMP"); fi
SSH_ARGV+=("$TARGET")

# Emit disclaimer before session start.
cat >&2 <<EOF
[hvv-defender] Interactive SSH session recording engaged.
[hvv-defender] Target        : $TARGET
[hvv-defender] Proxy Jump    : ${PROXY_JUMP:-<none>}
[hvv-defender] Authorized By : $AUTHORIZED_BY
[hvv-defender] Session Log   : $SESSION_LOG
[hvv-defender] DISCLAIMER: The recording captures plaintext commands and
[hvv-defender]             responses (including any secrets typed at prompts).
[hvv-defender]             Before delivering to the customer, run:
[hvv-defender]             python3.11 scripts/desensitize.py --input "$SESSION_LOG"
EOF

TS_START="$(date -Iseconds 2>/dev/null || date +%Y-%m-%dT%H:%M:%S%z)"
UNAME_S="$(uname -s)"

if [[ "$UNAME_S" == "Darwin" || "$UNAME_S" == "FreeBSD" ]]; then
    # BSD script(1): script [-a] [-q] file [command...]
    script -q "$SESSION_LOG" "${SSH_ARGV[@]}"
    RC=$?
else
    # GNU util-linux script(1): script [-q] [-c cmd] file
    QUOTED_CMD=""
    for arg in "${SSH_ARGV[@]}"; do
        QUOTED_CMD+="$(printf '%q ' "$arg")"
    done
    script -q -c "$QUOTED_CMD" "$SESSION_LOG"
    RC=$?
fi

TS_END="$(date -Iseconds 2>/dev/null || date +%Y-%m-%dT%H:%M:%S%z)"

# Audit entry (JSONL). Escape only the minimum -- values here are internally trusted.
json_escape() {
    printf '%s' "$1" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g' -e ':a;N;$!ba;s/\n/\\n/g'
}
AUDIT_LINE=$(cat <<EOF
{"ts":"$(json_escape "$TS_END")","action":"session_recorder","target":"$(json_escape "$HOST_PART")","proxy_jump":"$(json_escape "$PROXY_JUMP")","authorized_by":"$(json_escape "$AUTHORIZED_BY")","session_log":"$(json_escape "$SESSION_LOG")","ts_start":"$(json_escape "$TS_START")","ts_end":"$(json_escape "$TS_END")","exit_code":$RC,"desensitized":false,"audit_log_version":"$VERSION","interactive":true}
EOF
)
echo "$AUDIT_LINE" >> "$AUDIT_LOG"

echo "[hvv-defender] Session ended. exit=$RC" >&2
echo "[hvv-defender] Audit appended to: $AUDIT_LOG" >&2
echo "[hvv-defender] REMINDER: Run desensitize.py on $SESSION_LOG before delivery." >&2

exit "$RC"
