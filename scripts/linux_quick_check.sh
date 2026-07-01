#!/usr/bin/env bash
#
# linux_quick_check.sh — On-host forensic collector for HVV blue team.
#
# Purpose:    Collect a snapshot of system state to a tar.gz that the customer
#             ships back to the analyst. READ-ONLY: no files are modified,
#             nothing is deleted, no external network calls are made.
# Inputs:     none (interactive confirm). Optional flags:
#                 --with-logs    additionally tar /var/log
#                 -y / --yes     skip the 5-second confirm
# Outputs:    /tmp/hvv-collect-<host>-<ts>.tar.gz
# Red lines:  no remote calls, no modifications, no deletions, no service
#             restarts. Per-command failures are tolerated and recorded.
#
# Run as root or via sudo for best coverage.

set -u
LANG=C
LC_ALL=C
umask 077

WITH_LOGS=0
YES=0
for arg in "$@"; do
  case "$arg" in
    --with-logs) WITH_LOGS=1 ;;
    -y|--yes)    YES=1 ;;
    -h|--help)
      sed -n '1,18p' "$0"
      exit 0
      ;;
    *) echo "unknown flag: $arg" >&2; exit 1 ;;
  esac
done

HOST="$(hostname 2>/dev/null || echo unknown-host)"
TS="$(date -u +%Y%m%dT%H%M%SZ)"
OUTDIR="/tmp/hvv-collect-${HOST}-${TS}"
TARGZ="${OUTDIR}.tar.gz"

cat <<'BANNER'
====================================================================
 hvv-defender · linux_quick_check.sh — read-only forensic collector
 - no modifications, no deletions, no network calls
 - root / sudo recommended; some items skipped otherwise
 - output: /tmp/hvv-collect-<host>-<ts>.tar.gz
====================================================================
BANNER

if [ "$YES" -eq 0 ]; then
  printf "Starting in 5s; press Ctrl-C to abort, or Enter to start now... "
  if read -r -t 5 _ 2>/dev/null; then
    :
  fi
fi

mkdir -p "$OUTDIR" || { echo "cannot create $OUTDIR" >&2; exit 1; }
echo "[*] collecting to $OUTDIR"

run_to() {
  # run_to <outfile> -- <cmd> [args...]
  local out="$1"; shift
  if [ "${1-}" = "--" ]; then shift; fi
  {
    echo "### $(date -u +%FT%TZ) :: $*"
    "$@" 2>&1
    echo "### exit=$?"
  } >> "$OUTDIR/$out"
}

note() {
  echo "$*" >> "$OUTDIR/00-collector.log"
}

note "collector start ts=$TS host=$HOST user=$(id -un 2>/dev/null)"

# 01 base
{
  echo "## hostname"; hostname 2>&1
  echo "## uname -a"; uname -a 2>&1
  echo "## uptime";   uptime 2>&1
  echo "## w";        w 2>&1
  echo "## who";      who 2>&1
  echo "## id";       id 2>&1
  echo "## date";     date -u 2>&1
  echo "## /etc/os-release"; [ -f /etc/os-release ] && cat /etc/os-release 2>&1
} > "$OUTDIR/01-base.txt" 2>/dev/null

# 02 accounts
{
  echo "## /etc/passwd"; cat /etc/passwd 2>&1
  echo "## /etc/group";  cat /etc/group  2>&1
  echo "## getent group"; getent group 2>&1
  if [ "$(id -u)" -eq 0 ]; then
    echo "## /etc/shadow"; cat /etc/shadow 2>&1
  else
    echo "## /etc/shadow [skipped: not root]"
  fi
  echo "## sudo -l (current user)"; sudo -ln 2>&1 || true
  echo "## /etc/sudoers"; [ -r /etc/sudoers ] && cat /etc/sudoers 2>&1 || echo "[unreadable]"
  echo "## /etc/sudoers.d/*"
  if [ -d /etc/sudoers.d ]; then
    for f in /etc/sudoers.d/*; do
      [ -e "$f" ] || continue
      echo "==$f=="
      cat "$f" 2>&1
    done
  fi
  echo "## uid==0 entries"; awk -F: '$3==0 {print}' /etc/passwd 2>&1
} > "$OUTDIR/02-accounts.txt" 2>/dev/null

# 03 login history
{
  echo "## last -F"; last -F 2>&1 | head -200
  echo "## lastb -F"; lastb -F 2>&1 | head -200
  echo "## faillock"; faillock 2>&1 || echo "[faillock unavailable]"
  echo "## lastlog"; lastlog 2>&1 | head -200
} > "$OUTDIR/03-login-history.txt" 2>/dev/null

# 04 processes
{
  echo "## ps -auxwwf"; ps -auxwwf 2>&1
  echo "## ps -eo pid,ppid,user,etime,stat,cmd"; ps -eo pid,ppid,user,etime,stat,cmd 2>&1
  echo "## pstree -p"; pstree -p 2>&1 || echo "[pstree unavailable]"
} > "$OUTDIR/04-processes.txt" 2>/dev/null

# 05 network
{
  echo "## ss -tnp"; ss -tnp 2>&1
  echo "## ss -unp"; ss -unp 2>&1
  echo "## ip -4 a"; ip -4 a 2>&1
  echo "## ip -6 a"; ip -6 a 2>&1
  echo "## ip route"; ip route 2>&1
  echo "## ip -6 route"; ip -6 route 2>&1
  echo "## iptables -L -n -v"; iptables -L -n -v 2>&1 || echo "[iptables unavailable]"
  echo "## nft list ruleset"; nft list ruleset 2>&1 || echo "[nft unavailable]"
  echo "## resolv.conf"; [ -f /etc/resolv.conf ] && cat /etc/resolv.conf 2>&1
  echo "## /etc/hosts"; cat /etc/hosts 2>&1
} > "$OUTDIR/05-network.txt" 2>/dev/null

# 06 listening
{
  echo "## ss -tlnp"; ss -tlnp 2>&1
  echo "## ss -ulnp"; ss -ulnp 2>&1
  echo "## netstat -tlnp (fallback)"; netstat -tlnp 2>&1 || true
} > "$OUTDIR/06-listening.txt" 2>/dev/null

# 07 recent files
{
  echo "## recent modified files (last 7 days, limit 5000)"
  find / -xdev -mtime -7 -type f -printf "%T@ %p\n" 2>/dev/null | sort -n | tail -5000 | cut -d' ' -f2- 2>&1
} > "$OUTDIR/07-files-recent.txt" 2>/dev/null

# 08 suid
{
  echo "## SUID files"
  find / -xdev -perm -4000 -type f 2>/dev/null
  echo "## SGID files"
  find / -xdev -perm -2000 -type f 2>/dev/null
} > "$OUTDIR/08-suid.txt" 2>/dev/null

# 09 persistence
{
  echo "## /etc/crontab"; [ -f /etc/crontab ] && cat /etc/crontab 2>&1
  echo "## /etc/cron.{hourly,daily,weekly,monthly}.d/"
  for d in /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly /etc/cron.d; do
    [ -d "$d" ] && echo "==$d==" && ls -la "$d" 2>&1
  done
  echo "## user crontabs (/var/spool/cron)"; ls -laR /var/spool/cron 2>&1 || true
  echo "## systemctl enabled units"; systemctl list-unit-files --state=enabled 2>&1 || true
  echo "## /etc/rc.local"; [ -f /etc/rc.local ] && cat /etc/rc.local 2>&1
  echo "## /etc/profile, /etc/bash.bashrc"
  for f in /etc/profile /etc/bash.bashrc /etc/bashrc; do
    [ -f "$f" ] && echo "==$f==" && cat "$f" 2>&1
  done
  echo "## /etc/profile.d/*.sh"
  for f in /etc/profile.d/*.sh; do
    [ -e "$f" ] || continue
    echo "==$f=="; cat "$f" 2>&1
  done
} > "$OUTDIR/09-persistence.txt" 2>/dev/null

# 10 ssh
{
  echo "## /etc/ssh/sshd_config"; [ -f /etc/ssh/sshd_config ] && cat /etc/ssh/sshd_config 2>&1
  echo "## authorized_keys per user"
  while IFS=: read -r u _ uid _ _ home _; do
    [ -z "${home:-}" ] && continue
    [ "$uid" -lt 0 ] && continue
    f="$home/.ssh/authorized_keys"
    if [ -f "$f" ]; then
      echo "==$u==$f=="
      cat "$f" 2>&1
    fi
  done < /etc/passwd
} > "$OUTDIR/10-ssh.txt" 2>/dev/null

# 11 bash_history
{
  echo "## bash_history per user"
  while IFS=: read -r u _ uid _ _ home _; do
    [ -z "${home:-}" ] && continue
    f="$home/.bash_history"
    if [ -f "$f" ]; then
      echo "==$u==$f=="
      cat "$f" 2>&1
    fi
  done < /etc/passwd
  echo "## root .zsh_history"; [ -f /root/.zsh_history ] && cat /root/.zsh_history 2>&1
} > "$OUTDIR/11-bash-history.txt" 2>/dev/null

# 12 logs (optional)
if [ "$WITH_LOGS" -eq 1 ]; then
  echo "[*] archiving /var/log (large, may take a while)"
  tar czf "$OUTDIR/12-logs.tar.gz" /var/log 2>/dev/null || echo "[warn] tar /var/log failed" > "$OUTDIR/12-logs.tar.gz.warning"
else
  echo "[skipped]: re-run with --with-logs to include /var/log" > "$OUTDIR/12-logs.txt"
fi

# 13 pam
{
  echo "## /etc/pam.d/ listing"
  ls -la /etc/pam.d/ 2>&1
  echo "## md5sum /etc/pam.d/*"
  md5sum /etc/pam.d/* 2>/dev/null
} > "$OUTDIR/13-pam.txt" 2>/dev/null

# 14 systemd
{
  echo "## systemctl list-units --type=service"
  systemctl list-units --type=service --all 2>&1
  echo "## systemctl list-timers"
  systemctl list-timers --all 2>&1
} > "$OUTDIR/14-systemd-units.txt" 2>/dev/null

# 15 env
{
  echo "## env"; env 2>&1
  echo "## /etc/environment"; [ -f /etc/environment ] && cat /etc/environment 2>&1
  echo "## /etc/profile.d/*.sh (head -500 combined)"
  cat /etc/profile.d/*.sh 2>/dev/null | head -500
} > "$OUTDIR/15-env.txt" 2>/dev/null

note "collector end ts=$(date -u +%Y%m%dT%H%M%SZ)"
echo "[*] packing $TARGZ"
tar czf "$TARGZ" -C /tmp "$(basename "$OUTDIR")" 2>/dev/null

if [ -f "$TARGZ" ]; then
  SIZE=$(stat -c%s "$TARGZ" 2>/dev/null || stat -f%z "$TARGZ" 2>/dev/null || echo "?")
  echo
  echo "==> $TARGZ"
  echo "    size: ${SIZE} bytes"
  echo
  echo "Send the file back to the analyst via your standard secure channel."
  echo "Example:  scp $TARGZ analyst@<analyst-host>:/path/to/intake/"
else
  echo "[ERROR] failed to create archive" >&2
  exit 1
fi

exit 0
