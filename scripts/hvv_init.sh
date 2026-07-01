#!/usr/bin/env bash
# ============================================================================
# hvv_init.sh — hvv-defender 依赖工具一键安装
#
# 逻辑就一件事：检查系统缺什么工具 → 直接装。
#
# 需要的工具：
#   - tshark    (traffic 模式必需)
#   - python3   (所有脚本必需)
#   - sshpass   (remote 模式密码认证必需；无 sshpass 时降级到 expect)
#   - expect    (remote 模式密码认证的备选；sshpass 不可用时启用)
#
# 支持平台：macOS (brew) / Debian & Ubuntu (apt) / RHEL & Fedora (dnf/yum)
#           / Alpine (apk) / Arch (pacman) / openSUSE (zypper)
# Windows 检测到会打印手工安装指引，不自动装。
#
# 合规：不外发数据、只装白名单工具、脚本本身不处理客户数据。
# ============================================================================

set -uo pipefail

# tshark / python3 是硬依赖；sshpass / expect 是 remote 模式的可选依赖。
# 二选一即可满足 remote 密码认证需求，都装最稳。
REQUIRED=(tshark python3)
OPTIONAL_REMOTE=(sshpass expect)

# ---------- 1) 检查缺什么 ----------
missing=()
for cmd in "${REQUIRED[@]}"; do
  command -v "$cmd" >/dev/null 2>&1 || missing+=("$cmd")
done

# 可选：remote 模式密码认证依赖
# 策略：sshpass 是主选（-p 简洁 + ssh_probe.py 使用简单），expect 是备选（macOS brew 有时装 sshpass 失败）
# 目标：sshpass 与 expect 都尽量装；至少一个 ready 才算合格
missing_optional=()
for cmd in "${OPTIONAL_REMOTE[@]}"; do
  command -v "$cmd" >/dev/null 2>&1 || missing_optional+=("$cmd")
done
remote_pw_ready=0
if command -v sshpass >/dev/null 2>&1 || command -v expect >/dev/null 2>&1; then
  remote_pw_ready=1
fi

# fast-path：全部都已装（硬依赖 + 两个可选都在）
if [[ ${#missing[@]} -eq 0 && ${#missing_optional[@]} -eq 0 ]]; then
  echo "[OK] 所有依赖已就绪：${REQUIRED[*]} ${OPTIONAL_REMOTE[*]}"
  for cmd in "${REQUIRED[@]}" "${OPTIONAL_REMOTE[@]}"; do
    echo "     $cmd → $(command -v "$cmd")"
  done
  exit 0
fi

if [[ ${#missing[@]} -gt 0 ]]; then
  echo "[INFO] 缺失硬依赖：${missing[*]}"
fi
if [[ ${#missing_optional[@]} -gt 0 ]]; then
  echo "[INFO] remote 模式密码认证工具缺：${missing_optional[*]}（推荐 sshpass + expect 都装）"
fi

# ---------- 2) 决定包管理器 ----------
uname_s=$(uname -s)
case "$uname_s" in
  Darwin*)
    if ! command -v brew >/dev/null 2>&1; then
      echo "[ERR] macOS 需要先装 Homebrew：https://brew.sh/"
      exit 1
    fi
    INSTALL="brew install"
    ;;
  Linux*)
    if   command -v apt-get >/dev/null 2>&1; then INSTALL="sudo DEBIAN_FRONTEND=noninteractive apt-get install -y"
    elif command -v dnf     >/dev/null 2>&1; then INSTALL="sudo dnf install -y"
    elif command -v yum     >/dev/null 2>&1; then INSTALL="sudo yum install -y"
    elif command -v apk     >/dev/null 2>&1; then INSTALL="sudo apk add"
    elif command -v pacman  >/dev/null 2>&1; then INSTALL="sudo pacman -S --noconfirm"
    elif command -v zypper  >/dev/null 2>&1; then INSTALL="sudo zypper install -y"
    else
      echo "[ERR] 未识别 Linux 包管理器，请手动安装：${missing[*]}"
      exit 1
    fi
    ;;
  MINGW*|MSYS*|CYGWIN*)
    echo "[ERR] Windows 无法自动安装。请手动装以下工具：${missing[*]} ${OPTIONAL_REMOTE[*]}"
    echo "      tshark  : https://www.wireshark.org/download.html  (或 choco install wireshark)"
    echo "      python3 : https://www.python.org/downloads/         (或 choco install python)"
    echo "      sshpass : Windows 上一般用 WSL + apt install sshpass；纯 Win 用 Plink / PuTTY -pw"
    echo "      expect  : choco install expect (需 ActiveTcl) 或 WSL + apt install expect"
    exit 1
    ;;
  *)
    echo "[ERR] 不支持的平台 $uname_s。请手动安装：${missing[*]}"
    exit 1
    ;;
esac

# ---------- 3) 工具名 → 包名（大部分同名；tshark 与 sshpass/expect 有平台差异） ----------
pkg_of() {
  case "$1" in
    tshark)
      case "$uname_s" in
        Darwin*) echo "wireshark" ;;
        Linux*)
          if command -v dnf >/dev/null 2>&1 || command -v yum >/dev/null 2>&1 || command -v pacman >/dev/null 2>&1; then
            echo "wireshark-cli"
          else
            echo "tshark"
          fi
          ;;
      esac
      ;;
    sshpass)
      # macOS Homebrew 主仓库已下架 sshpass（license 问题），走 esolitos/ipa/sshpass tap
      case "$uname_s" in
        Darwin*) echo "esolitos/ipa/sshpass" ;;
        *)       echo "sshpass" ;;
      esac
      ;;
    expect) echo "expect" ;;
    *) echo "$1" ;;
  esac
}

# ---------- 4a) 硬依赖 ----------
if [[ ${#missing[@]} -gt 0 ]]; then
  for cmd in "${missing[@]}"; do
    pkg=$(pkg_of "$cmd")
    echo "[INFO] 安装 ${cmd} (包名 ${pkg}) ..."
    # shellcheck disable=SC2086
    if ! $INSTALL $pkg; then
      echo "[ERR] ${cmd} 安装失败，请手动排查"
      exit 1
    fi
  done
fi

# ---------- 4b) remote 密码认证依赖（可选；能装几个装几个） ----------
if [[ ${#missing_optional[@]} -gt 0 ]]; then
  installed_any=0
  for cmd in "${missing_optional[@]}"; do
    pkg=$(pkg_of "$cmd")
    echo "[INFO] 安装 ${cmd} (包名 ${pkg}) —— remote 模式密码认证用 ..."
    # shellcheck disable=SC2086
    if $INSTALL $pkg; then
      installed_any=1
    else
      echo "[WARN] ${cmd} 安装失败（macOS 上 sshpass 若走 brew 官方仓库会拒绝 license，需 tap esolitos/ipa；此处已用 tap 名，若仍失败请手动 brew tap esolitos/ipa 再试）"
    fi
  done
  # 装完后再确认一次：至少要有一个可用
  if command -v sshpass >/dev/null 2>&1 || command -v expect >/dev/null 2>&1; then
    :  # ok
  else
    echo "[WARN] sshpass / expect 都未装成功；remote 模式仍可用（只是不能走密码认证）"
    echo "       建议改用 SSH 公钥登录：ssh-copy-id user@host"
  fi
fi

# ---------- 5) 二次确认 ----------
echo ""
fail=0
for cmd in "${REQUIRED[@]}"; do
  if command -v "$cmd" >/dev/null 2>&1; then
    echo "[OK] $cmd → $(command -v "$cmd")"
  else
    echo "[ERR] $cmd 装完仍不在 PATH（可能需要重新打开 shell 或加 PATH）"
    fail=1
  fi
done

# 可选依赖只 warn 不 fail
remote_ok=0
for cmd in "${OPTIONAL_REMOTE[@]}"; do
  if command -v "$cmd" >/dev/null 2>&1; then
    echo "[OK] $cmd → $(command -v "$cmd")  (remote 模式密码认证)"
    remote_ok=1
  fi
done
if [[ $remote_ok -eq 0 ]]; then
  echo "[WARN] sshpass / expect 都未就绪，remote 模式将强制要求 SSH 公钥登录"
fi

if [[ $fail -eq 0 ]]; then
  echo ""
  echo "[OK] hvv-defender 依赖就绪。可用触发词："
  echo "     /hvv-defender monitor | audit | traffic | ir | remote"
fi
exit $fail
