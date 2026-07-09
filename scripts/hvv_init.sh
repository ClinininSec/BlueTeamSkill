#!/usr/bin/env bash
# ============================================================================
# hvv_init.sh — hvv-defender 依赖工具一键安装
#
# 逻辑就一件事：检查系统缺什么工具 → 直接装。
#
# 需要的工具：
#   - tshark    (traffic 模式必需)
#   - python3.11 (script  运行必需)
#   - sshpass   (remote 模式密码认证必需；无 sshpass 时降级到 expect)
#   - expect    (remote 模式密码认证的备选；sshpass 不可用时启用)
#
# 支持平台：macOS (brew) / Ubuntu (deadsnakes ppa) / Debian (apt)
#           / RHEL & Fedora (dnf/yum) / Alpine (apk) / Arch (pacman)
#           / openSUSE (zypper)
# Windows 检测到会打印手工安装指引，不自动装。
#
# 合规：不外发数据、只装白名单工具、脚本本身不处理客户数据。
# ============================================================================

set -uo pipefail

# tshark / python3.11 是硬依赖；sshpass / expect 是 remote 模式的可选依赖。
# 二选一即可满足 remote 密码认证需求，都装最稳。
REQUIRED=(tshark python3.11)
OPTIONAL_REMOTE=(sshpass expect)

# ---------- 1) 决定包管理器 ----------
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
      echo "[ERR] 未识别 Linux 包管理器，请手动安装：${REQUIRED[*]} ${OPTIONAL_REMOTE[*]}"
      exit 1
    fi
    ;;
  MINGW*|MSYS*|CYGWIN*)
    echo "[ERR] Windows 无法自动安装。请手动装以下工具："
    echo "      python3.11 : https://www.python.org/downloads/         (或 choco install python311)"
    echo "      tshark     : https://www.wireshark.org/download.html   (或 choco install wireshark)"
    echo "      sshpass    : Windows 上一般用 WSL + apt install sshpass；纯 Win 用 Plink / PuTTY -pw"
    echo "      expect     : choco install expect (需 ActiveTcl) 或 WSL + apt install expect"
    exit 1
    ;;
  *)
    echo "[ERR] 不支持的平台 $uname_s。请手动安装：${REQUIRED[*]}"
    exit 1
    ;;
esac

# ---------- 2) 工具名 → 包名（大部分同名；tshark 与 sshpass/expect 有平台差异） ----------
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
    python3.11)
      case "$uname_s" in
        Darwin*) echo "python@3.11" ;;
        Linux*)
          # pacman / zypper 系包名无点；其余发行版均为 python3.11
          if command -v pacman >/dev/null 2>&1 || command -v zypper >/dev/null 2>&1; then
            echo "python311"
          else
            echo "python3.11"
          fi
          ;;
      esac
      ;;
    expect) echo "expect" ;;
    *) echo "$1" ;;
  esac
}

# ---------- 3) 检查缺什么 ----------
missing=()
for cmd in "${REQUIRED[@]}"; do
  command -v "$cmd" >/dev/null 2>&1 || missing+=("$cmd")
done

missing_optional=()
for cmd in "${OPTIONAL_REMOTE[@]}"; do
  command -v "$cmd" >/dev/null 2>&1 || missing_optional+=("$cmd")
done

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

# ---------- 4) 平台特定预处理：python3.11 源准备 ----------
# Ubuntu 22.04 及之前的官方源默认不带 python3.11，deadsnakes 长期维护各版本 Python
if [[ "$uname_s" == Linux* ]] && command -v apt-get >/dev/null 2>&1 \
   && grep -iq ubuntu /etc/os-release 2>/dev/null \
   && ! command -v python3.11 >/dev/null 2>&1; then
  echo "[INFO] Ubuntu 上 python3.11 走 deadsnakes PPA ..."
  sudo apt-get update -qq
  sudo apt-get install -y software-properties-common
  sudo add-apt-repository -y ppa:deadsnakes/ppa
  sudo apt-get update -qq
fi
# RHEL / Fedora: python3.11 可能需要 EPEL；dnf/yum 安装失败时提示
if [[ "$uname_s" == Linux* ]] && (command -v dnf >/dev/null 2>&1 || command -v yum >/dev/null 2>&1) \
   && ! command -v python3.11 >/dev/null 2>&1; then
  echo "[INFO] RHEL/Fedora 上 python3.11 可能需先启用 EPEL："
  echo "       sudo dnf install -y epel-release   (RHEL/CentOS)"
  echo "       sudo dnf install -y python3.11      (Fedora 37+ 直接可用)"
fi

# ---------- 5a) 硬依赖 ----------
if [[ ${#missing[@]} -gt 0 ]]; then
  for cmd in "${missing[@]}"; do
    pkg=$(pkg_of "$cmd")
    echo "[INFO] 安装 ${cmd} (包名 ${pkg}) ..."
    # shellcheck disable=SC2086
    if ! $INSTALL $pkg; then
      echo "[ERR] ${cmd} 安装失败，请手动排查"
      echo "      若系统源无 ${pkg}，可用 pyenv 安装：curl https://pyenv.run | bash && pyenv install 3.11"
      exit 1
    fi
  done
fi

# ---------- 5b) remote 密码认证依赖（可选；能装几个装几个） ----------
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

# ---------- 6) 二次确认 ----------
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
