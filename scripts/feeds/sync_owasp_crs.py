#!/usr/bin/env python3.11
# -*- coding: utf-8 -*-
"""
sync_owasp_crs.py — OWASP CRS 通用 Web 攻击正则 → traffic-signatures.json 同步器.

用途
----
浅克隆 OWASP Core Rule Set，解析 SecRule `@rx <正则>` 操作符，提取通用 Web 攻击
检测正则（SQLi/RCE/XSS/LFI/RFI/PHP），转换为 hvv-defender traffic-signatures.json
的 http view 条目（field=uri/request_line_excerpt），由 traffic_anomaly.py http 分发消费。

红线
----
- 只提取 CRS 的检测正则（@rx 后的模式），不输出完整可复现 exploit payload。
- CRS 正则本身是检测特征（匹配 SQLi/RCE 关键词模式），符合项目"只到触发字段+关键词"红线。
- 策展：只取通用攻击类（930-LFI/931-RFI/932-RCE/933-PHP/941-XSS/942-SQLi），
  跳过 900/911/920/921 等协议合规类（误报高、与护网检测目标不符）。

离线优先
--------
构建期浅克隆上游 + 解析转换，产物落 data/traffic-signatures.json。运行时 traffic_anomaly
只读本地 JSON，零外发。

用法
----
    python3.11 scripts/feeds/sync_owasp_crs.py            # 同步并合并到 data/traffic-signatures.json
    python3.11 scripts/feeds/sync_owasp_crs.py --dry-run   # 只打印提取的条目，不写文件
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Iterator

REPO_URL = "https://github.com/coreruleset/coreruleset.git"
# 策展的规则文件 → 项目 category 映射（只取通用攻击类）
FILE_CATEGORY = {
    "REQUEST-930-APPLICATION-ATTACK-LFI.conf":  ("lfi",        "request_line_excerpt"),
    "REQUEST-931-APPLICATION-ATTACK-RFI.conf":  ("rfi",        "request_line_excerpt"),
    "REQUEST-932-APPLICATION-ATTACK-RCE.conf":  ("rce",        "request_line_excerpt"),
    "REQUEST-933-APPLICATION-ATTACK-PHP.conf":  ("rce",        "request_line_excerpt"),
    "REQUEST-941-APPLICATION-ATTACK-XSS.conf":  ("xss",        "request_line_excerpt"),
    "REQUEST-942-APPLICATION-ATTACK-SQLI.conf": ("sqli",       "request_line_excerpt"),
}
# CRS rule id → 项目 severity（CRS 用 paranoia level，这里按攻击类映射）
CATEGORY_SEVERITY = {
    "sqli": "high", "rce": "high", "lfi": "high", "rfi": "high", "xss": "medium",
}

# data/traffic-signatures.json 路径（相对脚本位置）
DEFAULT_OUTPUT = Path(__file__).resolve().parent.parent.parent / "data" / "traffic-signatures.json"
# 新条目 id 前缀（避免与现有 SIG-TRAF-001~126 冲突，用 SIG-TRAF-CRS-xxx）
ID_PREFIX = "SIG-TRAF-CRS"


def log(msg: str) -> None:
    print(f"[sync_owasp_crs] {msg}", file=sys.stderr)


def shallow_clone(dst: Path) -> bool:
    """浅克隆 CRS（sparse-checkout 仅 rules/）。带重试，成功返回 True。"""
    clone_ok = False
    for attempt in range(3):
        try:
            subprocess.run(
                ["git", "clone", "--depth", "1", "--filter=blob:none",
                 "--sparse", REPO_URL, str(dst)],
                check=True, capture_output=True, timeout=120,
            )
            clone_ok = True
            break
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
            log(f"克隆尝试 {attempt+1}/3 失败: {e}")
            if dst.exists():
                import shutil
                shutil.rmtree(dst, ignore_errors=True)
        except FileNotFoundError:
            log("git 未安装")
            return False
    if not clone_ok:
        return False
    try:
        subprocess.run(
            ["git", "sparse-checkout", "set", "rules"],
            cwd=dst, check=True, capture_output=True, timeout=30,
        )
        return True
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
        log(f"sparse-checkout 失败: {e}")
        return False


def extract_rx_from_file(path: Path) -> Iterator[str]:
    """从单个 CRS .conf 文件提取所有 @rx 后的正则字符串。

    CRS SecRule 格式：
        SecRule <VARS> "@rx <pattern>" \\<续行>
            "id:...,phase:...,..."
    pattern 内的双引号用 \\" 转义。本解析器用状态机逐字符扫描，从 "@rx 后第一个
    非空白字符开始，遇到未转义的 " 结束，正确跳过 \\"。
    """
    text = path.read_text(encoding="utf-8", errors="replace")
    # 合并反斜杠续行（行尾 \ + 换行 → 空），把跨行 SecRule 拼成一行
    text = re.sub(r"\\\s*\n\s*", " ", text)

    for m in re.finditer(r'"@rx\s+', text):
        start = m.end()
        i = start
        out = []
        while i < len(text):
            ch = text[i]
            if ch == "\\" and i + 1 < len(text):
                # 转义字符：保留反斜杠 + 下一字符（包括 \"）
                out.append(ch)
                out.append(text[i + 1])
                i += 2
                continue
            if ch == '"':
                break  # 未转义的引号 = pattern 结束
            out.append(ch)
            i += 1
        pattern = "".join(out)
        # 还原 CRS 的 \" → "（Python re 里 " 不是元字符，可直接保留，但为干净还原）
        pattern = pattern.replace('\\"', '"')
        if len(pattern) < 4:
            continue
        yield pattern


def is_valid_python_re(pattern: str) -> bool:
    """验证正则能否被 Python re 编译。CRS 用 PCRE，绝大多数兼容，少数不兼容需跳过。"""
    try:
        re.compile(pattern)
        return True
    except re.error:
        return False


def convert() -> list[dict]:
    """克隆 CRS → 提取正则 → 转项目 traffic-signatures 条目。返回新条目列表。"""
    with tempfile.TemporaryDirectory(prefix="crs-sync-") as td:
        clone_dir = Path(td) / "crs"
        if not shallow_clone(clone_dir):
            log("克隆失败，终止")
            return []
        rules_dir = clone_dir / "rules"
        if not rules_dir.is_dir():
            log(f"rules/ 目录不存在: {rules_dir}")
            return []

        entries: list[dict] = []
        seq = 1
        for fname, (category, field) in FILE_CATEGORY.items():
            fpath = rules_dir / fname
            if not fpath.is_file():
                log(f"跳过（文件不存在）: {fname}")
                continue
            n_file = 0
            for pattern in extract_rx_from_file(fpath):
                if not is_valid_python_re(pattern):
                    continue
                entries.append({
                    "id": f"{ID_PREFIX}-{seq:03d}",
                    "category": category,
                    "view": "http",
                    "field": field,
                    "pattern": pattern,
                    "tool": f"owasp-crs-{fname.split('-')[1].lower()}",
                    "severity": CATEGORY_SEVERITY.get(category, "medium"),
                    "description": f"OWASP CRS {fname.split('-')[1]} 通用 {category.upper()} 检测正则",
                    "false_positive": "CRS 通用正则，护网期建议结合 URI 路径与状态码二次确认",
                })
                seq += 1
                n_file += 1
            log(f"{fname}: 提取 {n_file} 条有效正则")
        return entries


def merge_into_output(entries: list[dict], output: Path, dry_run: bool) -> int:
    """把新条目追加到 traffic-signatures.json（按 pattern 去重），返回新增数。"""
    if not entries:
        log("无条目可合并")
        return 0
    data = json.loads(output.read_text(encoding="utf-8"))
    sigs = data.get("signatures", [])
    existing_patterns = {s.get("pattern") for s in sigs}
    new = [e for e in entries if e["pattern"] not in existing_patterns]
    if dry_run:
        log(f"[dry-run] 将新增 {len(new)} 条（去重前 {len(entries)}）")
        for e in new[:5]:
            log(f"  样例: {e['id']} {e['category']} {e['pattern'][:60]}...")
        return len(new)
    sigs.extend(new)
    data["signatures"] = sigs
    data["total"] = len(sigs)
    data["updated_at"] = "2026-07-10"
    output.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    log(f"合并完成：新增 {len(new)} 条，当前共 {len(sigs)} 条 → {output}")
    return len(new)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="OWASP CRS → traffic-signatures.json 同步器")
    p.add_argument("--output", default=str(DEFAULT_OUTPUT),
                   help=f"输出 JSON 路径（默认 {DEFAULT_OUTPUT}）")
    p.add_argument("--dry-run", action="store_true", help="只打印不写文件")
    args = p.parse_args(argv)

    entries = convert()
    log(f"共提取 {len(entries)} 条候选条目")
    n = merge_into_output(entries, Path(args.output), args.dry_run)
    return 0 if n >= 0 else 1


if __name__ == "__main__":
    sys.exit(main())
