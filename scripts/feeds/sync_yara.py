#!/usr/bin/env python3.11
# -*- coding: utf-8 -*-
"""
sync_yara.py — YARA 通用 webshell 检测规则 → webshell-patterns.json 同步器.

用途
----
解析 YARA 规则文件（bartblaze/Yara-rules），提取 webshell/backdoor 相关规则的
strings（字符串 + 正则），转换为 hvv-defender webshell-patterns.json 条目，
由 webshell_scan.py 消费（MULTILINE|DOTALL 编译，大小写敏感，需自带 (?i)）。

红线
----
- 只提取 YARA strings 的检测特征（字符串/正则），不输出完整 webshell 样本。
- 策展：只取 webshell/backdoor 相关规则（meta.category=MALWARE + malware_type=WEBSHELL，
  或文件名含 webshell/shell/backdoor），跳过 APT/ransomware 等针对性家族规则。

离线优先
--------
构建期解析本地 YARA 目录，产物落 data/webshell-patterns.json，运行时零外发。

用法
----
    python3.11 scripts/feeds/sync_yara.py --local ~/Downloads/hvv-feeds/Yara-rules-master
    python3.11 scripts/feeds/sync_yara.py --local <dir> --dry-run
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Iterator

DEFAULT_OUTPUT = Path(__file__).resolve().parent.parent.parent / "data" / "webshell-patterns.json"
ID_PREFIX = "SIG-WS-YARA"

# webshell 相关文件名/路径关键词
SHELL_KEYWORDS = ("webshell", "shell", "backdoor")


def log(msg: str) -> None:
    print(f"[sync_yara] {msg}", file=sys.stderr)


# YARA 规则结构正则
RULE_HEADER_RE = re.compile(r'^\s*rule\s+(\w+)', re.MULTILINE)
META_BLOCK_RE = re.compile(r'meta:\s*(.*?)\s*strings:', re.DOTALL | re.IGNORECASE)
# strings 段：$name = "string" 或 $name = /regex/ modifiers
YARA_STRING_RE = re.compile(
    r'\$(\w+)\s*=\s*(?:"([^"]*)"|/(.*?)/)\s*((?:\w+\s+)*)',
    re.DOTALL,
)


def is_webshell_rule(meta_text: str, file_path: Path) -> bool:
    """判断是否 webshell 相关规则（meta 字段或文件名）。"""
    mt = meta_text.lower()
    if "webshell" in mt or "backdoor" in mt:
        return True
    fname = file_path.name.lower()
    return any(k in fname for k in SHELL_KEYWORDS)


def yara_regex_to_python(pattern: str, modifiers: str) -> str | None:
    """YARA 正则转 Python 正则。nocase → 加 (?i)。不兼容的跳过返回 None。

    YARA 正则与 PCRE 接近，绝大多数字符类/量词兼容 Python re。
    """
    out = pattern
    if "nocase" in modifiers.lower():
        out = "(?i)" + out
    # 验证可编译
    try:
        re.compile(out)
        return out
    except re.error:
        return None


def yara_string_to_pattern(value: str) -> str | None:
    """YARA 字符串字面量转 Python 正则（re.escape + 锚定子串）。"""
    if not value or len(value) < 4:
        return None
    try:
        pat = re.escape(value)
        re.compile(pat)
        return pat
    except re.error:
        return None


def parse_yar_file(path: Path) -> list[dict]:
    """解析单个 YARA 文件，返回 webshell 相关规则的 strings 条目。"""
    text = path.read_text(encoding="utf-8", errors="replace")
    entries: list[dict] = []
    # 按 rule 拆分
    rule_starts = [(m.start(), m.group(1)) for m in RULE_HEADER_RE.finditer(text)]
    rule_starts.append((len(text), None))
    for i in range(len(rule_starts) - 1):
        start, name = rule_starts[i]
        end = rule_starts[i + 1][0]
        body = text[start:end]
        meta_m = META_BLOCK_RE.search(body)
        if not meta_m:
            continue
        meta_text = meta_m.group(1)
        if not is_webshell_rule(meta_text, path):
            continue
        # 描述
        desc_m = re.search(r'description\s*=\s*"([^"]*)"', meta_text, re.IGNORECASE)
        desc = desc_m.group(1) if desc_m else f"YARA rule {name}"
        # strings 段（meta 之后到 condition 之前）
        cond_m = re.search(r'\bcondition:', body, re.IGNORECASE)
        strings_end = cond_m.start() if cond_m else len(body)
        strings_start = meta_m.end()
        strings_text = body[strings_start:strings_end]
        for sm in YARA_STRING_RE.finditer(strings_text):
            sname, sval, sregex, smod = sm.group(1), sm.group(2), sm.group(3), sm.group(4)
            pattern = None
            stype = ""
            if sregex is not None and sregex != "":
                pattern = yara_regex_to_python(sregex, smod)
                stype = "regex"
            elif sval:
                pattern = yara_string_to_pattern(sval)
                stype = "string"
            if pattern:
                entries.append({
                    "rule_name": name,
                    "string_name": sname,
                    "pattern": pattern,
                    "source_type": stype,
                    "description": desc,
                })
    return entries


def convert(local_dir: Path) -> list[dict]:
    """遍历本地 YARA 目录，提取 webshell strings，转 webshell-patterns 条目。

    只保留正则类 strings（文件内容特征，如 eval\(/base64_decode），跳过纯字符串
    字面量——后者多为 webshell 工具输出/回显文本，对 webshell_scan 扫文件内容无价值。
    """
    yar_files = sorted(local_dir.rglob("*.yar"))
    if not yar_files:
        rules_sub = local_dir / "rules"
        if rules_sub.is_dir():
            yar_files = sorted(rules_sub.rglob("*.yar"))
    log(f"扫描到 {len(yar_files)} 个 .yar 文件")
    entries: list[dict] = []
    seq = 1
    n_skipped_str = 0
    for yf in yar_files:
        for e in parse_yar_file(yf):
            if e["source_type"] != "regex":
                n_skipped_str += 1
                continue
            entries.append({
                "id": f"{ID_PREFIX}-{seq:03d}",
                "lang": "generic",
                "pattern": e["pattern"],
                "severity": "high",
                "description": f"YARA {e['rule_name']}.{e['string_name']}: {e['description'][:80]}",
                "false_positive": "YARA 通用 webshell 正则特征，需结合文件类型",
            })
            seq += 1
    log(f"提取 {len(entries)} 条 webshell 正则特征（跳过 {n_skipped_str} 条纯字符串字面量）")
    return entries


def merge_into_output(entries: list[dict], output: Path, dry_run: bool) -> int:
    if not entries:
        log("无条目可合并")
        return 0
    data = json.loads(output.read_text(encoding="utf-8"))
    rules = data.get("rules", data) if isinstance(data, dict) else data
    existing = {r.get("pattern") for r in rules}
    new = [e for e in entries if e["pattern"] not in existing]
    if dry_run:
        log(f"[dry-run] 将新增 {len(new)} 条")
        for e in new[:5]:
            log(f"  {e['id']} {e['pattern'][:60]}")
        return len(new)
    rules.extend(new)
    if isinstance(data, dict):
        data["rules"] = rules
        data["total"] = len(rules)
        data["updated_at"] = "2026-07-10"
        output.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    else:
        output.write_text(json.dumps(rules, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    log(f"合并完成：新增 {len(new)} 条，当前共 {len(rules)} 条 → {output}")
    return len(new)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="YARA webshell → webshell-patterns.json 同步器")
    p.add_argument("--local", required=True, help="本地 Yara-rules 目录（含 rules/ 或直接 .yar）")
    p.add_argument("--output", default=str(DEFAULT_OUTPUT))
    p.add_argument("--dry-run", action="store_true")
    args = p.parse_args(argv)
    local = Path(args.local)
    if not local.is_dir():
        log(f"目录不存在: {local}")
        return 1
    entries = convert(local)
    return 0 if merge_into_output(entries, Path(args.output), args.dry_run) >= 0 else 1


if __name__ == "__main__":
    sys.exit(main())
