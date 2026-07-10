#!/usr/bin/env python3.11
# -*- coding: utf-8 -*-
"""
sync_et_open.py — ET Open 通用 Suricata 流量规则 → traffic-signatures.json 同步器.

用途
----
解析 ET Open Suricata 规则文件，提取通用 http 攻击规则的 content/pcre 特征，
转换为 hvv-defender traffic-signatures.json 的 http view 条目（ua/uri/request_line_excerpt），
由 traffic_anomaly.py http 分发消费。

红线
----
- 只提取 content/pcre 检测特征，不输出完整 exploit payload。
- 策展：只取通用攻击类（web_server/web_specific_apps/sql/user_agents/coinminer/exploit_kit），
  跳过 chat/tor/p2p 等非攻击类；只取 alert http 规则；按 msg 分类映射 category。

离线优先
--------
构建期解析本地 ET Open rules 目录，产物落 data/traffic-signatures.json，运行时零外发。

用法
----
    python3.11 scripts/feeds/sync_et_open.py --local ~/Downloads/hvv-feeds/et-open
    python3.11 scripts/feeds/sync_et_open.py --local <dir> --dry-run
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

DEFAULT_OUTPUT = Path(__file__).resolve().parent.parent.parent / "data" / "traffic-signatures.json"
ID_PREFIX = "SIG-TRAF-ET"

# 策展的规则文件 → category 映射
# 只取通用类（扫描器 UA / 挖矿 / 通用 webshell 标题 / exploit_kit），跳过
# web_specific_apps(特定应用漏洞) 和 malware(特定家族) —— 后者非通用、量大、护网误报高。
FILE_CATEGORY = {
    "emerging-web_server.rules":         "rce",       # 通用 webshell 标题/路径
    "emerging-user_agents.rules":        "scanner",   # 扫描器/工具 UA
    "emerging-coinminer.rules":          "c2",        # 挖矿池/矿机通信
    "emerging-exploit_kit.rules":        "c2",        # 通用漏洞利用 kit
    "emerging-current_events.rules":     "c2",        # 通用事件响应 IOC
}

# Suricata 规则正则
# alert http ... (msg:"..."; ... content:"..."; ... pcre:"/.../"; sid:N; ...)
RULE_RE = re.compile(
    r'^alert\s+http\s+.*?\(msg:"([^"]*)";(.*?)sid:(\d+);',
    re.DOTALL,
)
# http.uri/content 字段 + 上下文标记
HTTP_URI_RE = re.compile(r'http\.uri;\s*content:"([^"]*)"', re.DOTALL)
HTTP_UA_RE = re.compile(r'http\.user_agent;\s*content:"([^"]*)"|http_header.*?User-Agent.*?content:"([^"]*)"', re.DOTALL | re.IGNORECASE)
BARE_CONTENT_RE = re.compile(r'(?<![\w.])content:"([^"]*)"', re.DOTALL)
PCRE_RE = re.compile(r'pcre:"/(.*?)/(\w*)"', re.DOTALL)


def log(msg: str) -> None:
    print(f"[sync_et_open] {msg}", file=sys.stderr)


def suricata_to_python_re(pcre_pattern: str, pcre_flags: str) -> str | None:
    """Suricata pcre 转 Python 正则。i flag → (?i)。不兼容跳过。"""
    out = pcre_pattern
    if "i" in pcre_flags:
        out = "(?i)" + out
    try:
        re.compile(out)
        return out
    except re.error:
        return None


def extract_features(msg: str, options: str) -> list[tuple[str, str]]:
    """从一条 Suricata 规则的 options 提取 (field, pattern) 对。

    优先级：http.uri content → field=uri；http.user_agent content → field=ua；
    否则用 pcre 或裸 content → field=request_line_excerpt。
    """
    feats: list[tuple[str, str]] = []
    # http.uri content
    for m in HTTP_URI_RE.finditer(options):
        val = m.group(1)
        if val and len(val) >= 3:
            feats.append(("uri", re.escape(val)))
    # http.user_agent content
    for m in HTTP_UA_RE.finditer(options):
        val = m.group(1) or m.group(2)
        if val and len(val) >= 3:
            feats.append(("ua", re.escape(val)))
    # pcre（若上面没有，用 pcre 放 request_line_excerpt）
    if not feats:
        for m in PCRE_RE.finditer(options):
            pat = suricata_to_python_re(m.group(1), m.group(2))
            if pat and len(pat) >= 4:
                feats.append(("request_line_excerpt", pat))
    # 裸 content（无 http 字段标记，作 request_line_excerpt 子串）
    if not feats:
        for m in BARE_CONTENT_RE.finditer(options):
            val = m.group(1)
            if val and len(val) >= 4 and "|" not in val:  # 跳过 hex content（含 |）
                feats.append(("request_line_excerpt", re.escape(val)))
    return feats


def convert(local_dir: Path) -> list[dict]:
    rules_dir = local_dir / "rules" if (local_dir / "rules").is_dir() else local_dir
    if not rules_dir.is_dir():
        log(f"找不到 rules 目录: {rules_dir}")
        return []
    entries: list[dict] = []
    seq = 1
    for fname, category in FILE_CATEGORY.items():
        fpath = rules_dir / fname
        if not fpath.is_file():
            log(f"跳过（文件不存在）: {fname}")
            continue
        n_file = 0
        for line in fpath.read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            m = RULE_RE.match(line)
            if not m:
                continue
            msg, options, sid = m.group(1), m.group(2), m.group(3)
            for field, pattern in extract_features(msg, options):
                entries.append({
                    "id": f"{ID_PREFIX}-{seq:03d}",
                    "category": category,
                    "view": "http",
                    "field": field,
                    "pattern": pattern,
                    "tool": f"et-open-{fname.replace('emerging-','').replace('.rules','')}",
                    "severity": "high" if category in ("rce", "c2") else "medium",
                    "description": f"ET Open {msg[:70]}",
                    "false_positive": "ET Open 通用规则，护网期结合业务确认",
                })
                seq += 1
                n_file += 1
        log(f"{fname}: 提取 {n_file} 条")
    return entries


def merge_into_output(entries: list[dict], output: Path, dry_run: bool) -> int:
    if not entries:
        log("无条目可合并")
        return 0
    data = json.loads(output.read_text(encoding="utf-8"))
    sigs = data.get("signatures", [])
    existing = {s.get("pattern") for s in sigs}
    new = [e for e in entries if e["pattern"] not in existing]
    if dry_run:
        log(f"[dry-run] 将新增 {len(new)} 条（去重前 {len(entries)}）")
        for e in new[:5]:
            log(f"  {e['id']} {e['category']} {e['field']} {e['pattern'][:50]}")
        return len(new)
    sigs.extend(new)
    data["signatures"] = sigs
    data["total"] = len(sigs)
    data["updated_at"] = "2026-07-10"
    output.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    log(f"合并完成：新增 {len(new)} 条，当前共 {len(sigs)} 条 → {output}")
    return len(new)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="ET Open Suricata → traffic-signatures.json 同步器")
    p.add_argument("--local", required=True, help="本地 ET Open 目录（含 rules/）")
    p.add_argument("--output", default=str(DEFAULT_OUTPUT))
    p.add_argument("--dry-run", action="store_true")
    args = p.parse_args(argv)
    local = Path(args.local)
    if not local.is_dir():
        log(f"目录不存在: {local}")
        return 1
    entries = convert(local)
    log(f"共提取 {len(entries)} 条候选条目")
    return 0 if merge_into_output(entries, Path(args.output), args.dry_run) >= 0 else 1


if __name__ == "__main__":
    sys.exit(main())
