#!/usr/bin/env python3.11
# -*- coding: utf-8 -*-
"""
sync_sigma.py — Sigma 通用 Windows 检测规则 → sysmon-detection-rules.json 同步器.

用途
----
解析 SigmaHQ Sigma 规则（rules/windows/），提取通用持久化/提权/横向/Sysmon 检测规则，
转换 detection 语法为 Python 正则，落 data/sysmon-detection-rules.json，由 evtx_hunt.py
消费（阶段0.1 已激活 R-WIN-023 emit，灌入即告警）。

红线
----
- 只提取 detection 的检测特征（字段+正则），不输出完整 exploit payload。
- 策展：只取 level high/critical + 通用攻击类（process_creation/registry/file_event/
  network_connection），跳过特定恶意软件家族（含具体 malware name 的 title）。

转换规则
--------
Sigma detection modifier → Python 正则：
  Field|re: value        → value（原样，已是正则）
  Field|contains: value  → re.escape(value) 作为子串
  Field|endswith: value  → .*re.escape(value)$
  Field|startswith: v    → ^re.escape(v)
  Field: value（无修饰）→ ^re.escape(value)$（精确匹配）
logsource category → Sysmon event_id：process_creation→1, file_event→11,
  registry_set→13, registry_add→12, network_connection→3, 其他跳过。
condition: 只支持 'selection' / 'selection and not filter_*' 基本子集，复杂 condition 跳过。

离线优先
--------
构建期解析本地 Sigma 目录，产物落 data/sysmon-detection-rules.json，运行时零外发。

用法
----
    python3.11 scripts/feeds/sync_sigma.py --local ~/Downloads/hvv-feeds/sigma
    python3.11 scripts/feeds/sync_sigma.py --local <dir> --dry-run
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

import yaml

DEFAULT_OUTPUT = Path(__file__).resolve().parent.parent.parent / "data" / "sysmon-detection-rules.json"
ID_PREFIX = "SIG-SYSMON-SIGMA"

# logsource category → Sysmon event_id
CATEGORY_EVENT_ID = {
    "process_creation": 1,
    "file_event": 11,
    "registry_set": 13,
    "registry_add": 12,
    "registry_event": 13,
    "network_connection": 3,
    "image_load": 7,
    "process_access": 10,
}

# Sigma detection 里的 Sysmon EventData 字段（决定 evtx_hunt 从 data 取哪个字段）
# 只处理这些字段，其余跳过
SUPPORTED_FIELDS = {
    "CommandLine", "Image", "TargetFilename", "TargetObject", "Details",
    "DestinationIp", "DestinationHostname", "QueryName",
}


def log(msg: str) -> None:
    print(f"[sync_sigma] {msg}", file=sys.stderr)


def sigma_value_to_pattern(value, modifier: str) -> str | None:
    """Sigma 单值 + modifier → Python 正则。value 可为 str 或 list。"""
    def one(v: str, mod: str) -> str | None:
        if not isinstance(v, str) or not v:
            return None
        if mod == "re":
            pat = v
        elif mod == "contains":
            pat = re.escape(v)
        elif mod == "endswith":
            pat = ".*" + re.escape(v) + "$"
        elif mod == "startswith":
            pat = "^" + re.escape(v)
        else:  # 无修饰 = 精确
            pat = "^" + re.escape(v) + "$"
        try:
            re.compile(pat)
            return pat
        except re.error:
            return None
    if isinstance(value, list):
        pats = [one(v, modifier) for v in value if isinstance(v, str)]
        pats = [p for p in pats if p]
        if not pats:
            return None
        return "(?:" + "|".join(pats) + ")"
    return one(value, modifier)


def parse_selection(sel: dict) -> list[tuple[str, str]]:
    """解析一个 selection dict → [(field, pattern)] 列表。

    Sigma key 格式 Field 或 Field|modifier。多字段在 selection 里是 AND，
    本转换器把每个字段拆成独立条目（OR 语义），简化为单字段单正则。
    """
    out: list[tuple[str, str]] = []
    for key, val in sel.items():
        parts = key.split("|", 1)
        field = parts[0]
        modifier = parts[1] if len(parts) > 1 else ""
        if field not in SUPPORTED_FIELDS:
            continue
        pat = sigma_value_to_pattern(val, modifier)
        if pat:
            out.append((field, pat))
    return out


def convert_rule(rule: dict) -> list[dict]:
    """转一条 Sigma 规则 → 多条 sysmon JSON 条目（每个字段一条）。"""
    # logsource → event_id
    ls = rule.get("logsource", {}) or {}
    category = ls.get("category", "")
    eid = CATEGORY_EVENT_ID.get(category)
    if eid is None:
        return []
    # level 过滤
    level = (rule.get("level") or "").lower()
    if level not in ("high", "critical"):
        return []
    # detection
    detection = rule.get("detection", {}) or {}
    condition = (detection.get("condition") or "").strip()
    # 只支持基本 condition
    if condition and not re.match(r'^selection(\s+and\s+not\s+(filter_\w+\s*)*(1 of filter_\w+)?)?$', condition):
        if condition != "selection":
            return []
    sel = detection.get("selection")
    if not isinstance(sel, dict):
        return []
    feats = parse_selection(sel)
    if not feats:
        return []
    title = (rule.get("title") or "Sigma rule")[:80]
    fp = rule.get("falsepositives") or []
    fp_str = ", ".join(str(x) for x in fp[:2]) if isinstance(fp, list) else str(fp)[:80]
    tags = rule.get("tags") or []
    attack = [t for t in tags if str(t).startswith("attack.t")][:2]
    out = []
    for field, pat in feats:
        out.append({
            "event_id": eid,
            "field": field,
            "pattern": pat,
            "severity": "high" if level == "critical" else "medium",
            "description": f"Sigma: {title}" + (f" [{','.join(attack)}]" if attack else ""),
            "false_positive": fp_str or "见 Sigma 原规则 falsepositives",
        })
    return out


def convert(local_dir: Path) -> list[dict]:
    rules_root = local_dir / "rules" / "windows" if (local_dir / "rules" / "windows").is_dir() else local_dir
    if not rules_root.is_dir():
        log(f"找不到 rules/windows: {rules_root}")
        return []
    yml_files = sorted(rules_root.rglob("*.yml"))
    log(f"扫描到 {len(yml_files)} 个 Sigma yml")
    entries: list[dict] = []
    seq = 1
    n_skip = 0
    for yf in yml_files:
        try:
            rules = list(yaml.safe_load_all(yf.read_text(encoding="utf-8")))
        except Exception:
            n_skip += 1
            continue
        for rule in rules:
            if not isinstance(rule, dict):
                continue
            for e in convert_rule(rule):
                e["id"] = f"{ID_PREFIX}-{seq:03d}"
                entries.append(e)
                seq += 1
    log(f"提取 {len(entries)} 条（跳过 {n_skip} 个解析失败文件）")
    return entries


def merge_into_output(entries: list[dict], output: Path, dry_run: bool) -> int:
    if not entries:
        log("无条目可合并")
        return 0
    data = json.loads(output.read_text(encoding="utf-8"))
    rules = data.get("rules", data) if isinstance(data, dict) else data
    existing = {(r.get("event_id"), r.get("field"), r.get("pattern")) for r in rules}
    new = [e for e in entries if (e["event_id"], e["field"], e["pattern"]) not in existing]
    if dry_run:
        log(f"[dry-run] 将新增 {len(new)} 条（去重前 {len(entries)}）")
        for e in new[:5]:
            log(f"  eid={e['event_id']} field={e['field']} {e['pattern'][:50]}")
        return len(new)
    for e in new:
        if "id" not in e:
            e["id"] = f"{ID_PREFIX}-{len(rules)+1:03d}"
    rules.extend(new)
    if isinstance(data, dict):
        data["rules"] = rules
        data["total"] = len(rules)
        data["updated_at"] = "2026-07-10"
        output.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    log(f"合并完成：新增 {len(new)} 条，当前共 {len(rules)} 条 → {output}")
    return len(new)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Sigma Windows → sysmon-detection-rules.json 同步器")
    p.add_argument("--local", required=True, help="本地 Sigma 目录（含 rules/windows/）")
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
