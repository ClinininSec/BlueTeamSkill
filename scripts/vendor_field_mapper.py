#!/usr/bin/env python3
"""vendor_field_mapper.py — 国产安全设备告警字段归一化脚本 (hvv-defender skill).

用途: 把 4 家国产安全设备（QAX NGSOC / Sangfor SIP / 长亭 SafeLine WAF / 安恒明御 WAF）
的告警 JSON/CSV 归一化为 hvv-defender skill 的 12 字段标准 schema。

红线: 纯 stdlib / 不做网络调用 / 不做脱敏 (脱敏由 desensitize.py 负责)。

用法:
    python vendor_field_mapper.py --input alerts.json --vendor qax-ngsoc --output out.jsonl
    python vendor_field_mapper.py --self-test
"""
from __future__ import annotations

import argparse
import csv
import io
import json
import os
import re
import sys
from typing import Any

# ---------------- 常量 ----------------

SKILL_FIELDS = [
    "ts", "src_ip", "dst_ip", "dst_port", "proto", "rule_name",
    "severity", "payload", "user_agent", "username", "hostname", "action",
]
SKILL_CATEGORIES = {"webshell", "brute-force", "sqli", "rce", "lateral",
                    "recon", "data-exfil", "其他"}
SKILL_SEVERITIES = {"P0", "P1", "P2", "P3"}
VENDORS = ["qax-ngsoc", "sangfor-sip", "changting-safeline", "dbappsec-mingyu"]
DEFAULT_VENDOR_DIR = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "..", "references", "log-fields",
)

# 通用 category 字段别名（用于 category 反查）
CATEGORY_ALIASES = ["category", "attack_type", "event_type", "threat_type",
                    "event_category", "attack_type_name"]


# ---------------- 极简 frontmatter YAML 解析 ----------------

def _strip_quotes(v: str) -> str:
    v = v.strip()
    if len(v) >= 2 and v[0] == v[-1] and v[0] in ('"', "'"):
        return v[1:-1]
    return v


def _parse_scalar(v: str) -> Any:
    """把 'foo' / '"bar"' / '123' / '' 转成合适的 Python 值."""
    v = v.strip()
    if v == "":
        return None
    if len(v) >= 2 and v[0] == v[-1] and v[0] in ('"', "'"):
        return v[1:-1]
    if re.match(r"^-?\d+$", v):
        try:
            return int(v)
        except ValueError:
            return v
    return v


def _parse_inline_list(v: str) -> list:
    """解析 [a, b, c] 行内列表."""
    v = v.strip()
    if not (v.startswith("[") and v.endswith("]")):
        return [v]
    inner = v[1:-1].strip()
    if not inner:
        return []
    return [_strip_quotes(p) for p in inner.split(",") if p.strip()]


def parse_frontmatter(md_text: str) -> dict:
    """极简 YAML frontmatter 解析器, 支持 key: scalar / key: [inline_list] /
    key:\\n  nested_key: v (2-space indent) / key:\\n  - list_item.
    仅支持本 skill vendor md 用到的极简子集."""
    m = re.match(r"^---\s*\n(.*?)\n---\s*\n", md_text, re.DOTALL)
    if not m:
        raise ValueError("no frontmatter found (missing leading `---` block)")
    body = m.group(1)
    root: dict = {}
    stack: list[tuple[int, Any]] = [(0, root)]
    current_key: str | None = None

    for raw in body.split("\n"):
        line = raw.rstrip()
        if not line.strip() or line.strip().startswith("#"):
            continue
        indent = len(line) - len(line.lstrip(" "))
        stripped = line.strip()

        while stack and stack[-1][0] > indent:
            stack.pop()
        _, container = stack[-1]

        # 缩进列表项
        if stripped.startswith("- "):
            item_val = _parse_scalar(stripped[2:].strip())
            if isinstance(container, list):
                container.append(item_val)
            else:
                if current_key is None:
                    continue
                if not isinstance(container.get(current_key), list):
                    container[current_key] = []
                container[current_key].append(item_val)
                if stack[-1][1] is not container[current_key]:
                    stack.append((indent, container[current_key]))
            continue

        # key: value
        if ":" in stripped:
            key, _, val = stripped.partition(":")
            key, val = key.strip(), val.strip()
            while stack and isinstance(stack[-1][1], list):
                stack.pop()
            _, container = stack[-1]

            if val == "":
                container[key] = {}
                stack.append((indent + 2, container[key]))
                current_key = key
            elif val.startswith("["):
                container[key] = _parse_inline_list(val)
                current_key = key
            else:
                container[key] = _parse_scalar(val)
                current_key = key

    return root


def load_vendor_config(vendor: str, vendor_dir: str) -> dict:
    md_path = os.path.join(vendor_dir, f"vendor-{vendor}.md")
    if not os.path.isfile(md_path):
        raise FileNotFoundError(f"vendor md not found: {md_path}")
    with open(md_path, encoding="utf-8") as f:
        text = f.read()
    fm = parse_frontmatter(text)
    for req in ("vendor_name", "field_map", "severity_map", "category_map"):
        if req not in fm:
            raise ValueError(f"vendor md {md_path} missing frontmatter key: {req}")
    return fm


# ---------------- 输入解析 ----------------

def load_input(path: str) -> list[dict]:
    """支持 json 数组 / ndjson / csv / 带 data/result 包裹层的 json object 四种."""
    with open(path, "rb") as f:
        raw = f.read()
    text = raw.decode("utf-8-sig", errors="replace")
    lower = path.lower()

    if lower.endswith(".csv"):
        reader = csv.DictReader(io.StringIO(text))
        return [dict(row) for row in reader]

    stripped = text.lstrip()
    if stripped.startswith("["):
        try:
            data = json.loads(text)
            if isinstance(data, list):
                return [d for d in data if isinstance(d, dict)]
        except json.JSONDecodeError:
            pass
    if stripped.startswith("{"):
        try:
            obj = json.loads(text)
            for key in ("data", "result", "records", "alerts", "items"):
                if isinstance(obj.get(key), list):
                    return [d for d in obj[key] if isinstance(d, dict)]
            return [obj]
        except json.JSONDecodeError:
            pass

    # ndjson fallback
    records = []
    for ln in text.splitlines():
        ln = ln.strip()
        if not ln:
            continue
        try:
            obj = json.loads(ln)
            if isinstance(obj, dict):
                records.append(obj)
        except json.JSONDecodeError:
            continue
    return records


# ---------------- 归一化 ----------------

def _lookup_alias(record: dict, aliases: list[str]) -> Any:
    """按 aliases 顺序在 record 里找第一个非空值 (含大小写不敏感 fallback)."""
    if not aliases:
        return None
    for a in aliases:
        if a in record and record[a] not in (None, ""):
            return record[a]
        for k, v in record.items():
            if k.lower() == str(a).lower() and v not in (None, ""):
                return v
    return None


def _map_severity(raw_sev: Any, sev_map: dict) -> str | None:
    if raw_sev in (None, ""):
        return None
    key = str(raw_sev).strip()
    if key in sev_map:
        return sev_map[key]
    for k, v in sev_map.items():
        if str(k).lower() == key.lower():
            return v
    try:
        num = int(float(key))
        if num in sev_map:
            return sev_map[num]
        if str(num) in sev_map:
            return sev_map[str(num)]
    except (ValueError, TypeError):
        pass
    return None


def _map_category(raw_rule: Any, raw_cat: Any, cat_map: dict) -> str:
    candidates = [str(c).strip() for c in (raw_cat, raw_rule) if c not in (None, "")]
    for k, v in cat_map.items():
        for cand in candidates:
            if k == cand or k in cand:
                return v
    return "其他"


def normalize_record(record: dict, vendor_cfg: dict, strict: bool
                     ) -> tuple[dict | None, str | None]:
    """把一条厂商原始告警归一化为 skill 标准 alert."""
    field_map = vendor_cfg.get("field_map", {})
    sev_map = vendor_cfg.get("severity_map", {})
    cat_map = vendor_cfg.get("category_map", {})

    out: dict = {}
    for fld in SKILL_FIELDS:
        aliases = field_map.get(fld) or []
        if not isinstance(aliases, list):
            aliases = [aliases]
        out[fld] = _lookup_alias(record, aliases)

    if out["ts"] in (None, ""):
        return None, "missing ts"

    raw_sev = out["severity"]
    mapped_sev = _map_severity(raw_sev, sev_map) if sev_map else None
    if strict and mapped_sev is None and raw_sev not in (None, ""):
        return None, f"unknown severity: {raw_sev}"
    out["severity"] = mapped_sev or "P2"

    raw_cat = _lookup_alias(record, CATEGORY_ALIASES)
    out["category"] = _map_category(out.get("rule_name"), raw_cat, cat_map)
    out["vendor"] = vendor_cfg.get("vendor_name", "unknown")
    out["_raw_keys"] = sorted(record.keys())

    return out, None


# ---------------- self-test ----------------

SELF_TEST_SAMPLES = {
    "qax-ngsoc": {
        "detect_time": "2026-06-30 08:14:23", "attacker_ip": "203.0.113.50",
        "victim_ip": "192.168.1.100", "dst_port": 443, "attack_type": "SQL注入",
        "risk_level": "高危", "signature": "sqlmap detected",
        "user_agent": "sqlmap/1.7", "action": "block"},
    "sangfor-sip": {
        "alarm_time": "2026-06-30 09:22:11", "atk_src_ip": "198.51.100.10",
        "atk_dst_ip": "10.0.1.50", "dst_port": 8080, "protocol": "http",
        "event_name": "Fastjson利用", "threat_level": "高危",
        "packet_content": "@type:com.sun.rowset.JdbcRowSetImpl",
        "disposal": "blocked"},
    "changting-safeline": {
        "event_time": "2026-06-30T10:00:00+08:00", "client_ip": "203.0.113.99",
        "upstream_addr": "10.1.2.3:443", "server_port": 443, "scheme": "https",
        "attack_type": "命令执行", "risk_level": "high",
        "raw_request": "GET /?cmd=id", "user_agent": "curl/8.0",
        "host": "web.example.com", "action": "block"},
    "dbappsec-mingyu": {
        "attack_time": "2026-06-30 11:11:11", "attack_source_ip": "203.0.113.7",
        "target_ip": "10.10.10.10", "target_port": 80,
        "attack_type_name": "WebShell上传", "threat_level": "致命",
        "attack_content": "POST /upload/x.jsp",
        "protected_host": "shop.example.com", "disposal": "拦截"},
}
SELF_TEST_EXPECTED = {
    "qax-ngsoc": {"src_ip": "203.0.113.50", "category": "sqli", "severity": "P1"},
    "sangfor-sip": {"src_ip": "198.51.100.10", "category": "rce", "severity": "P0"},
    "changting-safeline": {"src_ip": "203.0.113.99", "category": "rce", "severity": "P1"},
    "dbappsec-mingyu": {"src_ip": "203.0.113.7", "category": "webshell", "severity": "P0"},
}


def run_self_test(vendor_dir: str) -> int:
    passed, failed = 0, 0
    print("=== vendor_field_mapper self-test ===")
    for vendor, sample in SELF_TEST_SAMPLES.items():
        try:
            cfg = load_vendor_config(vendor, vendor_dir)
        except (FileNotFoundError, ValueError) as e:
            print(f"[FAIL] {vendor}: cannot load vendor config: {e}")
            failed += 1
            continue
        out, err = normalize_record(sample, cfg, strict=False)
        if err or out is None:
            print(f"[FAIL] {vendor}: normalize error: {err}")
            failed += 1
            continue
        expect = SELF_TEST_EXPECTED[vendor]
        mismatch = [f"{k}: got {out.get(k)!r}, expect {v!r}"
                    for k, v in expect.items() if out.get(k) != v]
        if mismatch:
            print(f"[FAIL] {vendor}: {'; '.join(mismatch)}")
            failed += 1
        else:
            print(f"[PASS] {vendor}: ts={out.get('ts')} src_ip={out.get('src_ip')} "
                  f"category={out.get('category')} severity={out.get('severity')}")
            passed += 1
    print(f"--- self-test result: {passed}/{passed + failed} PASS ---")
    return 0 if failed == 0 else 1


# ---------------- CLI ----------------

def build_argparser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="vendor_field_mapper.py",
        description="Normalize vendor alert JSON/CSV into hvv-defender skill "
                    "standard schema. Supported vendors: " + ", ".join(VENDORS),
    )
    p.add_argument("--input", help="input file (json array / ndjson / csv)")
    p.add_argument("--vendor", choices=VENDORS, help="vendor key")
    p.add_argument("--output", help="output NDJSON path (default: stdout)")
    p.add_argument("--vendor-dir", default=DEFAULT_VENDOR_DIR,
                   help="directory of vendor-*.md files")
    p.add_argument("--strict", action="store_true",
                   help="strict mode: fail on missing fields / unmapped severity")
    p.add_argument("--self-test", action="store_true",
                   help="run built-in self-test (embedded samples, no input needed)")
    return p


def main(argv: list[str]) -> int:
    args = build_argparser().parse_args(argv)

    if args.self_test:
        return run_self_test(args.vendor_dir)

    if not args.input or not args.vendor:
        print("error: --input and --vendor are required (or use --self-test)",
              file=sys.stderr)
        return 2

    try:
        cfg = load_vendor_config(args.vendor, args.vendor_dir)
        records = load_input(args.input)
    except (OSError, ValueError, FileNotFoundError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 2

    if not records:
        print("warning: no records loaded from input", file=sys.stderr)

    out_stream = open(args.output, "w", encoding="utf-8") if args.output else sys.stdout
    ok, skipped = 0, 0
    skip_reasons: dict[str, int] = {}
    try:
        for rec in records:
            norm, err = normalize_record(rec, cfg, strict=args.strict)
            if err or norm is None:
                skipped += 1
                skip_reasons[err or "unknown"] = skip_reasons.get(err or "unknown", 0) + 1
                if args.strict:
                    print(f"error: strict mode abort: {err}", file=sys.stderr)
                    return 2
                continue
            out_stream.write(json.dumps(norm, ensure_ascii=False) + "\n")
            ok += 1
    finally:
        if args.output:
            out_stream.close()

    print(f"[vendor_field_mapper] vendor={args.vendor} ok={ok} skipped={skipped}",
          file=sys.stderr)
    if skip_reasons:
        print(f"[vendor_field_mapper] skip reasons: {skip_reasons}", file=sys.stderr)
    return 0 if skipped == 0 else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
