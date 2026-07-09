#!/usr/bin/env python3.11
# -*- coding: utf-8 -*-
"""
hvv_common.py — shared helpers for hvv-defender scripts.

定位
----
跨脚本复用的纯函数集合。每个 hvv-defender 检测脚本原本都自包含（为了满足
"单脚本可独立 `python3.11 xxx.py` 运行 + 冷启动零外部依赖"两条硬约束），导致 parse_ts /
iter_ndjson / emit / in_window 等工具函数在 8 个脚本里逐字复制。本模块把这些
重复提炼到一处单点维护。

合规与边界
----------
- 纯 stdlib。不引入任何第三方包（延续无 requirements.txt 设计）。
- 不持有状态、不读 data/、不做网络、不做脱敏。
- 不改变任何脚本的进程边界或 subprocess 管道调用链。

import 可达性
-------------
各脚本顶部用一段幂等 sys.path 引导后即可 import：

    import sys, pathlib
    sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))   # scripts/*.py
    # 或 scripts/remote/*.py 用 .parent.parent
    import hvv_common  # noqa: E402

不设 PYTHONPATH、不 pip install、不加 __init__.py（单文件模块不需要）。
"""
from __future__ import annotations

import datetime as _dt
import json
import os
import sys
from pathlib import Path
from typing import Any, Iterable, Iterator

__all__ = [
    "parse_ts",
    "in_window",
    "iter_ndjson",
    "emit_finding",
    "eprint",
    "now_iso",
    "compact_ts",
    "expand_path",
    "parse_target",
    "append_audit",
]

datetime = _dt.datetime
timezone = _dt.timezone


# ──────────────────────────────────────────────────────────────────────────
# 时间
# ──────────────────────────────────────────────────────────────────────────

def parse_ts(s: Any, *, assume_utc: bool = False) -> datetime | None:
    """Parse an ISO-ish timestamp string into a datetime.

    统一了原散落在 auth_log_audit / nginx_anomaly / timeline_build /
    traffic_anomaly（4 份逐字相同，naive 不补 tz）与 evtx_hunt
    （增强版，naive 补 UTC）两族的实现。

    - 接受 str | datetime | None；空值返回 None。
    - 传入已是 datetime：原样返回（assume_utc 时给 naive 补 UTC）。
    - 字符串：先试 fromisoformat（含 'Z'→'+00:00' 归一），失败则逐个 fallback
      格式 strptime。

    assume_utc=False 时保持原 4 份逐字版的行为：naive datetime 不补时区
    （避免改动 auth/timeline/traffic 的时间比较语义）。evtx_hunt
    的 ISO 解析路径传 assume_utc=True 以保留其"naive 视为 UTC"语义。
    """
    if not s:
        return None
    if isinstance(s, datetime):
        if assume_utc and not s.tzinfo:
            return s.replace(tzinfo=timezone.utc)
        return s
    s = str(s).strip().replace("Z", "+00:00")
    for fmt in (None,
                "%Y-%m-%dT%H:%M:%S.%f",
                "%Y-%m-%dT%H:%M:%S",
                "%Y-%m-%d %H:%M:%S",
                "%m/%d/%Y %H:%M:%S %p",
                "%m/%d/%Y %I:%M:%S %p"):
        try:
            if fmt is None:
                dt = datetime.fromisoformat(s)
            else:
                dt = datetime.strptime(s, fmt)
            if assume_utc and not dt.tzinfo:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except Exception:
            continue
    return None


def in_window(ts: str | None, since: str | None, until: str | None) -> bool:
    """Lexicographic ISO timestamp window filter.

    log_parser / timeline_build 两份逐字相同的实现。naive 字符串比较对
    well-formed ISO 时间戳成立；无法判定时保留记录（返回 True）。
    """
    if since is None and until is None:
        return True
    if not ts:
        return True  # keep if we cannot decide
    try:
        if since and ts < since:
            return False
        if until and ts > until:
            return False
    except Exception:
        return True
    return True


# ──────────────────────────────────────────────────────────────────────────
# NDJSON 流
# ──────────────────────────────────────────────────────────────────────────

def iter_ndjson(
    src: str | Path | Any,
    *,
    log_type: str | Iterable[str] | None = None,
    predicate=None,
) -> Iterator[dict]:
    """Yield parsed JSON objects from an NDJSON stream.

    统一了原散落在 auth_log_audit / nginx_anomaly / timeline_build /
    traffic_anomaly / ioc_match 的 5 份近乎相同的读取器。

    src 可以是：
    - 路径字符串 / Path：打开该文件读取；
    - "-"：从 stdin 读取；
    - 已打开的文件对象：直接迭代（ioc_match 的用法，调用方负责 open/close）。

    log_type：只保留 rec["log_type"] 等于（或在）该值的记录。auth 传
    "linux-auth"；nginx 传 ("nginx-access", "apache-access")。
    predicate：可选的可调用对象 rec -> bool，True 才 yield。nginx 也可用
    predicate 表达多值过滤；traffic 传 predicate=lambda r: r.get("view")。
    log_type 与 predicate 同时给出时两者取交集。
    """
    # 已打开的文件对象：直接用，不负责关闭。
    if hasattr(src, "read") or hasattr(src, "__next__"):
        fh = src
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            if _ndjson_keep(rec, log_type, predicate):
                yield rec
        return

    path = str(src)
    fh = sys.stdin if path == "-" else open(path, "r", encoding="utf-8")
    try:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            if _ndjson_keep(rec, log_type, predicate):
                yield rec
    finally:
        if path != "-":
            fh.close()


def _ndjson_keep(rec: dict, log_type, predicate) -> bool:
    """Shared filter logic for iter_ndjson."""
    if log_type is not None:
        if isinstance(log_type, str):
            if rec.get("log_type") != log_type:
                return False
        else:
            if rec.get("log_type") not in log_type:
                return False
    if predicate is not None:
        try:
            if not predicate(rec):
                return False
        except Exception:
            return False
    return True


# ──────────────────────────────────────────────────────────────────────────
# 8 字段告警构造
# ──────────────────────────────────────────────────────────────────────────

def emit_finding(
    findings: list[dict],
    *,
    id_prefix: str,
    severity: str,
    category: str,
    evidence: dict,
    rule_id: str,
    fp_prob: float,
    action: str,
    iocs: list[dict] | None = None,
    seq: int | None = None,
) -> str:
    """Append a unified 8-field finding to `findings` and return its id.

    统一了 auth_log_audit / nginx_anomaly / evtx_hunt / traffic_anomaly 的
    emit() 骨架（id = f"{PREFIX}-{n:03d}"，n = len(findings)+1），以及
    webshell_scan 的 build_finding()（id 用调用方传入的 seq）。

    各脚本仍自己提供 severity / category / fp_prob / action 的规则查找表
    （那是规则数据，不是重复代码），只把构造 dict 的骨架抽到这里。

    evidence：调用方组装好的证据 dict（不同日志类型字段不同），原样放入。
    seq：可选；给出则用该序号生成 id（webshell 用），否则用 len(findings)+1。
    """
    n = seq if seq is not None else len(findings) + 1
    finding_id = f"{id_prefix}-{n:03d}"
    findings.append({
        "id": finding_id,
        "severity": severity,
        "category": category,
        "evidence": evidence,
        "rule_id": rule_id,
        "false_positive_prob": fp_prob,
        "recommended_action": action,
        "iocs": iocs if iocs is not None else [],
    })
    return finding_id


# ──────────────────────────────────────────────────────────────────────────
# remote 公共工具（remote_collect.py + ssh_probe.py 逐字相同的 6 个函数）
# ──────────────────────────────────────────────────────────────────────────

def eprint(*args, **kwargs) -> None:
    """Print to stderr."""
    print(*args, file=sys.stderr, **kwargs)


def now_iso() -> str:
    """ISO-8601 with local tz offset. Python 3.8-safe."""
    return datetime.now().astimezone().isoformat(timespec="seconds")


def compact_ts() -> str:
    """Compact local timestamp for filenames, e.g. 20260702T185604."""
    return datetime.now().strftime("%Y%m%dT%H%M%S")


def expand_path(p: str) -> str:
    """Expand ~ and make absolute."""
    return os.path.abspath(os.path.expanduser(p))


def parse_target(target: str):
    """Parse 'user@host[:port]' into (user, host, port); None tuple on failure."""
    if "@" not in target:
        return None, None, None
    user, rest = target.split("@", 1)
    if ":" in rest:
        host, port_s = rest.rsplit(":", 1)
        try:
            port = int(port_s)
        except ValueError:
            return None, None, None
        return user, host, port
    return user, rest, None


def append_audit(audit_path: str, record: dict) -> None:
    """Append one JSONL audit record, creating parent dirs as needed."""
    p = Path(expand_path(audit_path))
    p.parent.mkdir(parents=True, exist_ok=True)
    with open(p, "a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False) + "\n")
