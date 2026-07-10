#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
traffic_anomaly.py — Rule engine for pcap-derived NDJSON.

Consumes the NDJSON produced by pcap_parser.py and emits 8-field findings
for 19 rules (R-TRAF-001 .. R-TRAF-203), plus R-TRAF-999 correlation cluster.

Rule catalogue
--------------
Group A - foundational (12):
  R-TRAF-001  Scanner UA hits (sqlmap/nuclei/xray/awvs/...)             P2
  R-TRAF-002  Sensitive HTTP path (.git/.env/actuator/swagger/...)      P2
  R-TRAF-003  SQLi trigger strings in URI                               P1
  R-TRAF-004  RCE trigger strings (jndi/fastjson/@type/passwd/...)      P0
  R-TRAF-005  DGA-like DNS qname (length + entropy + rate)              P1
  R-TRAF-006  DNSCAT2 / iodine tunneling (long qname + TXT high-freq)   P0
  R-TRAF-007  Malicious TLS SNI / cert CN (traffic-signatures c2)       P1
  R-TRAF-008  Reverse-shell listener ports + long outbound conn         P0
  R-TRAF-009  Cleartext credentials (basic auth / ftp / telnet)         P2
  R-TRAF-010  Large outbound stream (bytes_a2b>50MB, duration>60s)      P1
  R-TRAF-011  C2 heartbeat pattern (many small packets, long duration)  P1
  R-TRAF-012  Webshell key markers (godzilla/behinder/antsword)         P0

Group B - Windows lateral (4):
  R-TRAF-101  SMB named-pipe lateral (svcctl/lsass/samr)                P1
  R-TRAF-102  PsExec/WMIExec pipe markers (PSEXECSVC/TSVCPIPE)          P0
  R-TRAF-103  RDP fan-in scan (>5 src_ips to one dst on 3389)           P1
  R-TRAF-104  WMI DCOM lateral (IWbemLevel1Login)                       P1

Group C - tunneling tools (3):
  R-TRAF-201  frp/frps heartbeat (default ports + empty SNI)            P1
  R-TRAF-202  nps/npc magic-byte handshake                              P1
  R-TRAF-203  chisel/gost HTTP CONNECT + long-lived tunnel              P1

Correlation:
  R-TRAF-999  Same src_ip triggers >=3 distinct rule_ids                escalate

Red lines:
  - Offline only. pcap files must be provided by user; no live capture.
  - No stream reassembly, no full-body capture, only headers + strings.
  - Passwords / secrets are masked as "***<len>" before emit.
  - No outbound network calls to threat-intel APIs.
  - Detection features only; NO reproducible attack payloads.

Example
-------
  pcap_parser.py --input a.pcap | traffic_anomaly.py --input -
  traffic_anomaly.py --input flows.ndjson --output findings.json -v
"""
from __future__ import annotations

import argparse
import json
import math
import re
import sys
from collections import Counter, defaultdict, deque
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Iterator

# Shared helpers (pure stdlib). sys.path bootstrap keeps the script runnable
# standalone as `python3 scripts/traffic_anomaly.py` without PYTHONPATH/pip.
sys.path.insert(0, str(Path(__file__).resolve().parent))
import hvv_common as _hc  # noqa: E402

# --------------------------------------------------------------------------- #
# Rule metadata                                                               #
# --------------------------------------------------------------------------- #

SEVERITY = {
    "R-TRAF-001": "P2", "R-TRAF-002": "P2", "R-TRAF-003": "P1",
    "R-TRAF-004": "P0", "R-TRAF-005": "P1", "R-TRAF-006": "P0",
    "R-TRAF-007": "P1", "R-TRAF-008": "P0", "R-TRAF-009": "P2",
    "R-TRAF-010": "P1", "R-TRAF-011": "P1", "R-TRAF-012": "P0",
    "R-TRAF-101": "P1", "R-TRAF-102": "P0", "R-TRAF-103": "P1",
    "R-TRAF-104": "P1",
    "R-TRAF-201": "P1", "R-TRAF-202": "P1", "R-TRAF-203": "P1",
    "R-TRAF-999": "P0",
}

CATEGORY = {
    "R-TRAF-001": "recon", "R-TRAF-002": "recon", "R-TRAF-003": "sqli",
    "R-TRAF-004": "rce", "R-TRAF-005": "c2", "R-TRAF-006": "c2",
    "R-TRAF-007": "c2", "R-TRAF-008": "c2", "R-TRAF-009": "brute-force",
    "R-TRAF-010": "data-exfil", "R-TRAF-011": "c2", "R-TRAF-012": "webshell",
    "R-TRAF-101": "lateral", "R-TRAF-102": "lateral", "R-TRAF-103": "lateral",
    "R-TRAF-104": "lateral",
    "R-TRAF-201": "tunnel", "R-TRAF-202": "tunnel", "R-TRAF-203": "tunnel",
    "R-TRAF-999": "c2",
}

FP_PROB = {
    "R-TRAF-001": 0.10, "R-TRAF-002": 0.30, "R-TRAF-003": 0.10,
    "R-TRAF-004": 0.05, "R-TRAF-005": 0.30, "R-TRAF-006": 0.10,
    "R-TRAF-007": 0.20, "R-TRAF-008": 0.15, "R-TRAF-009": 0.20,
    "R-TRAF-010": 0.35, "R-TRAF-011": 0.30, "R-TRAF-012": 0.05,
    "R-TRAF-101": 0.30, "R-TRAF-102": 0.10, "R-TRAF-103": 0.25,
    "R-TRAF-104": 0.25,
    "R-TRAF-201": 0.30, "R-TRAF-202": 0.35, "R-TRAF-203": 0.35,
    "R-TRAF-999": 0.10,
}

ACTION = {
    "R-TRAF-001": "封禁扫描器源 IP；对该 IP 拉全量行为时间线；启用 WAF 规则",
    "R-TRAF-002": "下线敏感路径 / 加访问控制；审计是否已发生泄露",
    "R-TRAF-003": "确认接口是否参数化；快照 DB 状态；封禁源 IP",
    "R-TRAF-004": "立即切 ir 模式；隔离目标机；查 JVM 外联与进程；参考 playbook/rce",
    "R-TRAF-005": "结合被查询域名情报评估；封禁 recursive resolver 出站; 参考 playbook/c2",
    "R-TRAF-006": "断开 DNS 出站；抓取受影响主机进程；参考 playbook/c2",
    "R-TRAF-007": "封禁 TLS 目的 IP / 添加 SNI/CN 黑名单",
    "R-TRAF-008": "隔离主机、抓 rss 内存、查 crontab/service；参考 playbook/rce",
    "R-TRAF-009": "强制切换到加密协议；重置涉事账户口令",
    "R-TRAF-010": "审计外发目的地是否白名单；确认业务是否有大流量场景",
    "R-TRAF-011": "结合外联域名情报，进入 ir 取证；参考 playbook/c2",
    "R-TRAF-012": "立即切 ir 模式；参考 playbook/webshell",
    "R-TRAF-101": "对 SMB 445 出/入方向做主机策略；核查目标机是否非管理员登录",
    "R-TRAF-102": "立即 ir；参考 playbook/lateral；查 SCM 服务日志",
    "R-TRAF-103": "对 RDP 3389 加双因素 / IP 白名单；查失败登录日志",
    "R-TRAF-104": "查看 WMI 消费者持久化项 (Get-WmiObject); 参考 playbook/lateral",
    "R-TRAF-201": "封禁 frp 服务器 IP；查客户端进程",
    "R-TRAF-202": "封禁 nps 服务器 IP；查客户端进程",
    "R-TRAF-203": "封禁 chisel 目的；查主机 outbound proxy 配置",
    "R-TRAF-999": "关联多规则命中的 IP 视为主要 IOC，立即进入 ir",
}

# === R-TRAF-050~098 (v0.3-M1) ================================================
# TLS deepening (050-069) / DNS tunneling deep heuristics (070-084) /
# CN red-team tool fingerprints (085-098).
# Existing rules above are NOT modified; new rules are appended via .update()
# on the shared metadata dicts and via a second-pass detect_v03_m1_extra().
# =============================================================================

SEVERITY.update({
    "R-TRAF-050": "P0", "R-TRAF-051": "P0", "R-TRAF-052": "P1",
    "R-TRAF-053": "P1", "R-TRAF-054": "P1", "R-TRAF-055": "P2",
    "R-TRAF-056": "P2", "R-TRAF-057": "P1", "R-TRAF-058": "P2",
    "R-TRAF-059": "P1", "R-TRAF-060": "P3", "R-TRAF-061": "P3",
    "R-TRAF-062": "P3", "R-TRAF-063": "P3", "R-TRAF-064": "P2",
    "R-TRAF-065": "P3", "R-TRAF-066": "P3", "R-TRAF-067": "P2",
    "R-TRAF-068": "P3", "R-TRAF-069": "P2",
    "R-TRAF-070": "P1", "R-TRAF-071": "P1", "R-TRAF-072": "P1",
    "R-TRAF-073": "P0", "R-TRAF-074": "P0", "R-TRAF-075": "P2",
    "R-TRAF-076": "P1", "R-TRAF-077": "P2", "R-TRAF-078": "P0",
    "R-TRAF-079": "P2", "R-TRAF-080": "P2", "R-TRAF-081": "P1",
    "R-TRAF-082": "P2", "R-TRAF-083": "P3", "R-TRAF-084": "P2",
    "R-TRAF-085": "P0", "R-TRAF-086": "P0", "R-TRAF-087": "P1",
    "R-TRAF-088": "P1", "R-TRAF-089": "P0", "R-TRAF-090": "P1",
    "R-TRAF-091": "P2", "R-TRAF-092": "P2", "R-TRAF-093": "P2",
    "R-TRAF-094": "P2", "R-TRAF-095": "P0", "R-TRAF-096": "P0",
    "R-TRAF-097": "P1", "R-TRAF-098": "P1",
})

CATEGORY.update({
    "R-TRAF-050": "c2",     "R-TRAF-051": "c2",     "R-TRAF-052": "c2",
    "R-TRAF-053": "c2",     "R-TRAF-054": "c2",     "R-TRAF-055": "c2",
    "R-TRAF-056": "c2",     "R-TRAF-057": "c2",     "R-TRAF-058": "c2",
    "R-TRAF-059": "c2",     "R-TRAF-060": "recon",  "R-TRAF-061": "recon",
    "R-TRAF-062": "recon",  "R-TRAF-063": "recon",  "R-TRAF-064": "c2",
    "R-TRAF-065": "recon",  "R-TRAF-066": "recon",  "R-TRAF-067": "recon",
    "R-TRAF-068": "recon",  "R-TRAF-069": "c2",
    "R-TRAF-070": "c2",     "R-TRAF-071": "c2",     "R-TRAF-072": "c2",
    "R-TRAF-073": "c2",     "R-TRAF-074": "c2",     "R-TRAF-075": "c2",
    "R-TRAF-076": "c2",     "R-TRAF-077": "recon",  "R-TRAF-078": "c2",
    "R-TRAF-079": "c2",     "R-TRAF-080": "c2",     "R-TRAF-081": "c2",
    "R-TRAF-082": "c2",     "R-TRAF-083": "c2",     "R-TRAF-084": "c2",
    "R-TRAF-085": "webshell", "R-TRAF-086": "webshell", "R-TRAF-087": "webshell",
    "R-TRAF-088": "webshell", "R-TRAF-089": "c2",     "R-TRAF-090": "recon",
    "R-TRAF-091": "recon",  "R-TRAF-092": "recon",  "R-TRAF-093": "recon",
    "R-TRAF-094": "recon",  "R-TRAF-095": "tunnel", "R-TRAF-096": "tunnel",
    "R-TRAF-097": "brute-force", "R-TRAF-098": "c2",
})

FP_PROB.update({
    "R-TRAF-050": 0.10, "R-TRAF-051": 0.10, "R-TRAF-052": 0.20,
    "R-TRAF-053": 0.25, "R-TRAF-054": 0.15, "R-TRAF-055": 0.35,
    "R-TRAF-056": 0.40, "R-TRAF-057": 0.15, "R-TRAF-058": 0.40,
    "R-TRAF-059": 0.20, "R-TRAF-060": 0.50, "R-TRAF-061": 0.50,
    "R-TRAF-062": 0.60, "R-TRAF-063": 0.50, "R-TRAF-064": 0.30,
    "R-TRAF-065": 0.50, "R-TRAF-066": 0.50, "R-TRAF-067": 0.35,
    "R-TRAF-068": 0.50, "R-TRAF-069": 0.30,
    "R-TRAF-070": 0.20, "R-TRAF-071": 0.25, "R-TRAF-072": 0.20,
    "R-TRAF-073": 0.15, "R-TRAF-074": 0.05, "R-TRAF-075": 0.40,
    "R-TRAF-076": 0.20, "R-TRAF-077": 0.35, "R-TRAF-078": 0.10,
    "R-TRAF-079": 0.35, "R-TRAF-080": 0.35, "R-TRAF-081": 0.30,
    "R-TRAF-082": 0.40, "R-TRAF-083": 0.50, "R-TRAF-084": 0.30,
    "R-TRAF-085": 0.05, "R-TRAF-086": 0.05, "R-TRAF-087": 0.10,
    "R-TRAF-088": 0.15, "R-TRAF-089": 0.15, "R-TRAF-090": 0.20,
    "R-TRAF-091": 0.20, "R-TRAF-092": 0.25, "R-TRAF-093": 0.25,
    "R-TRAF-094": 0.20, "R-TRAF-095": 0.10, "R-TRAF-096": 0.10,
    "R-TRAF-097": 0.25, "R-TRAF-098": 0.35,
})

ACTION.update({
    "R-TRAF-050": "封禁目的 IP；导出 TLS 流做 JA3 复核；参考 playbook/c2",
    "R-TRAF-051": "封禁目的 IP；核查主机内存有无 Sliver/Havoc/BRC4 loader",
    "R-TRAF-052": "结合国密业务白名单核验；非国密链路命中即视为高置信 C2",
    "R-TRAF-053": "对该会话做全链路解密复核；域前置攻击应立即断开",
    "R-TRAF-054": "封禁目的 IP；检查主机 rss 内存有无默认 profile 载荷",
    "R-TRAF-055": "结合流量心跳评估；空 SNI 结合出方向长连接置信度显著提升",
    "R-TRAF-056": "对照业务国密白名单；未声明国密业务出现即告警",
    "R-TRAF-057": "短命自签证书 = C2 强证据，立即封禁 + 主机 ir",
    "R-TRAF-058": "结合 UA/请求内容复核，可能是伪装 h2 的 h1 客户端",
    "R-TRAF-059": "内网私域 SNI 出公网 = 数据/隧道泄露，立即封禁",
    "R-TRAF-060": "低置信调优项：加入白名单或结合业务链路核查",
    "R-TRAF-061": "低置信调优项，通常需结合其他 TLS 特征使用",
    "R-TRAF-062": "ECH 出现在企业网罕见，需结合业务是否启用做判断",
    "R-TRAF-063": "0 extension 通常来自自研工具，需重点关注",
    "R-TRAF-064": "SNI 是 IP = 非常规客户端；结合 UA、目的地评估",
    "R-TRAF-065": "单密码套件通常来自定制客户端，需列入观察名单",
    "R-TRAF-066": "TLS 会话恢复异常，通常是抓包不全或攻击工具",
    "R-TRAF-067": "同 src 大量握手失败 = 证书轮换攻击 / 扫描",
    "R-TRAF-068": "浏览器 UA 但 ALPN 缺失，需结合 JA3 复核",
    "R-TRAF-069": "SNI + ALPN 均空 = 无头工具默认特征",
    "R-TRAF-070": "确认源主机是否 DNS 隧道客户端；断 DNS 出站",
    "R-TRAF-071": "结合工具情报核查；高熵长 qname = 编码痕迹",
    "R-TRAF-072": "父域子域爆炸 = DGA 或隧道；封禁父域出站",
    "R-TRAF-073": "TXT 占比高 = dnscat2 / iodine 强证据；进入 ir",
    "R-TRAF-074": "NULL 查询是 iodine 特征；进入 ir 模式",
    "R-TRAF-075": "UDP/53 payload 大小异常，结合子域名长度综合评估",
    "R-TRAF-076": "base32/64 编码痕迹 + 长 qname = 高置信隧道",
    "R-TRAF-077": "NXDOMAIN 爆发 = DGA 探测或 typo，需分诊",
    "R-TRAF-078": "CS DNS beacon 强特征；立即封禁目的域",
    "R-TRAF-079": "非白名单 DoH/DoT 出站 = DNS 隐私逃逸；封禁",
    "R-TRAF-080": "n-gram DGA 特征；结合家族情报做归属",
    "R-TRAF-081": "beacon 心跳强证据；进入 ir 抓包与主机分析",
    "R-TRAF-082": "DNS 响应远大于查询 = 反向隧道；封禁并溯源",
    "R-TRAF-083": "TTL 异常，参考 DNS TTL 调优白名单",
    "R-TRAF-084": "重复 qname 高频 = 心跳或探测；结合响应内容",
    "R-TRAF-085": "冰蝎强特征；进入 ir 参考 playbook/webshell",
    "R-TRAF-086": "哥斯拉强特征；进入 ir 参考 playbook/webshell",
    "R-TRAF-087": "蚁剑高置信；封禁源 IP + 主机 ir",
    "R-TRAF-088": "灵蜥高置信；主机 ir + 检查 webshell 落地",
    "R-TRAF-089": "Viper C2 强特征；进入 ir 参考 playbook/c2",
    "R-TRAF-090": "fscan 内网扫描；确认是否护网蓝队授权",
    "R-TRAF-091": "goby 扫描；确认授权",
    "R-TRAF-092": "xray 扫描；确认授权",
    "R-TRAF-093": "nuclei 扫描；确认授权",
    "R-TRAF-094": "Yakit 平台流量；结合业务方是否使用",
    "R-TRAF-095": "suo5 内网穿透 = 高置信隧道；立即封禁 + 主机 ir",
    "R-TRAF-096": "neo-regeorg / reGeorg = 高置信 webshell 隧道；进入 ir",
    "R-TRAF-097": "弱口令暴破；封禁源 IP + 强制账户锁定",
    "R-TRAF-098": "免杀 loader 心跳嫌疑；结合主机进程综合分析",
})

# --------------------------------------------------------------------------- #
# Regex patterns                                                              #
# --------------------------------------------------------------------------- #

SCANNER_UA_RX = re.compile(
    r"(?i)(sqlmap|nuclei|\bxray\b|acunetix|AWVS|nessus|nikto|dirsearch|"
    r"wpscan|fscan|masscan|nmap|pocsuite|afrog|wfuzz|\bffuf\b|hydra|"
    r"gobuster|feroxbuster|zgrab|BurpCollaborator|Burp Suite|"
    r"antSword|antsword)"
)

SENSITIVE_PATH_RX = re.compile(
    r"(?i)/(\.git(/|$)|\.env(\.|$|/|\?)|wp-admin|wp-login|actuator(/|$)|"
    r"swagger|phpinfo\.php|phpmyadmin|console/login|manager/html|"
    r"jmx-console|web-console|\.ssh/|/etc/passwd)"
)

SQLI_RX = re.compile(
    r"(?i)(\bunion\s+(?:all\s+)?select\b|\bsleep\(\s*\d+\s*\)|"
    r"\bbenchmark\(\s*\d+|'\s*or\s*'?1'?\s*=\s*'?1|"
    r"\"\s*or\s*\"?1\"?\s*=\s*\"?1|"
    r"\bextractvalue\b|\bupdatexml\b|information_schema)"
)

RCE_RX = re.compile(
    r"(?i)(\$\{jndi:|Runtime\.getRuntime|java\.lang\.Runtime|ProcessBuilder|"
    r"@type[\"']?\s*:\s*[\"']?com\.|TemplatesImpl|fastjson|"
    r"cmd\.exe|/bin/(?:sh|bash)\b|/etc/passwd|/proc/self|"
    r"[?&](?:cmd|exec|command|c)=(?:cat|ls|whoami|id|uname|wget|curl|nc|bash|sh)\b|"
    r"\(\)\s*\{\s*:;\s*\})"
)

WEBSHELL_KEY_RX = re.compile(
    r"(3c6e0b8a9c15224a|e45e329feb5d925b|antSword|antsword|"
    r"pass=@eval|pass=@assert|/(?:shell|c99|r57|wso|b374k)\.(?:php|jsp|aspx))",
    re.IGNORECASE,
)

REV_SHELL_PORTS = {4444, 1337, 8888, 13337, 6666, 7777, 31337}

SMB_LATERAL_PIPE_RX = re.compile(
    r"(?i)(\\\\PIPE\\\\svcctl|\\\\PIPE\\\\lsass|\\\\PIPE\\\\samr|"
    r"\\\\PIPE\\\\atsvc|\\\\PIPE\\\\winreg)"
)

PSEXEC_RX = re.compile(
    r"(?i)(PSEXECSVC|winexesvc|WINEXESVC|TSVCPIPE)"
)

WMI_RX = re.compile(r"(?i)(IWbemLevel1Login|IWbemServices)")

FRP_MAGIC_RX = re.compile(r"^\x00{4}[\x01-\x0f]")

NPS_MAGIC_RX = re.compile(r"^(\x00\x00\x00[\x0a\x14])")


# === R-TRAF-050~098 (v0.3-M1) regexes & tables ===============================
# JA3 / JA3S fingerprint tables — 2023-2025 public research values.
# Sources: SalesForce ja3 repo, TrickyTLS, TrisulNSM, various IR blogs.
# These MUST be re-validated with fresh IR samples per engagement.
KNOWN_JA3_C2 = {
    # CobaltStrike default profiles (Java keytool 4.x/5.x)
    "72a589da586844d7f0818ce684948eea": ("cobalt-strike", "P0"),
    "a0e9f5d64349fb13191bc781f81f42e1": ("cobalt-strike-4x", "P0"),
    "8916410db85077a5460817142dcbc8bc": ("cobalt-strike-tls13", "P0"),
    # Sliver mTLS default
    "80215ceceabc84f78e10c14e0932abfd": ("sliver", "P0"),
    "b32309a26951912be7dba376398abc3b": ("sliver-mtls", "P0"),
    # Mythic (Apfell / Poseidon)
    "d9d99a03093874c9f309b7f2f052ffa1": ("mythic", "P1"),
    # Havoc default agent
    "3fed133de60c35724739b913924b6c24": ("havoc", "P0"),
    # Brute Ratel C4
    "0a3d5f30f81f79e46f682dc98354c1c1": ("brute-ratel", "P0"),
    # Metasploit meterpreter reverse_https
    "3b5074b1b5d032e5620f69f9f700ff0e": ("metasploit", "P1"),
    # Merlin C2
    "6e9b0f7fd66a37b0aeecda0d4b40b1e5": ("merlin", "P1"),
}

KNOWN_JA3S_C2 = {
    # CS teamserver defaults
    "b742b407517bac9536a77a7b0fee28e9": ("cobalt-strike-server", "P0"),
    "ec74a5c51106f0419184d0dd08fb05bc": ("cobalt-strike-cn-mod", "P0"),
    # Sliver server
    "f4febc55ea12b31ae17cfb7e614afda8": ("sliver-server", "P0"),
    # Havoc teamserver
    "5c1a3d5eaa5e78d5c85a2f8b5b6d3e2a": ("havoc-server", "P0"),
}

# Default self-signed CN/O values for red-team C2 frameworks
C2_CERT_CN_RX = re.compile(
    r"(?i)^(?:Major Cobalt Strike|Cobalt Strike|multiplayer|"
    r"Sliver|cloudflare-inc|HavocFramework|BRC4|localhost\.localdomain|"
    r"OperatorFoundation|Mythic C2)$"
)

# GM (国密) TLS ciphersuites — SM2 / SM3 / SM4 identifiers.
GM_CIPHER_RX = re.compile(
    r"(?i)(SM2|SM3|SM4|ECC-SM2|ECDHE-SM2|GM-.*|"
    r"0x00c6|0x00c7|0xe011|0xe013|0xe019|0xe051|0xe053|0xe055|0xe057)"
)

# GREASE (RFC 8701) values.
_GREASE_VALS = {"0a0a", "1a1a", "2a2a", "3a3a", "4a4a", "5a5a", "6a6a", "7a7a",
                "8a8a", "9a9a", "aaaa", "baba", "caca", "dada", "eaea", "fafa"}

# DNS covert-channel — base32/base64 alphabet detection on qname first label.
_BASE32_RX = re.compile(r"^[a-z2-7]+$", re.IGNORECASE)
_BASE64URL_RX = re.compile(r"^[a-z0-9_\-]+$", re.IGNORECASE)

# CS DNS beacon default subdomain prefixes.
CS_DNS_BEACON_RX = re.compile(
    r"(?i)^(?:api|cdn|www|post|www6)\.[a-f0-9]{8,}\."
)

# Known DoH/DoT public resolver hostnames (whitelist reverse: outbound to
# non-whitelisted DoH endpoint is what we detect on the negative).
KNOWN_DOH_HOSTS = {
    "dns.google", "cloudflare-dns.com", "one.one.one.one",
    "dns.quad9.net", "doh.opendns.com", "dns.adguard.com",
    "dns.alidns.com", "doh.pub", "doh.360.cn",
}

# CN red-team webshell / RAT signatures — traffic-side markers only.
BEHINDER_MARKER_RX = re.compile(
    r"(?i)(?:e45e329feb5d925b|rebeyond|Pass:\s*[A-Za-z0-9+/=]{16,}|"
    r"Content-Type:\s*application/octet-stream.*Cookie:\s*rememberMe=)"
)
GODZILLA_MARKER_RX = re.compile(
    r"(?i)(?:3c6e0b8a9c15224a|Cookie:\s*[a-zA-Z0-9]+=[A-Za-z0-9+/=]{40,}|"
    r"pass=@?assert|Referer:\s*http[s]?://[^ ]+/?[a-z0-9]{16,}\.jsp)"
)
ANTSWORD_MARKER_RX = re.compile(
    r"(?i)(?:antSword|antsword|Referer:\s*http[s]?://[^ ]+/[^\s]+\.(?:php|jsp|asp)$|"
    r"X-Forwarded-For:\s*127\.0\.0\.1$)"
)
LINX_MARKER_RX = re.compile(
    r"(?i)(?:/linx-agent|X-Session-Id:\s*[a-f0-9]{32}|Linx\s*Agent|"
    r"User-Agent:.*linx[- ]?\d)"
)
VIPER_MARKER_RX = re.compile(
    r"(?i)(?:/api/v[0-9]/user/login/index|/msf/download|Viper-Sn|"
    r"User-Agent:.*Viper(?:\s|/))"
)
FSCAN_MARKER_RX = re.compile(
    r"(?i)(?:User-Agent:\s*Mozilla/5\.0.*fscan|/nice\s+ports.*Trinity|"
    r"/webalizer/webalizer\.current)"
)
GOBY_MARKER_RX = re.compile(
    r"(?i)(?:User-Agent:\s*Goby|X-Goby-.*:|/goby-webapp)"
)
XRAY_MARKER_RX = re.compile(
    r"(?i)(?:User-Agent:\s*.*[Xx]ray|X-Xray-Reproduce-Id|/xray-cb-[a-f0-9]{8,})"
)
NUCLEI_MARKER_RX = re.compile(
    r"(?i)(?:User-Agent:\s*Nuclei|X-Nuclei-Id|/nuclei-\d)"
)
YAKIT_MARKER_RX = re.compile(
    r"(?i)(?:User-Agent:\s*Yakit|X-Yakit-|/yakit\-web)"
)
SUO5_MARKER_RX = re.compile(
    r"(?i)(?:/suo5|Suo5-|X-Suo5-|Upgrade:\s*websocket.*/suo5)"
)
REGEORG_MARKER_RX = re.compile(
    r"(?i)(?:tunnel\.(?:aspx|jsp|php|nosocket\.php)|"
    r"X-CMD:\s*(?:CONNECT|CONNECTED|FORWARD|DISCONNECT)|"
    r"neo-regeorg|reGeorg)"
)
BRUTE_MARKER_RX = re.compile(
    r"(?i)(?:User-Agent:\s*(?:hydra|patator|medusa|bp/[0-9])|"
    r"POST\s+/(?:login|admin|auth)\b.*Content-Length:\s*[1-6][0-9]$)"
)


# --------------------------------------------------------------------------- #
# Helpers                                                                     #
# --------------------------------------------------------------------------- #


def parse_ts(s: str | None) -> datetime | None:
    return _hc.parse_ts(s)


def qname_entropy_ratio(q: str) -> float:
    """Cheap DGA heuristic: mixed digit ratio + label length."""
    if not q:
        return 0.0
    labels = q.strip(".").split(".")
    if not labels:
        return 0.0
    longest = max(labels, key=len)
    if not longest:
        return 0.0
    digits = sum(1 for c in longest if c.isdigit())
    letters = sum(1 for c in longest if c.isalpha())
    if letters == 0:
        return 1.0
    return digits / max(1, letters + digits)


def label_shannon(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    total = len(s)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


def load_signatures(path: Path) -> dict:
    if not path.exists():
        return {"signatures": []}
    return json.loads(path.read_text(encoding="utf-8"))


def compile_signatures(sig_data: dict) -> list[dict]:
    out: list[dict] = []
    for s in sig_data.get("signatures", []):
        pat = s.get("pattern")
        if not pat:
            continue
        try:
            s["_re"] = re.compile(pat)
        except re.error:
            continue
        out.append(s)
    return out


def _mask(s: str | None, n: int = 200) -> str | None:
    if s is None:
        return None
    return s if len(s) <= n else s[:n] + "…"


# === v0.3-M1 helpers =========================================================
def _qname_first_label(q: str) -> str:
    if not q:
        return ""
    return q.strip(".").split(".", 1)[0]


def _qname_parent(q: str) -> str:
    if not q:
        return ""
    parts = q.strip(".").split(".")
    if len(parts) < 2:
        return q.strip(".")
    return ".".join(parts[-2:])


def _base_alphabet_ratio(label: str) -> tuple[float, float]:
    """Return (base32_ratio, base64url_ratio) of chars in label."""
    if not label:
        return 0.0, 0.0
    total = len(label)
    b32 = sum(1 for c in label if c.isalnum() and c.lower() in "abcdefghijklmnopqrstuvwxyz234567")
    b64 = sum(1 for c in label if c.isalnum() or c in "-_")
    return b32 / total, b64 / total


def _is_grease(hex_val: str) -> bool:
    return hex_val.lower() in _GREASE_VALS


def _is_numeric_or_ip(s: str) -> bool:
    if not s:
        return False
    s2 = s.replace(".", "").replace(":", "")
    return s2.isdigit() or all(c in "0123456789abcdefABCDEF:." for c in s)


def _tls_alert_v03_extra(rec: dict, findings: list, tls_state: dict) -> None:
    """Emit R-TRAF-050~069 for a single tls-view record."""
    raw = rec.get("raw") or {}
    sni = raw.get("sni") or ""
    cn = raw.get("cert_cn") or ""
    issuer = raw.get("cert_issuer") or ""
    ja3 = raw.get("ja3") or raw.get("ja3_hash") or ""
    ja3s = raw.get("ja3s") or raw.get("ja3s_hash") or ""
    cipher = raw.get("cipher") or ""
    alpn = raw.get("alpn") or ""
    host = raw.get("host") or ""
    cert_not_before = raw.get("cert_not_before")
    cert_not_after = raw.get("cert_not_after")
    exts_order = raw.get("tls_extensions") or ""

    # R-TRAF-050 JA3 hits known CS beacon
    if ja3 and ja3.lower() in KNOWN_JA3_C2:
        tool, _ = KNOWN_JA3_C2[ja3.lower()]
        if tool.startswith("cobalt"):
            emit(findings, "R-TRAF-050", rec,
                 {"narrative": "JA3 matches known CS beacon fingerprint",
                  "ja3": ja3, "tool": tool})
        else:
            emit(findings, "R-TRAF-051", rec,
                 {"narrative": f"JA3 matches known C2 fingerprint ({tool})",
                  "ja3": ja3, "tool": tool})

    # R-TRAF-052 JA3S hits CN-modified CS server or other server-side C2
    if ja3s and ja3s.lower() in KNOWN_JA3S_C2:
        tool, _ = KNOWN_JA3S_C2[ja3s.lower()]
        emit(findings, "R-TRAF-052", rec,
             {"narrative": f"JA3S matches known C2 server ({tool})",
              "ja3s": ja3s, "tool": tool})

    # R-TRAF-053 SNI vs Host mismatch (domain fronting suspect)
    if sni and host and sni.lower() != host.lower():
        # only alert when both look like real hostnames
        if "." in sni and "." in host:
            emit(findings, "R-TRAF-053", rec,
                 {"narrative": "SNI/Host mismatch (domain fronting suspect)",
                  "sni": _mask(sni, 80), "host": _mask(host, 80)})

    # R-TRAF-054 default self-signed CN/O
    if cn and C2_CERT_CN_RX.search(cn):
        emit(findings, "R-TRAF-054", rec,
             {"narrative": "TLS cert CN matches default red-team self-signed",
              "cert_cn": _mask(cn, 80)})

    # R-TRAF-055 empty SNI or numeric-only SNI (Sliver mTLS default)
    if sni == "" or _is_numeric_or_ip(sni):
        # Downgrade weight: only alert when we also have TLS handshake context
        if ja3 or cn or cipher:
            emit(findings, "R-TRAF-055", rec,
                 {"narrative": "empty/numeric SNI (Sliver mTLS default suspect)",
                  "sni": sni or "<empty>"})

    # R-TRAF-056 SM2/SM3/SM4 GM cipher outside declared GM business
    if cipher and GM_CIPHER_RX.search(cipher):
        emit(findings, "R-TRAF-056", rec,
             {"narrative": "GM (SM2/SM3/SM4) TLS cipher outside whitelist",
              "cipher": _mask(cipher, 80)})

    # R-TRAF-057 short-lived cert (<24h) + self-signed
    if cert_not_before and cert_not_after:
        nb = parse_ts(cert_not_before)
        na = parse_ts(cert_not_after)
        if nb and na and (na - nb) < timedelta(hours=24):
            if issuer and cn and issuer.lower() == cn.lower():
                emit(findings, "R-TRAF-057", rec,
                     {"narrative": "very short-lived self-signed cert (<24h)",
                      "cert_lifetime_h": f"{(na - nb).total_seconds() / 3600:.1f}"})

    # R-TRAF-058 ALPN says h2 but flow lacks HTTP/2 markers (heuristic)
    if alpn and "h2" in alpn.lower():
        if raw.get("http_version") and "1." in str(raw.get("http_version")):
            emit(findings, "R-TRAF-058", rec,
                 {"narrative": "ALPN=h2 but HTTP/1.x observed on same stream",
                  "alpn": alpn})

    # R-TRAF-059 outbound to public IP but SNI = private domain
    dip = rec.get("dst_ip") or ""
    if sni and dip:
        priv_sni = any(sni.lower().endswith(sfx) for sfx in
                       (".local", ".corp", ".internal", ".lan", ".intra", ".prod.internal"))
        pub_dst = not (dip.startswith(("10.", "192.168.", "172.16.", "172.17.",
                                        "172.18.", "172.19.", "172.20.",
                                        "172.21.", "172.22.", "172.23.",
                                        "172.24.", "172.25.", "172.26.",
                                        "172.27.", "172.28.", "172.29.",
                                        "172.30.", "172.31.", "127.")))
        if priv_sni and pub_dst:
            emit(findings, "R-TRAF-059", rec,
                 {"narrative": "public dst IP but private-domain SNI",
                  "sni": _mask(sni, 80), "dst_ip": dip})

    # R-TRAF-060 GREASE absent in Client Hello (modern browsers ALWAYS include)
    if exts_order and "grease" not in exts_order.lower() and ja3:
        # only informational when we have ja3 to compare
        if not any(_is_grease(x) for x in exts_order.split(",")):
            emit(findings, "R-TRAF-060", rec,
                 {"narrative": "TLS Client Hello lacks GREASE (non-browser client)",
                  "exts_len": len(exts_order.split(","))})

    # R-TRAF-061 ECH extension appearing outside whitelist
    if exts_order and "ech" in exts_order.lower():
        emit(findings, "R-TRAF-061", rec,
             {"narrative": "TLS ECH extension observed (rare on corp networks)"})

    # R-TRAF-062 extension count = 0 or extremely low (< 4)
    if exts_order:
        n_ext = len([e for e in exts_order.split(",") if e.strip()])
        if 0 < n_ext < 4:
            emit(findings, "R-TRAF-062", rec,
                 {"narrative": f"unusually few TLS extensions ({n_ext})",
                  "extension_count": n_ext})

    # R-TRAF-063 SNI is bare IP literal
    if sni and _is_numeric_or_ip(sni) and "." in sni:
        emit(findings, "R-TRAF-063", rec,
             {"narrative": "SNI carries IP literal instead of hostname",
              "sni": sni})

    # R-TRAF-064 single ciphersuite proposed (custom tool)
    if cipher and "," not in cipher and len(cipher) > 4:
        # very small proposal set is heuristically suspicious
        emit(findings, "R-TRAF-064", rec,
             {"narrative": "TLS Client Hello proposed a single ciphersuite",
              "cipher": _mask(cipher, 40)})

    # R-TRAF-065 session ticket + session_id both empty (fresh handshake)
    if raw.get("session_id_empty") and raw.get("session_ticket_empty"):
        emit(findings, "R-TRAF-065", rec,
             {"narrative": "fresh session (no ticket, no id) — atypical for busy client"})

    # R-TRAF-066 handshake failure spike (per src)
    if raw.get("alert_level") == "fatal":
        key = rec.get("src_ip") or "?"
        tls_state["alert_spikes"][key] = tls_state["alert_spikes"].get(key, 0) + 1
        if tls_state["alert_spikes"][key] > 20:
            emit(findings, "R-TRAF-066", rec,
                 {"narrative": "fatal TLS alert spike (>20 from same src)",
                  "alert_count": tls_state["alert_spikes"][key]})

    # R-TRAF-067 same client cycling many different SNIs quickly
    if sni:
        src = rec.get("src_ip") or "?"
        tls_state["sni_set"][src].add(sni)
        if len(tls_state["sni_set"][src]) > 40:
            if src not in tls_state["sni_flood_emitted"]:
                emit(findings, "R-TRAF-067", rec,
                     {"narrative": ">40 distinct SNIs from same src (recon)",
                      "distinct_sni": len(tls_state["sni_set"][src])})
                tls_state["sni_flood_emitted"].add(src)

    # R-TRAF-068 browser-like UA hint but ALPN missing (mismatch)
    ua_hint = raw.get("ua_hint") or ""
    if ua_hint and any(b in ua_hint.lower() for b in ("chrome", "firefox", "safari")) \
            and not alpn:
        emit(findings, "R-TRAF-068", rec,
             {"narrative": "browser-hinted UA but ALPN missing",
              "ua_hint": _mask(ua_hint, 80)})

    # R-TRAF-069 SNI + ALPN both empty (headless tool default)
    if not sni and not alpn and (ja3 or cipher):
        emit(findings, "R-TRAF-069", rec,
             {"narrative": "SNI + ALPN both empty (headless tool)",
              "ja3": ja3 or "<none>"})


def _dns_alert_v03_extra(rec: dict, findings: list, dns_state: dict) -> None:
    """Emit R-TRAF-070~084 for a single dns-view record."""
    raw = rec.get("raw") or {}
    qname = raw.get("qname") or ""
    qtype = (raw.get("qtype") or "").upper()
    rcode = raw.get("rcode")
    src = rec.get("src_ip") or "?"
    ts = parse_ts(rec.get("ts"))

    first_label = _qname_first_label(qname)
    parent = _qname_parent(qname)
    q_len = len(qname)

    # Rolling stats
    if ts:
        dns_state["len_samples"][src].append((ts, q_len))
        # Keep last 5 min window trimmed cheaply
        cutoff = ts - timedelta(minutes=5)
        while dns_state["len_samples"][src] and dns_state["len_samples"][src][0][0] < cutoff:
            dns_state["len_samples"][src].popleft()
        if qtype == "TXT":
            dns_state["txt_count"][src] += 1
        if qtype in ("NULL", "10"):
            dns_state["null_count"][src] += 1
        dns_state["all_count"][src] += 1
        dns_state["parent_children"][parent].add(first_label)
        if rcode == 3:
            dns_state["nxdom_count"][src].append(ts)
            cutoff = ts - timedelta(minutes=5)
            while dns_state["nxdom_count"][src] and dns_state["nxdom_count"][src][0] < cutoff:
                dns_state["nxdom_count"][src].popleft()

    # R-TRAF-070 average qname length > 40 + high frequency
    samples = dns_state["len_samples"][src]
    if len(samples) >= 20:
        avg_len = sum(x[1] for x in samples) / len(samples)
        if avg_len > 40:
            key = f"{src}:R070"
            if key not in dns_state["emitted"]:
                emit(findings, "R-TRAF-070", rec,
                     {"narrative": f"avg qname length > 40 across {len(samples)} queries",
                      "avg_qname_len": f"{avg_len:.1f}"})
                dns_state["emitted"].add(key)

    # R-TRAF-071 Shannon entropy > 4.0 on first label
    if first_label and len(first_label) >= 16:
        h = label_shannon(first_label)
        if h > 4.0:
            emit(findings, "R-TRAF-071", rec,
                 {"narrative": "first label Shannon entropy > 4.0",
                  "shannon": f"{h:.2f}", "qname": _mask(qname, 80)})

    # R-TRAF-072 same parent domain > 100 distinct sub in 5 min window
    if parent and len(dns_state["parent_children"][parent]) > 100:
        key = f"{parent}:R072"
        if key not in dns_state["emitted"]:
            emit(findings, "R-TRAF-072", rec,
                 {"narrative": f"parent domain has >100 distinct subdomains",
                  "parent": parent,
                  "distinct_sub": len(dns_state["parent_children"][parent])})
            dns_state["emitted"].add(key)

    # R-TRAF-073 TXT ratio > 30%
    all_c = dns_state["all_count"].get(src, 0)
    txt_c = dns_state["txt_count"].get(src, 0)
    if all_c >= 30 and (txt_c / all_c) > 0.30:
        key = f"{src}:R073"
        if key not in dns_state["emitted"]:
            emit(findings, "R-TRAF-073", rec,
                 {"narrative": f"TXT ratio {txt_c}/{all_c} > 30%",
                  "txt_ratio": f"{txt_c / all_c:.2f}"})
            dns_state["emitted"].add(key)

    # R-TRAF-074 NULL ratio > 5%
    null_c = dns_state["null_count"].get(src, 0)
    if all_c >= 30 and (null_c / all_c) > 0.05:
        key = f"{src}:R074"
        if key not in dns_state["emitted"]:
            emit(findings, "R-TRAF-074", rec,
                 {"narrative": f"NULL ratio {null_c}/{all_c} > 5% (iodine)",
                  "null_ratio": f"{null_c / all_c:.2f}"})
            dns_state["emitted"].add(key)

    # R-TRAF-075 UDP/53 payload size distribution abnormal
    pl_size = raw.get("payload_len") or 0
    if isinstance(pl_size, (int, float)) and pl_size > 400 and qtype == "A":
        emit(findings, "R-TRAF-075", rec,
             {"narrative": "large DNS payload for simple A query",
              "payload_len": pl_size})

    # R-TRAF-076 first label base32/base64 alphabet ratio > 80%
    if first_label and len(first_label) >= 20:
        b32r, b64r = _base_alphabet_ratio(first_label)
        if b32r >= 0.85 or b64r >= 0.85:
            emit(findings, "R-TRAF-076", rec,
                 {"narrative": "first label matches base32/base64 alphabet >80%",
                  "b32_ratio": f"{b32r:.2f}", "b64_ratio": f"{b64r:.2f}"})

    # R-TRAF-077 NXDOMAIN storm from single client
    nx_dq = dns_state["nxdom_count"].get(src, deque())
    if len(nx_dq) > 50:
        key = f"{src}:R077"
        if key not in dns_state["emitted"]:
            emit(findings, "R-TRAF-077", rec,
                 {"narrative": f">{50} NXDOMAIN within 5 min from same src",
                  "nxdomain_5min": len(nx_dq)})
            dns_state["emitted"].add(key)

    # R-TRAF-078 CS DNS beacon default prefix
    if qname and CS_DNS_BEACON_RX.search(qname):
        emit(findings, "R-TRAF-078", rec,
             {"narrative": "qname matches CS DNS beacon default prefix",
              "qname": _mask(qname, 80)})

    # R-TRAF-079 DoH/DoT outbound to non-whitelisted resolver
    dst_port = rec.get("dst_port")
    if dst_port in (443, 853):
        host_hint = raw.get("sni") or raw.get("host") or ""
        if host_hint and host_hint not in KNOWN_DOH_HOSTS \
                and any(k in host_hint.lower() for k in ("doh", "dns-over", "dnstls", "dot")):
            emit(findings, "R-TRAF-079", rec,
                 {"narrative": "DoH/DoT to non-whitelisted resolver",
                  "host_hint": _mask(host_hint, 80)})

    # R-TRAF-080 simple n-gram heuristic: consonant clusters length >= 5
    if first_label and len(first_label) >= 12:
        max_consec = 0
        cur = 0
        for c in first_label.lower():
            if c not in "aeiou0123456789":
                cur += 1
                max_consec = max(max_consec, cur)
            else:
                cur = 0
        if max_consec >= 7:
            emit(findings, "R-TRAF-080", rec,
                 {"narrative": "consonant/digit cluster >=7 (DGA n-gram heuristic)",
                  "max_consec_consonant": max_consec})

    # R-TRAF-081 time-interval uniformity (beacon jitter)
    intervals = dns_state["intervals"][src]
    if ts:
        if intervals and intervals[-1]:
            delta = (ts - intervals[-1]).total_seconds()
            intervals.append(ts)
            dns_state["deltas"][src].append(delta)
            if len(dns_state["deltas"][src]) > 20:
                dns_state["deltas"][src].popleft()
        else:
            intervals.append(ts)
    deltas = list(dns_state["deltas"].get(src, []))
    if len(deltas) >= 15:
        mean = sum(deltas) / len(deltas)
        if mean > 0:
            var = sum((d - mean) ** 2 for d in deltas) / len(deltas)
            cv = math.sqrt(var) / mean
            if cv < 0.15 and mean > 5:  # very uniform, > 5s spacing
                key = f"{src}:R081"
                if key not in dns_state["emitted"]:
                    emit(findings, "R-TRAF-081", rec,
                         {"narrative": "highly uniform DNS query interval (beacon)",
                          "coeff_variation": f"{cv:.3f}",
                          "mean_interval_s": f"{mean:.1f}"})
                    dns_state["emitted"].add(key)

    # R-TRAF-082 answer size >> query size (reverse tunneling)
    resp_ip = raw.get("response_ip") or ""
    ans_len = raw.get("answer_len") or 0
    if isinstance(ans_len, (int, float)) and q_len and ans_len > q_len * 4 and ans_len > 200:
        emit(findings, "R-TRAF-082", rec,
             {"narrative": "DNS answer >> query (reverse tunnel suspect)",
              "answer_len": ans_len, "qname_len": q_len})

    # R-TRAF-083 abnormal TTL — 0 or > 604800 (7d)
    ttl = raw.get("ttl")
    if isinstance(ttl, (int, float)) and (ttl == 0 or ttl > 604800):
        emit(findings, "R-TRAF-083", rec,
             {"narrative": f"anomalous TTL={ttl}", "ttl": ttl})

    # R-TRAF-084 repeated qname burst (same qname > 30 times / 5 min)
    if qname:
        dns_state["qname_count"][(src, qname)] = dns_state["qname_count"].get((src, qname), 0) + 1
        if dns_state["qname_count"][(src, qname)] > 30:
            key = f"{src}:{qname}:R084"
            if key not in dns_state["emitted"]:
                emit(findings, "R-TRAF-084", rec,
                     {"narrative": "same qname >30 times in window (beacon poll)",
                      "qname": _mask(qname, 80),
                      "count": dns_state["qname_count"][(src, qname)]})
                dns_state["emitted"].add(key)


def _cn_tool_alert_v03_extra(rec: dict, findings: list, http_state: dict) -> None:
    """Emit R-TRAF-085~098 for a single http/tls-view record."""
    raw = rec.get("raw") or {}
    view = rec.get("view")
    ua = raw.get("ua") or ""
    uri = raw.get("uri") or ""
    host = raw.get("host") or ""
    req_line = raw.get("request_line_excerpt") or ""
    method = raw.get("method") or ""
    ctype = raw.get("content_type") or ""
    clen = raw.get("content_length") or 0
    sni = raw.get("sni") or ""

    haystack = " ".join([uri, ua, req_line, host])

    # R-TRAF-085 冰蝎 Behinder v3/v4
    if BEHINDER_MARKER_RX.search(haystack):
        emit(findings, "R-TRAF-085", rec,
             {"narrative": "Behinder v3/v4 webshell traffic marker",
              "tool": "behinder"})

    # R-TRAF-086 哥斯拉 Godzilla xc-key
    if GODZILLA_MARKER_RX.search(haystack):
        emit(findings, "R-TRAF-086", rec,
             {"narrative": "Godzilla webshell marker",
              "tool": "godzilla"})

    # R-TRAF-087 AntSword UA/XFF combo
    if view == "http" and ANTSWORD_MARKER_RX.search(haystack):
        emit(findings, "R-TRAF-087", rec,
             {"narrative": "AntSword UA/XFF combination",
              "tool": "antsword"})

    # R-TRAF-088 Linx 灵蜥
    if LINX_MARKER_RX.search(haystack):
        emit(findings, "R-TRAF-088", rec,
             {"narrative": "Linx (灵蜥) agent traffic marker",
              "tool": "linx"})

    # R-TRAF-089 Viper C2
    if VIPER_MARKER_RX.search(haystack) or (sni and "viper" in sni.lower()):
        emit(findings, "R-TRAF-089", rec,
             {"narrative": "Viper C2 default URI/SNI marker",
              "tool": "viper"})

    # R-TRAF-090 fscan
    if FSCAN_MARKER_RX.search(haystack):
        emit(findings, "R-TRAF-090", rec,
             {"narrative": "fscan scanner marker",
              "tool": "fscan"})
    else:
        # multi-port scan behavior from same src
        src = rec.get("src_ip") or "?"
        dport = rec.get("dst_port")
        if dport:
            http_state["ports_by_src"][src].add(dport)
            if len(http_state["ports_by_src"][src]) > 25 \
                    and src not in http_state["fscan_emitted"]:
                emit(findings, "R-TRAF-090", rec,
                     {"narrative": ">25 distinct dst_ports from same src (scanner)",
                      "distinct_ports": len(http_state["ports_by_src"][src])})
                http_state["fscan_emitted"].add(src)

    # R-TRAF-091 goby
    if GOBY_MARKER_RX.search(haystack):
        emit(findings, "R-TRAF-091", rec,
             {"narrative": "Goby scanner marker", "tool": "goby"})

    # R-TRAF-092 xray
    if XRAY_MARKER_RX.search(haystack):
        emit(findings, "R-TRAF-092", rec,
             {"narrative": "xray scanner UA / cb-id marker", "tool": "xray"})

    # R-TRAF-093 nuclei
    if NUCLEI_MARKER_RX.search(haystack):
        emit(findings, "R-TRAF-093", rec,
             {"narrative": "Nuclei scanner marker", "tool": "nuclei"})

    # R-TRAF-094 Yakit
    if YAKIT_MARKER_RX.search(haystack):
        emit(findings, "R-TRAF-094", rec,
             {"narrative": "Yakit platform traffic marker", "tool": "yakit"})

    # R-TRAF-095 suo5 HTTP/2 内网穿透
    if SUO5_MARKER_RX.search(haystack):
        emit(findings, "R-TRAF-095", rec,
             {"narrative": "suo5 tunnel marker (HTTP/2 upgrade)", "tool": "suo5"})

    # R-TRAF-096 neo-regeorg / reGeorg
    if REGEORG_MARKER_RX.search(haystack):
        emit(findings, "R-TRAF-096", rec,
             {"narrative": "neo-regeorg / reGeorg tunnel headers", "tool": "regeorg"})

    # R-TRAF-097 brute-force tool UA / short-rapid POST
    if BRUTE_MARKER_RX.search(haystack):
        emit(findings, "R-TRAF-097", rec,
             {"narrative": "brute-force tool marker", "tool": "brute-force"})
    else:
        # Behavioral: repeated POST to /login-ish URI, short body, high rate
        if view == "http" and method == "POST" and uri:
            if any(k in uri.lower() for k in ("login", "auth", "admin", "signin", "logon")):
                if isinstance(clen, int) and 0 < clen < 200:
                    src = rec.get("src_ip") or "?"
                    http_state["login_burst"][src] += 1
                    if http_state["login_burst"][src] > 40 \
                            and src not in http_state["brute_emitted"]:
                        emit(findings, "R-TRAF-097", rec,
                             {"narrative": ">40 short POSTs to auth URI from same src",
                              "count": http_state["login_burst"][src]})
                        http_state["brute_emitted"].add(src)

    # R-TRAF-098 pulse beacon (loader回连) — flow-view helper
    if view == "flow":
        pkts = raw.get("packets_total") or 0
        duration = raw.get("duration_s") or 0.0
        bytes_total = raw.get("bytes_total") or 0
        # very small, regular pulses over long duration
        if pkts >= 30 and duration > 600 and bytes_total < 20 * 1024:
            emit(findings, "R-TRAF-098", rec,
                 {"narrative": "pulse-like beacon (small pkts, long duration)",
                  "packets": pkts, "duration_s": duration,
                  "bytes_total": bytes_total})


def _init_v03_state() -> dict:
    return {
        "tls": {
            "sni_set": defaultdict(set),
            "alert_spikes": {},
            "sni_flood_emitted": set(),
        },
        "dns": {
            "len_samples": defaultdict(deque),
            "txt_count": defaultdict(int),
            "null_count": defaultdict(int),
            "all_count": defaultdict(int),
            "parent_children": defaultdict(set),
            "nxdom_count": defaultdict(deque),
            "intervals": defaultdict(list),
            "deltas": defaultdict(deque),
            "qname_count": {},
            "emitted": set(),
        },
        "http": {
            "ports_by_src": defaultdict(set),
            "login_burst": defaultdict(int),
            "fscan_emitted": set(),
            "brute_emitted": set(),
        },
    }


# --------------------------------------------------------------------------- #
# Finding emit                                                                #
# --------------------------------------------------------------------------- #


def _iocs(rec: dict, rule_id: str) -> list[dict]:
    out = []
    if rec.get("src_ip"):
        out.append({
            "type": "ip", "value": rec["src_ip"], "confidence": "medium",
            "first_seen": rec.get("ts"),
            "source": f"{rule_id}@{rec.get('src_file')}:{rec.get('line_no')}",
            "tag": f"rule:{rule_id}",
        })
    return out


def emit(findings: list[dict], rule_id: str, rec: dict, extra: dict) -> None:
    raw = rec.get("raw") or {}
    _hc.emit_finding(
        findings,
        id_prefix="TRAF",
        severity=SEVERITY.get(rule_id, "P3"),
        category=CATEGORY.get(rule_id, "recon"),
        evidence={
            "ts": rec.get("ts"),
            "src_ip": rec.get("src_ip"),
            "dst_ip": rec.get("dst_ip"),
            "src_port": rec.get("src_port"),
            "dst_port": rec.get("dst_port"),
            "proto": rec.get("proto"),
            "view": rec.get("view"),
            "src_file": rec.get("src_file"),
            "line_no": rec.get("line_no"),
            "sig_id": extra.get("sig_id"),
            "tool": extra.get("tool"),
            "narrative": extra.get("narrative"),
            "hint": {k: _mask(str(v), 200) for k, v in extra.items()
                     if k not in {"sig_id", "tool", "narrative"} and v is not None},
        },
        rule_id=rule_id,
        fp_prob=FP_PROB.get(rule_id, 0.3),
        action=ACTION.get(rule_id, "纳入待跟进"),
        iocs=_iocs(rec, rule_id),
    )


# --------------------------------------------------------------------------- #
# Rule detection                                                              #
# --------------------------------------------------------------------------- #


def detect(records: Iterator[dict], sigs: list[dict]) -> list[dict]:
    findings: list[dict] = []

    # Signature buckets by view
    sig_by_view: dict[str, list[dict]] = defaultdict(list)
    for s in sigs:
        sig_by_view[s.get("view", "http")].append(s)

    # State for time-windowed rules
    dns_rate: dict[str, deque] = defaultdict(deque)          # per src_ip: qname timestamps
    dns_txt_rate: dict[str, deque] = defaultdict(deque)      # per src_ip: TXT-only qname ts
    rdp_fanin: dict[str, set[str]] = defaultdict(set)        # per dst_ip: set of src_ip
    rdp_fanin_emitted: set[str] = set()

    dns_window = timedelta(hours=1)

    def _prune(dq: deque, now: datetime, window: timedelta) -> None:
        while dq and (now - dq[0]) > window:
            dq.popleft()

    per_ip_rules: dict[str, set[str]] = defaultdict(set)
    per_ip_first_ts: dict[str, str] = {}

    # v0.3-M1 state buckets (TLS deepening / DNS covert / CN tools)
    _v03 = _init_v03_state()

    for rec in records:
        view = rec.get("view")
        raw = rec.get("raw") or {}
        ts = parse_ts(rec.get("ts"))

        # ============== HTTP-view rules ==============
        if view == "http":
            ua = raw.get("ua") or ""
            uri = raw.get("uri") or ""
            host = raw.get("host") or ""
            req_line = raw.get("request_line_excerpt") or ""
            content_len = raw.get("content_length") or 0
            method = raw.get("method") or ""

            # R-TRAF-001 scanner UA
            if ua and SCANNER_UA_RX.search(ua):
                emit(findings, "R-TRAF-001", rec,
                     {"narrative": "scanner UA hit", "hint_ua": _mask(ua)})

            # signature-driven scanner/webshell/c2 UA
            for s in sig_by_view.get("http", []):
                fld = s.get("field")
                val = None
                if fld == "ua":
                    val = ua
                elif fld == "uri":
                    val = uri
                elif fld == "host":
                    val = host
                elif fld == "request_line_excerpt":
                    val = req_line
                elif fld == "content_type":
                    val = raw.get("content_type") or ""
                elif fld == "method":
                    val = method
                elif fld == "content_length":
                    val = str(content_len)
                if val and s["_re"].search(val):
                    cat = s.get("category")
                    if cat == "scanner":
                        emit(findings, "R-TRAF-001", rec,
                             {"sig_id": s.get("id"), "tool": s.get("tool")})
                    elif cat == "webshell":
                        emit(findings, "R-TRAF-012", rec,
                             {"sig_id": s.get("id"), "tool": s.get("tool")})
                    elif cat == "c2":
                        emit(findings, "R-TRAF-007", rec,
                             {"sig_id": s.get("id"), "tool": s.get("tool")})
                    elif cat == "tunnel":
                        emit(findings, "R-TRAF-203", rec,
                             {"sig_id": s.get("id"), "tool": s.get("tool")})
                    elif cat == "exfil":
                        emit(findings, "R-TRAF-010", rec,
                             {"sig_id": s.get("id"), "tool": s.get("tool")})
                    elif cat == "sqli":
                        emit(findings, "R-TRAF-003", rec,
                             {"sig_id": s.get("id"), "tool": s.get("tool"),
                              "matched_field": fld})
                    elif cat == "rce":
                        emit(findings, "R-TRAF-004", rec,
                             {"sig_id": s.get("id"), "tool": s.get("tool"),
                              "matched_field": fld})
                    elif cat in ("xss", "lfi", "rfi"):
                        # CRS 通用 Web 攻击（XSS/LFI/RFI）归入 R-TRAF-002 web 攻击探测
                        emit(findings, "R-TRAF-002", rec,
                             {"sig_id": s.get("id"), "tool": s.get("tool"),
                              "attack_type": cat, "matched_field": fld})

            # R-TRAF-002 sensitive path
            if uri and SENSITIVE_PATH_RX.search(uri):
                emit(findings, "R-TRAF-002", rec,
                     {"narrative": "sensitive path probe"})

            # R-TRAF-003 SQLi
            if uri and SQLI_RX.search(uri):
                emit(findings, "R-TRAF-003", rec,
                     {"narrative": "SQLi trigger string"})

            # R-TRAF-004 RCE / JNDI / fastjson (URI *or* request line body)
            probe_str = uri or ""
            if req_line:
                probe_str = probe_str + " " + req_line
            if probe_str.strip() and RCE_RX.search(probe_str):
                emit(findings, "R-TRAF-004", rec,
                     {"narrative": "RCE trigger string"})

            # R-TRAF-012 webshell key markers
            if req_line and WEBSHELL_KEY_RX.search(req_line):
                emit(findings, "R-TRAF-012", rec,
                     {"narrative": "webshell key marker"})

            # v0.3-M1 CN red-team tool markers (http-view)
            _cn_tool_alert_v03_extra(rec, findings, _v03["http"])

        # ============== DNS-view rules ==============
        elif view == "dns":
            qname = raw.get("qname") or ""
            qtype = (raw.get("qtype") or "").upper()
            src = rec.get("src_ip") or "?"
            if ts:
                dns_rate[src].append(ts)
                _prune(dns_rate[src], ts, dns_window)
            # R-TRAF-005 DGA
            if qname and len(qname) > 30:
                ratio = qname_entropy_ratio(qname)
                if ratio > 0.25 and (not ts or len(dns_rate[src]) > 20):
                    emit(findings, "R-TRAF-005", rec,
                         {"narrative": "DGA-like qname pattern",
                          "digit_ratio": f"{ratio:.2f}",
                          "qname": _mask(qname)})
            # R-TRAF-006 DNSCAT2 / iodine
            if qtype in ("TXT", "16"):
                if ts:
                    dns_txt_rate[src].append(ts)
                    _prune(dns_txt_rate[src], ts, dns_window)
            if qname and len(qname) > 60:
                emit(findings, "R-TRAF-006", rec,
                     {"narrative": "very long qname (iodine-like)",
                      "qname_len": len(qname)})
            elif qtype in ("TXT", "16") and len(dns_txt_rate[src]) > 40:
                emit(findings, "R-TRAF-006", rec,
                     {"narrative": "TXT query flood (dnscat2-like)",
                      "txt_count_1h": len(dns_txt_rate[src])})
            # signature dns rules
            for s in sig_by_view.get("dns", []):
                fld = s.get("field")
                val = qname if fld == "qname" else (qtype if fld == "qtype" else "")
                if val and s["_re"].search(val):
                    emit(findings, "R-TRAF-005" if s.get("category") == "c2"
                         and "dga" in (s.get("tool") or "").lower()
                         else "R-TRAF-006", rec,
                         {"sig_id": s.get("id"), "tool": s.get("tool")})

            # v0.3-M1 DNS covert-channel deepening
            _dns_alert_v03_extra(rec, findings, _v03["dns"])

        # ============== TLS-view rules ==============
        elif view == "tls":
            sni = raw.get("sni") or ""
            cn = raw.get("cert_cn") or ""
            for s in sig_by_view.get("tls", []):
                fld = s.get("field")
                val = ""
                if fld == "sni":
                    val = sni
                elif fld == "cert_cn":
                    val = cn
                elif fld == "cert_issuer":
                    val = raw.get("cert_issuer") or ""
                elif fld == "ja3":
                    val = (raw.get("ja3") or raw.get("ja3_hash") or "").lower()
                elif fld == "ja3s":
                    val = (raw.get("ja3s") or raw.get("ja3s_hash") or "").lower()
                elif fld == "cipher":
                    val = raw.get("cipher") or ""
                if val is not None and s["_re"].search(val):
                    # frp SNI => tunnel; other c2 => R-TRAF-007
                    if s.get("category") == "tunnel":
                        emit(findings, "R-TRAF-201", rec,
                             {"sig_id": s.get("id"), "tool": s.get("tool")})
                    else:
                        emit(findings, "R-TRAF-007", rec,
                             {"sig_id": s.get("id"), "tool": s.get("tool")})

            # v0.3-M1 TLS deepening (JA3/JA3S/GM/domain-fronting)
            _tls_alert_v03_extra(rec, findings, _v03["tls"])
            # v0.3-M1 also allow CN-tool signature (Viper SNI etc.)
            _cn_tool_alert_v03_extra(rec, findings, _v03["http"])

        # ============== flow-view rules ==============
        elif view == "flow":
            bytes_a2b = raw.get("bytes_a2b") or 0
            duration = raw.get("duration_s") or 0.0
            pkts = raw.get("packets_total") or 0
            bytes_total = raw.get("bytes_total") or 0
            dst_port = rec.get("dst_port")

            # R-TRAF-008 reverse-shell listener port + long-lived
            if dst_port in REV_SHELL_PORTS and duration > 300:
                emit(findings, "R-TRAF-008", rec,
                     {"narrative": "reverse-shell listener port + long conn",
                      "duration_s": duration, "dst_port": dst_port})

            # R-TRAF-010 large outbound stream
            if bytes_a2b > 50 * 1024 * 1024 and duration > 60:
                emit(findings, "R-TRAF-010", rec,
                     {"narrative": "large outbound stream >50MB",
                      "bytes_a2b": bytes_a2b, "duration_s": duration})

            # R-TRAF-011 c2 heartbeat: many small packets, long-lived
            if pkts > 100 and duration > 1800:
                bpp = (bytes_total / pkts) if pkts else 0
                if bpp < 200:
                    emit(findings, "R-TRAF-011", rec,
                         {"narrative": "heartbeat pattern (small packets, long conn)",
                          "packets": pkts, "avg_bytes_per_pkt": f"{bpp:.1f}",
                          "duration_s": duration})

            # R-TRAF-101 SMB named pipe lateral
            if dst_port in (445, 139):
                emit(findings, "R-TRAF-101", rec,
                     {"narrative": "SMB traffic to 445/139 (context needed)",
                      "duration_s": duration, "bytes_total": bytes_total})

            # R-TRAF-103 RDP fan-in
            if dst_port == 3389 and rec.get("src_ip") and rec.get("dst_ip"):
                key = rec["dst_ip"]
                rdp_fanin[key].add(rec["src_ip"])
                if len(rdp_fanin[key]) >= 5 and key not in rdp_fanin_emitted:
                    emit(findings, "R-TRAF-103", rec,
                         {"narrative": "RDP fan-in (>=5 distinct src_ips)",
                          "distinct_src_ips": len(rdp_fanin[key])})
                    rdp_fanin_emitted.add(key)

            # R-TRAF-201 frp default port
            if dst_port in (7000, 7500, 7001):
                emit(findings, "R-TRAF-201", rec,
                     {"narrative": "frp default port hit",
                      "dst_port": dst_port, "duration_s": duration})

            # R-TRAF-202 nps default port
            if dst_port in (8024, 8082):
                emit(findings, "R-TRAF-202", rec,
                     {"narrative": "nps default port hit",
                      "dst_port": dst_port})

            # signature payload/flow rules
            for s in sig_by_view.get("flow", []):
                fld = s.get("field")
                val = ""
                if fld == "dst_port":
                    val = str(dst_port) if dst_port is not None else ""
                elif fld == "payload_first_bytes":
                    # pcap_parser 输出为 latin-1 str（前 16 字节），\xNN 签名直接 search
                    val = raw.get("payload_first_bytes") or ""
                if val and s["_re"].search(val):
                    cat = s.get("category")
                    tool = (s.get("tool") or "").lower()
                    if "psexec" in tool or "winexe" in tool:
                        emit(findings, "R-TRAF-102", rec,
                             {"sig_id": s.get("id"), "tool": s.get("tool")})
                    elif "wmi" in tool:
                        emit(findings, "R-TRAF-104", rec,
                             {"sig_id": s.get("id"), "tool": s.get("tool")})
                    elif "smb" in tool or "svcctl" in tool or "samr" in tool:
                        emit(findings, "R-TRAF-101", rec,
                             {"sig_id": s.get("id"), "tool": s.get("tool")})
                    elif cat == "tunnel":
                        if "frp" in tool:
                            emit(findings, "R-TRAF-201", rec,
                                 {"sig_id": s.get("id"), "tool": s.get("tool")})
                        elif "nps" in tool:
                            emit(findings, "R-TRAF-202", rec,
                                 {"sig_id": s.get("id"), "tool": s.get("tool")})
                        else:
                            emit(findings, "R-TRAF-203", rec,
                                 {"sig_id": s.get("id"), "tool": s.get("tool")})
                    elif cat == "c2":
                        emit(findings, "R-TRAF-008", rec,
                             {"sig_id": s.get("id"), "tool": s.get("tool")})

        # ============== creds-view rules ==============
        elif view == "creds":
            auth = (raw.get("auth_type") or "").lower()
            emit(findings, "R-TRAF-009", rec,
                 {"narrative": f"cleartext credential ({auth})",
                  "auth_type": auth,
                  "username": _mask(raw.get("username") or "", 40),
                  "password_masked": raw.get("password_masked")})

        # v0.3-M1 flow-view CN tool markers (loader pulse beacon)
        if view == "flow":
            _cn_tool_alert_v03_extra(rec, findings, _v03["http"])

        # Track cross-rule per-IP correlation
        if findings:
            latest = findings[-1]
            src = latest["evidence"].get("src_ip")
            rid = latest["rule_id"]
            if src:
                if rid not in per_ip_rules[src]:
                    per_ip_rules[src].add(rid)
                    per_ip_first_ts.setdefault(src, latest["evidence"].get("ts") or "")

    # R-TRAF-999 correlation cluster
    # v0.3-M1 extension: if src hit rules from >=2 of the three clusters
    # (TLS 050-069 / DNS 070-084 / CN-tool 085-098), attach apt-suspect tag.
    _TLS_CLUSTER = {f"R-TRAF-{i:03d}" for i in range(50, 70)}
    _DNS_CLUSTER = {f"R-TRAF-{i:03d}" for i in range(70, 85)}
    _CN_CLUSTER = {f"R-TRAF-{i:03d}" for i in range(85, 99)}

    for src, rule_set in per_ip_rules.items():
        distinct = {r for r in rule_set if r != "R-TRAF-999"}
        if len(distinct) >= 3:
            cluster_hit = 0
            hit_names = []
            if distinct & _TLS_CLUSTER:
                cluster_hit += 1
                hit_names.append("tls-deep")
            if distinct & _DNS_CLUSTER:
                cluster_hit += 1
                hit_names.append("dns-covert")
            if distinct & _CN_CLUSTER:
                cluster_hit += 1
                hit_names.append("cn-redteam")
            extra_narr = f"src_ip {src} hit {len(distinct)} distinct rules"
            emit_extra = {
                "narrative": extra_narr,
                "distinct_rules": sorted(distinct),
            }
            if cluster_hit >= 2:
                emit_extra["tag"] = "apt-suspect"
                emit_extra["cluster_hits"] = hit_names
                emit_extra["narrative"] = (
                    f"{extra_narr}; apt-suspect (crossed {cluster_hit} clusters: "
                    f"{', '.join(hit_names)})"
                )
            emit(findings, "R-TRAF-999",
                 {"src_ip": src, "dst_ip": None, "src_port": None,
                  "dst_port": None, "proto": None, "view": "correlation",
                  "src_file": None, "line_no": None,
                  "ts": per_ip_first_ts.get(src),
                  "raw": {}},
                 emit_extra)

    return findings


# --------------------------------------------------------------------------- #
# I/O + CLI                                                                   #
# --------------------------------------------------------------------------- #


def iter_ndjson(path: str) -> Iterator[dict]:
    yield from _hc.iter_ndjson(path, predicate=lambda r: r.get("view"))


def parse_args(argv=None):
    p = argparse.ArgumentParser(
        description="Traffic anomaly rule engine over pcap_parser NDJSON"
    )
    p.add_argument("--input", required=False,
                   help="NDJSON from pcap_parser.py (use - for stdin)")
    p.add_argument("--signatures", default=None,
                   help="traffic-signatures.json (default: ../data/traffic-signatures.json)")
    p.add_argument("--output", default=None, help="Output JSON file")
    p.add_argument("-q", "--quiet", action="store_true")
    p.add_argument("-v", "--verbose", action="store_true")
    p.add_argument("--self-test", action="store_true",
                   help="Run built-in v0.3-M1 self-test samples and exit")
    return p.parse_args(argv)


# --------------------------------------------------------------------------- #
# v0.3-M1 self-test samples                                                   #
# --------------------------------------------------------------------------- #

# self-test-samples: 5 synthetic NDJSON records targeting different new rules.
SELF_TEST_SAMPLES = [
    # (1) TLS JA3 hit -> R-TRAF-050 (CobaltStrike default JA3)
    {"ts": "2026-07-01T02:00:00Z", "view": "tls",
     "src_ip": "10.0.0.5", "dst_ip": "203.0.113.10",
     "src_port": 55555, "dst_port": 443, "proto": "tcp", "stream_id": 1,
     "src_file": "synthetic", "line_no": 1,
     "raw": {"sni": "cdn.example.com",
             "cert_cn": "Major Cobalt Strike",
             "cert_issuer": "Major Cobalt Strike",
             "cipher": "TLS_RSA_WITH_AES_256_CBC_SHA",
             "ja3": "72a589da586844d7f0818ce684948eea",
             "alpn": "h2", "host": "cdn.example.com"}},
    # (2) DNS TXT flood + long qname -> R-TRAF-070 / R-TRAF-071 / R-TRAF-073
    # Wrapped as a series of synthetic queries via helper below.
    # (3) CN webshell Behinder v3 -> R-TRAF-085
    {"ts": "2026-07-01T02:05:00Z", "view": "http",
     "src_ip": "192.0.2.10", "dst_ip": "10.0.0.100",
     "src_port": 40000, "dst_port": 80, "proto": "tcp", "stream_id": 3,
     "src_file": "synthetic", "line_no": 2,
     "raw": {"ua": "Mozilla/5.0",
             "uri": "/upload/index.jsp",
             "host": "web.example",
             "method": "POST", "content_type": "application/octet-stream",
             "content_length": 512,
             "request_line_excerpt": "POST /upload/index.jsp HTTP/1.1\r\n"
             "Cookie: rememberMe=deleteMe; Pass: e45e329feb5d925babcdefabcdef1234\r\n"
             "Content-Type: application/octet-stream"}},
    # (4) suo5 tunnel marker -> R-TRAF-095
    {"ts": "2026-07-01T02:07:00Z", "view": "http",
     "src_ip": "192.0.2.11", "dst_ip": "10.0.0.101",
     "src_port": 40001, "dst_port": 80, "proto": "tcp", "stream_id": 4,
     "src_file": "synthetic", "line_no": 3,
     "raw": {"ua": "Mozilla/5.0",
             "uri": "/suo5",
             "host": "internal.example",
             "method": "POST", "content_type": "application/octet-stream",
             "content_length": 4096,
             "request_line_excerpt": "POST /suo5 HTTP/1.1\r\nUpgrade: websocket\r\n"
             "X-Suo5-Ver: 1"}},
    # (5) neo-regeorg -> R-TRAF-096
    {"ts": "2026-07-01T02:08:00Z", "view": "http",
     "src_ip": "192.0.2.12", "dst_ip": "10.0.0.102",
     "src_port": 40002, "dst_port": 80, "proto": "tcp", "stream_id": 5,
     "src_file": "synthetic", "line_no": 4,
     "raw": {"ua": "Mozilla/5.0", "uri": "/tunnel.jsp",
             "host": "app.example",
             "method": "POST", "content_type": "application/octet-stream",
             "content_length": 200,
             "request_line_excerpt": "POST /tunnel.jsp HTTP/1.1\r\n"
             "X-CMD: CONNECT\r\n"}},
    # (6) Viper SNI + JA3S CN mod -> R-TRAF-052 / R-TRAF-089
    {"ts": "2026-07-01T02:09:00Z", "view": "tls",
     "src_ip": "192.0.2.13", "dst_ip": "198.51.100.5",
     "src_port": 40003, "dst_port": 443, "proto": "tcp", "stream_id": 6,
     "src_file": "synthetic", "line_no": 5,
     "raw": {"sni": "viper.example",
             "cert_cn": "Sliver",
             "cipher": "ECDHE-SM2-SM4",
             "ja3s": "ec74a5c51106f0419184d0dd08fb05bc",
             "host": "viper.example"}},
]


def _gen_dns_flood_samples() -> list[dict]:
    """Generate synthetic DNS records to trigger R-TRAF-070/071/073."""
    base_ts = datetime(2026, 7, 1, 3, 0, 0, tzinfo=timezone.utc)
    out = []
    for i in range(40):
        # 40 TXT queries with long high-entropy first labels under same parent
        label = f"{'abcdef1234567890' * 3}{i:04d}"  # >40 chars, high entropy
        qname = f"{label}.tunnel.example.com"
        ts = (base_ts + timedelta(seconds=i * 3)).isoformat()
        out.append({
            "ts": ts, "view": "dns",
            "src_ip": "10.0.0.7", "dst_ip": "8.8.8.8",
            "src_port": 40000 + i, "dst_port": 53, "proto": "udp",
            "stream_id": None,
            "src_file": "synthetic", "line_no": 100 + i,
            "raw": {"qname": qname, "qtype": "TXT", "rcode": 0,
                    "response_ip": None, "payload_len": 512},
        })
    return out


def run_self_test() -> int:
    """Run synthetic samples and print rule_id hit summary."""
    from datetime import timezone as _tz  # noqa
    samples = list(SELF_TEST_SAMPLES) + _gen_dns_flood_samples()
    findings = detect(iter(samples), sigs=[])
    hit_rules = sorted({f["rule_id"] for f in findings})
    new_rules = [r for r in hit_rules if r >= "R-TRAF-050" and r < "R-TRAF-100"]
    print(f"[self-test] total_samples={len(samples)} total_findings={len(findings)}")
    print(f"[self-test] all rule_ids hit: {hit_rules}")
    print(f"[self-test] new (v0.3-M1) rule_ids hit: {new_rules}")
    # PASS if we hit >=5 distinct new rules
    passed = len(new_rules) >= 5
    print(f"[self-test] result: {'PASS' if passed else 'FAIL'} "
          f"({len(new_rules)} new rules triggered, need >=5)")
    return 0 if passed else 3


def main(argv=None) -> int:
    args = parse_args(argv)
    if args.self_test:
        return run_self_test()
    if not args.input:
        print("[ERROR] --input is required (or use --self-test)", file=sys.stderr)
        return 1
    sig_path = Path(args.signatures) if args.signatures else \
        (Path(__file__).resolve().parent.parent / "data" / "traffic-signatures.json")
    sigs = compile_signatures(load_signatures(sig_path))
    if args.verbose:
        print(f"[traffic_anomaly] loaded {len(sigs)} signatures from {sig_path}",
              file=sys.stderr)

    findings = detect(iter_ndjson(args.input), sigs)

    output = {
        "version": "0.3-M1",
        "total": len(findings),
        "findings": findings,
    }
    text = json.dumps(output, ensure_ascii=False, indent=2)
    if args.output:
        Path(args.output).write_text(text, encoding="utf-8")
    else:
        print(text)
    if args.verbose:
        c = Counter(f["rule_id"] for f in findings)
        print(f"[traffic_anomaly] by_rule={dict(c)}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
    except FileNotFoundError as e:
        print(f"[ERROR] {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:  # noqa: BLE001
        print(f"[ERROR] runtime: {e}", file=sys.stderr)
        sys.exit(2)
