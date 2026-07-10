# Playbook: 流量审计（Traffic Audit）

> 适用模式：audit
> 难度：★★★★☆
> 平均处置时间：60-180 分钟（视 pcap 大小与命中数）
> rule_id 前缀：`PLB-TA-NNN`

> **何时使用**：客户提交 pcap / SIEM 定位阶段拉出流量证据 / IR 阶段的流量取证 / 疑似横向定位攻击路径 / 数据外发嫌疑核查。

---

## 1. 攻击面概述

护网期间蓝队做 pcap 审计的典型场景：

- **客户提交 pcap 请我们分析**：客户在 SIEM 收到告警但看不懂原始流量，把镜像抓包 pcap 交给蓝队，需要 30-60 min 内给出定性 + 定位。
- **SIEM 告警定位阶段**：SIEM 只报了"src_ip 有可疑行为"，需要抓包深入看具体 payload 才能定级。
- **IR 阶段的流量取证**：主机确认被入侵后，需要审计与外部通信的历史流量，还原攻击者操作序列。
- **客户内部横向可疑**：主机 A 与主机 B 之间流量异常，从 pcap 中判断是横向 & 使用了什么工具。
- **数据外发嫌疑核查**：主机流量异常大，判断是否有数据被打包外传。

MITRE ATT&CK 战术映射：pcap 审计覆盖 `Discovery (T1046)` / `Lateral Movement (TA0008)` / `Command and Control (TA0011)` / `Exfiltration (TA0010)` / `Impact (TA0040)` 的流量证据。

---

## 2. 输入前置条件

- **pcap / pcapng 文件**：wireshark 或 tcpdump 抓包产物
- **客户已确认可交付分析**：脱敏 / 授权范围明确
- **时间范围**：客户告知抓包起止时间（用于对齐主机侧日志）
- **抓包位置说明**：镜像口 / 网关口 / 主机 tcpdump —— 决定单向 / 双向流量的可见性
- **已知业务白名单**（可选但强烈建议）：
  - 客户内部服务器 IP 段
  - 正常出站域名清单
  - 内部漏扫 / 探活工具 IP
  - 堡垒机 IP
  - CDN IP 段

如果这些不齐，先跑 `capinfos` 看 pcap 摘要，再让客户补齐白名单。

---

## 3. 六步工作流

### 步骤 1：pcap 完整性检查

**做什么**：确认 pcap 可读、时长、包数、是否截断。

**用什么**：

```bash
# 类型判定
file <pcap>
# 期望：pcap capture file 或 pcapng

# 摘要信息
capinfos <pcap>
# 关注字段：Number of packets / File Size / Capture duration / Packet size limit
```

**判定标准**：

- 有 "Packet size limit: 0 bytes" → snaplen 未截断，好
- 有 "Packet size limit: 68 bytes" 之类 → 只抓了 header，无法看 payload，需要与客户重新抓包
- Number of packets = 0 → 文件损坏
- Capture duration 与客户预期不匹配 → 时间对齐核对

**关联 rule_id**：`PLB-TA-001`（pcap 完整性）

> 🔍 **检查点 A（审核）**：本步为确定性步骤，异常时触发 `agents/checkpoint-reviewer` 审核（命中合理性 + 误报剔除）。

---

### 步骤 2：归一化抠取

**做什么**：把 pcap 拆分为 6 大视图 NDJSON，便于后续脚本处理。

**用什么**：

```bash
scripts/pcap_parser.py \
  --input <pcap> \
  --views http,dns,tls,flow,creds,conn \
  --output /tmp/pcap-normalized.ndjson
```

**输出结构**（每行一条 event，含 view 字段）：

```json
{"view": "http", "ts": 1719734400, "src_ip": "192.168.1.100", "src_port": 45678, "dst_ip": "203.0.113.5", "dst_port": 80, "method": "POST", "uri": "/upload.php", "ua": "curl/7.68.0", ...}
{"view": "dns", "ts": 1719734401, "qname": "customer.example.com", "qtype": "A", "rdata": "...", "src_ip": "192.168.1.100", ...}
```

**判定标准**：

- 每类 view 至少有 1 条 event 输出
- src_ip / dst_ip 提取正确
- 时间戳格式统一（Unix epoch）

**关联 rule_id**：`PLB-TA-002`（归一化抠取完成）

> 🔍 **检查点 A（审核）**：本步为确定性步骤，异常时（0 记录 / 字段全空）触发 `agents/checkpoint-reviewer` 审核（命中合理性 + 误报剔除）。

---

### 步骤 3：IOC 匹配

**做什么**：用内置 IOC + 客户提供的 IOC 匹配已归一化的流量。

**用什么**：

```bash
scripts/ioc_match.py \
  --logs /tmp/pcap-normalized.ndjson \
  --builtin \
  --extra-iocs /path/to/customer-iocs.json \
  --output /tmp/ioc-hits.json
```

**输出**：命中的 IOC 条目 + 事件行号 + 命中类型（ip / domain / hash / ua / path 等）

**判定标准**：

- 高置信 IP 命中 → P1 起步
- 高置信 domain / SNI 命中 → P1 起步
- UA 指纹命中已知恶意工具 → P1 起步
- hash 命中（webshell / 木马文件） → P0

**关联 rule_id**：`PLB-TA-003`（IOC 匹配完成）

> **🔍 检查点 A（审核）**：本步完成后**必跑** `agents/checkpoint-reviewer`（确定性步骤仅异常时触发）。审核命中合理性 + 误报剔除（P2/P3 聚合统计，P0/P1 抽样逐条）。审核通过进检查点 B。

---

### 步骤 4：异常检测

**做什么**：跑运行时规则引擎，扫出所有 `R-TRAF-NNN` 命中。

**用什么**：

```bash
scripts/traffic_anomaly.py \
  --input /tmp/pcap-normalized.ndjson \
  --output /tmp/anomalies.json
```

**输出结构**（每条命中含 8 字段，符合 SKILL.md 输出契约）：

```json
{
  "id": "AUD-TRAF-001",
  "severity": "P0",
  "category": "c2",
  "rule_id": "R-TRAF-053",
  "evidence": "flow src=192.168.1.xxx dst=203.0.113.5:443 JA3=72a589da586844d7f0818ce684948eea",
  "false_positive_prob": 0.15,
  "recommended_action": "参考 references/playbooks/command-exec.md",
  "iocs": [...]
}
```

**判定标准**：按 severity 排序，P0/P1 立即进入下一步深挖，P2/P3 记录。

**关联 rule_id**：`PLB-TA-004`（异常检测完成）

> **🔍 检查点 A（审核）**：本步完成后**必跑** `agents/checkpoint-reviewer`（确定性步骤仅异常时触发）。审核命中合理性 + 误报剔除（P2/P3 聚合统计，P0/P1 抽样逐条）。审核通过进检查点 B。

---

### 步骤 4.5：流量研判（traffic-analyst）

**做什么**：由 LLM 决策 agent 对前序脚本结果做跨视图关联 + 误报研判 + 盲区发现 + 升级决策，输出流量研判报告。这是 traffic 模式新增的 LLM 决策环节，对标 audit 模式的 log-analyzer。

**输入**：
- pcap_parser 六视图归一化结果（`/tmp/pcap-normalized.ndjson`）
- traffic_anomaly findings（`/tmp/anomalies.json`）
- ioc_match 命中（`/tmp/ioc-hits.json`）

**输出**：流量研判报告（verdict + 攻击链），供步骤 5 横向 / 隧道判定与步骤 6 交付引用。

> **🧭 检查点 B（决策）**：**必跑** `agents/traffic-analyst` 做跨视图关联 + 误报研判 + 盲区发现 + 升级决策，输出流量研判报告（verdict + 攻击链）。

**关联 rule_id**：`PLB-TA-004.5`（流量研判）

---

### 步骤 5：横向 & 隧道判定

**做什么**：针对内网横向 / 出网隧道两大重点专门核查。

**参考**：

- 内网横向：`references/attack-patterns/windows-lateral-traffic.md`
- 出网隧道：`references/attack-patterns/tunnel-tools-traffic.md`

**关键指标**：

- **横向嫌疑**：内网 src → 内网 dst 的 445 / 3389 / 5985 / 135+ 高端口 / 88 端口有异常
- **隧道嫌疑**：内网 src → 外网 dst 的长连接 + 非业务白名单目的 IP

**用什么**：

```bash
# 内网 SMB / RDP / WMI 统计
tshark -r <pcap> -Y "ip.src == 192.168.0.0/16 and ip.dst == 192.168.0.0/16" \
  -T fields -e ip.src -e ip.dst -e tcp.dstport | sort | uniq -c | sort -rn

# 长连接（> 1h）
tshark -r <pcap> -q -z conv,tcp | awk 'NR>5 && $8 > 3600'
```

**判定标准**：命中 §5.2 § / §5.3 之横向 / 隧道特征 3 项以上 → P0。

**关联 rule_id**：`PLB-TA-005`（横向 & 隧道判定）

---

> **✅ 检查点 C（验证）**：出终报前**必跑** `agents/verdict-validator` 验证 verdict 证据闭环 + 攻击链时间线自洽。rejected 打回检查点 B 重做。

### 步骤 6：交付

**做什么**：把前 5 步结果汇总，脱敏后填入报告模板。

**用什么**：

```bash
# 脱敏
scripts/desensitize.py --input /tmp/anomalies.json --output /tmp/anomalies-safe.json

# 填入模板
# audit 模式 → assets/daily-report.md
# ir 模式 → assets/incident-report.md
```

**判定标准**：交付前 checklist：

- [ ] 所有 P0/P1 条目都有 evidence + rule_id
- [ ] 所有 src_ip / dst_ip / domain / user 都已脱敏
- [ ] IOC 列表按 SKILL.md 的 7 字段 schema 输出
- [ ] 报告顶部有事件概览 + 时间线
- [ ] 报告末尾有止血 / 根除 / 恢复建议

**关联 rule_id**：`PLB-TA-006`（交付完成）

---

## 4. 常见 pcap 审计场景

### 场景 A：客户告警要看具体流量证据

**触发**：客户 SIEM 告警"src_ip 有 SQLi 嫌疑"但不知道具体 payload，扔 pcap 让蓝队看。

**照做清单**：

1. `capinfos <pcap>` 确认 pcap 完整
2. `pcap_parser.py --views http` 只抠 http 视图节省时间
3. `traffic_anomaly.py` 跑规则，过滤 category == "sqli"
4. 定位到具体 URI + payload，脱敏后示给客户看
5. 反查该 URI 的所有请求（同 src_ip / 同 URI），看是否有成功回显（响应长度突变）
6. 判定：命中 payload 且响应异常 → P1；仅试探未成功 → P2
7. 输出：填 `assets/daily-report.md`，附上 pcap 切片 + tshark 命令供客户复现

**关联 rule_id**：`PLB-TA-011`

---

### 场景 B：主机失陷后做流量取证

**触发**：主机已确认被入侵（IR 阶段），需要看历史流量还原攻击者操作。

**照做清单**：

1. 拉取失陷主机对应时段的 pcap（客户提供或自己抓）
2. `pcap_parser.py --views http,dns,tls,flow,conn` 全视图抠取
3. `ioc_match.py` 匹配已知威胁情报 / 内置 IOC
4. `traffic_anomaly.py` 全规则扫
5. 按时间线排序：从**最早的可疑事件**开始，标记每一步（初次扫描 → payload 试探 → 命中 → 上传 → 横向 → 外联 C2）
6. 提取 IOC：攻击者 IP / C2 域名 / 工具 UA / webshell URL / 落地文件 hash
7. 输出：填 `assets/incident-report.md`，含攻击链时间线 + 完整 IOC 列表
8. 与主机侧证据对齐：进程时间 / 文件 mtime / bash_history

**关联 rule_id**：`PLB-TA-012`

---

### 场景 C：疑似内网横向定位攻击路径

**触发**：SIEM 提示"内网主机之间流量异常"，需要定位攻击路径。

**照做清单**：

1. 从 pcap 中过滤内网 → 内网流量
2. 重点看 SMB (445) / RDP (3389) / WMI (135+ 高端口) / WinRM (5985) / Kerberos (88)
3. 参考 `windows-lateral-traffic.md` 逐通道识别（PsExec / wmiexec / evil-winrm / Kerberoasting）
4. 画出主机连接关系图：谁 → 谁 → 谁
5. 定位**攻击链起点主机**（通常是最早出现 445 出站的主机）
6. 检查每个中间跳板：是否有 Impacket 类工具指纹 / 命名管道特征
7. 输出：攻击路径图 + 每一跳的 rule_id + 建议隔离主机清单

**关联 rule_id**：`PLB-TA-013`

---

### 场景 D：数据外发嫌疑核查

**触发**：主机流量异常大 / SIEM 告警数据外发 / 出网 IP 白名单外。

**照做清单**：

1. `pcap_parser.py --views http,flow,tls` 抠取
2. 统计每个 src_ip 的出站总字节数 + 长连接数（`tshark -q -z conv,tcp`）
3. 检查 HTTP 大 body 上传（`R-TRAF-096`）：Content-Length > 10MB 的 POST
4. 检查隧道工具（参考 `tunnel-tools-traffic.md`）：frp / nps / chisel / gost / stowaway
5. 检查公有云上传：`mega.nz` / `transfer.sh` / `filebin.net` / 非业务 S3
6. 检查 DNS 隧道（`R-TRAF-071` ~ `R-TRAF-074`）：长 qname / TXT 高频
7. 判定：命中任一 P0 隧道特征 + 大量数据 → 确认外发
8. 输出：外发 IOC（目的 IP / 域名 / 工具指纹） + 估算数据量 + 时间窗

**关联 rule_id**：`PLB-TA-014`

---

## 5. 关联分析

参考 `references/modes/audit.md` 的关联维度，本 playbook 重点关注：

### 5.1 跨视图关联（强信号）

- **同 src_ip 命中多视图**：http（扫描 / RCE 试探） + dns（C2 域名查询） + flow（长连接外联） = 强信号，直接 P0
- **单流长时间 + 大字节**：flow 视图中单 TCP 会话 > 1h + > 100MB → 数据外发嫌疑

### 5.2 跨规则关联（升级）

- **单 src 5 分钟内跨 3 类 rule_id**：例如同时命中 `R-TRAF-001`（扫描器） + `R-TRAF-021`（RCE 试探） + `R-TRAF-041`（webshell 通信） → 关联簇升级 P0

### 5.3 跨模式关联

- audit 命中的攻击者 IP → 反查 monitor 阶段是否有同 IP 告警（可能被误标 P3）
- audit 命中的 webshell URI → 反查主机侧文件是否已落地（升级 IR 模式）

### 5.4 关联升级判据表

| 单条命中 | 关联条件 | 升级为 |
|---|---|---|
| P2 扫描器命中 | 同 src 后续 5 min 内出现 payload 命中 | P1 |
| P1 payload 命中 | 响应 200 + 后续同 URI 出现 webshell 特征 | P0 |
| P1 隧道嫌疑 | 主机侧确认异常进程 | P0 |
| P1 数据外发 | 单流 > 100MB | P0 |
| P0 命中 | 3 台以上主机横向 | 全面 IR |

---

## 6. 误报排查清单

| # | 误报特征 | 如何排除 |
|---|---|---|
| 1 | 内部漏扫工具（绿盟 / 启明 / nessus） | src_ip 在客户漏扫白名单，时段是已报备时段 |
| 2 | CDN / 反代（多层代理导致 src_ip 出错） | 检查 X-Forwarded-For / Real-IP 头，还原真实客户端 |
| 3 | 健康检查（/healthz /metrics /_status） | 路径固定，请求节奏固定，来源固定，加白 |
| 4 | 备份任务（凌晨大流量 rsync / scp） | 时间窗对齐，源目对齐运维备份服务器 |
| 5 | CI/CD 部署流量 | 与发布平台日志对账 |
| 6 | 监控 agent（Prometheus / Zabbix） | 目的端口固定（9100 / 10050），源固定 |
| 7 | 业务 SDK 心跳（微信推送 / APM） | 目的域名可查（明确的商业 SDK 域名） |
| 8 | 蜜罐 / 靶场流量 | 与客户 CTF / 演练报备对齐 |
| 9 | 远程办公 SDK（TeamViewer / AnyDesk） | 域名可查（明确商业服务） |
| 10 | 云 SDK 心跳（SLS / CloudWatch） | 目的域名可查（阿里云 / AWS 官方域名） |

**误报判定原则**：能与"已知正常运维行为 / 已报备测试 / 已认证后台操作"对账上的，标 `false_positive_prob >= 0.8`，进 P3。

---

## 7. 止血 / 根除 / 恢复（3 阶段）

### 7.1 止血（Containment）

#### 网络层

| 动作 | 操作要点 | 副作用 | 回退路径 |
|---|---|---|---|
| 边界防火墙 ban 攻击 IP | iptables / 边界 ACL drop | 误伤同 NAT 出口 | 24h 观察后固化 |
| WAF ban 攻击 IP + URI | 联合规则 | 同上 | 分级观察 |
| 出口 DNS 加过滤（针对 C2 / 隧道域名） | 在客户 DNS server 加黑洞 | 影响业务解析（如误加）| 域名白名单核对 |
| 出口封 VPS 段 | 防火墙加 CIDR 黑名单 | 影响正常访问该云 VPS | 域名 / IP 白名单核对 |
| 内网 VLAN 隔离（横向嫌疑主机） | 交换机端口 ACL | 主机业务中断 | 根除后回接 |

#### 主机层

| 动作 | 操作要点 | 副作用 | 回退路径 |
|---|---|---|---|
| 隔离主机 | 摘出负载均衡 / 切换到管理 VLAN | 业务流量切备机 | 根除 + 验证后回切 |
| 保留 pcap 切片作为证据 | `tcpdump -w evidence.pcap -r <original> host <攻击IP>` | 无 | 无 |

#### 应用层

| 动作 | 操作要点 | 副作用 | 回退路径 |
|---|---|---|---|
| 临时下线漏洞 URL | nginx location 加 return 403 | 业务功能不可用 | 修复后回滚 |
| 关闭异常出站进程 | `kill -9 <pid>` | 可能丢失内存证据 | 建议先 dump 后 kill |

#### 账号层

| 动作 | 操作要点 | 副作用 | 回退路径 |
|---|---|---|---|
| 重置涉事账户口令 | AD / 应用后台改密 | 短期影响 | 已通知运维 |
| 撤销异常 kerberos ticket | KDC 强制重发 TGT | 需要重登录 | 无 |

### 7.2 根除（Eradication）

1. **删除落地文件**：pcap 中提取到的下载 URL / 落地路径 → 主机侧 `find` 定位并处理
2. **清除隧道进程**：主机侧 kill 掉 frp / chisel / gost / stowaway 等进程
3. **清除持久化**：crontab / systemd / authorized_keys 检查
4. **修补入口漏洞**：升级组件 / 改配置 / 加 WAF 规则

### 7.3 恢复（Recovery）

- 优先：基线快照回滚（提前有可信快照的话）
- 次选：保留快照 → 重装 → 还原业务数据（数据先扫描）
- 末选：原地清理后继续运行（仅在不能停机 + 根除完整时）

### 7.4 验证点

1. **流量层验证**：原攻击 IP 的请求全部 4xx / 无法连接
2. **主机层验证**：可疑进程 / 长连接均已清除
3. **DNS 层验证**：原 C2 域名解析被阻断（或已下线）
4. **WAF 层验证**：原命中规则在 24h 内复发率为 0

---

## 8. IOC 提取模板

遵循 SKILL.md 的 IOC 7 字段 schema。pcap 审计常见 IOC 类型：

| IOC type | 提取路径 | 示例值 | 置信度 |
|---|---|---|---|
| ip | 攻击者 src_ip / C2 dst_ip | `192.168.1.xxx` / `203.0.113.5` | high |
| domain | DNS 查询 / SNI / Host header | `<internal>` / `customer.example.com` | high |
| url | 恶意 URI 完整值 | `http://customer.example.com/upload/x.jsp` | high |
| ua | HTTP User-Agent | `sqlmap/1.7` / `antSword/v2.1` | high |
| ja3 | TLS JA3 指纹 | `72a589da586844d7f0818ce684948eea` | medium |
| cert-cn | TLS 证书 CN | `Major Cobalt Strike` | medium |
| sni | TLS SNI | `<empty>` / `customer.example.com` | medium |
| tool | 工具名 | `godzilla` / `frp` / `chisel` | medium |
| hash:sha256 | pcap 中传输的文件 hash（可提取 http body） | `<sha256>` | high |

### 提取示例

```json
[
  {
    "type": "ip",
    "value": "192.168.1.xxx",
    "confidence": "high",
    "first_seen": "2026-06-30T09:12:33+08:00",
    "source": "pcap:1.pcap:packet-12453",
    "tag": "attacker-ip,c2-src",
    "description": "对 customer.example.com 发起 CS beacon 通信"
  },
  {
    "type": "domain",
    "value": "customer.example.com",
    "confidence": "high",
    "first_seen": "2026-06-30T09:12:35+08:00",
    "source": "pcap:1.pcap:dns-view",
    "tag": "c2-domain",
    "description": "CS malleable profile default path 命中"
  },
  {
    "type": "ja3",
    "value": "72a589da586844d7f0818ce684948eea",
    "confidence": "medium",
    "first_seen": "2026-06-30T09:12:38+08:00",
    "source": "pcap:1.pcap:tls-view",
    "tag": "c2:cobaltstrike,default-jre",
    "description": "CS 默认 Java keytool JA3"
  },
  {
    "type": "tool",
    "value": "cobaltstrike",
    "confidence": "high",
    "first_seen": "2026-06-30T09:12:33+08:00",
    "source": "rule:R-TRAF-053",
    "tag": "c2-framework"
  }
]
```

提取重点：

- 攻击者 IP（外部 src / C2 dst）
- C2 / 隧道域名
- 工具指纹（框架名 / 特征 UA / JA3）
- webshell URL
- 落地文件 hash（如果 pcap 抓到了完整 body）

---

## 附录 A：常用 tshark filter 备忘

蓝队日常最常用 30 个 tshark filter，覆盖 pcap 审计全场景。

### HTTP 层

```bash
# 所有 HTTP 请求
tshark -r <pcap> -Y "http.request"

# 特定 URI
tshark -r <pcap> -Y 'http.request.uri contains "/upload"'

# 特定 UA
tshark -r <pcap> -Y 'http.user_agent contains "sqlmap"'

# 4xx 响应
tshark -r <pcap> -Y "http.response.code >= 400 and http.response.code < 500"

# POST 请求
tshark -r <pcap> -Y "http.request.method == POST"

# 大 body POST
tshark -r <pcap> -Y "http.request.method == POST and http.content_length > 10000"
```

### DNS 层

```bash
# 所有 DNS 查询
tshark -r <pcap> -Y "dns"

# TXT 记录
tshark -r <pcap> -Y "dns.qry.type == 16"

# 长 qname
tshark -r <pcap> -Y "dns.qry.name matches \".{50,}\""

# NXDOMAIN
tshark -r <pcap> -Y "dns.flags.rcode == 3"
```

### TLS 层

```bash
# 所有 TLS ClientHello
tshark -r <pcap> -Y "tls.handshake.type == 1"

# SNI 提取
tshark -r <pcap> -Y "tls.handshake.extensions_server_name" \
  -T fields -e tls.handshake.extensions_server_name | sort -u

# 空 SNI
tshark -r <pcap> -Y "tls.handshake.type == 1 and !tls.handshake.extensions_server_name"

# JA3 计算需要 tshark 3.x + 插件
```

### SMB / RDP / WMI 层

```bash
# SMB2 命令
tshark -r <pcap> -Y "smb2"

# SMB2 命名管道
tshark -r <pcap> -Y 'smb2.filename contains "\\PIPE\\"'

# RDP 会话
tshark -r <pcap> -Y "tcp.port == 3389 and tls.handshake"

# DCE/RPC
tshark -r <pcap> -Y "dcerpc"
```

### 流量统计

```bash
# TCP 会话统计
tshark -r <pcap> -q -z conv,tcp

# TCP 端点统计
tshark -r <pcap> -q -z endpoints,tcp

# IP 端点统计
tshark -r <pcap> -q -z endpoints,ip

# HTTP 请求统计
tshark -r <pcap> -q -z http_req,tree
```

### 时间窗口 & 端口过滤

```bash
# 时间窗口
tshark -r <pcap> -Y 'frame.time >= "2026-06-30 09:00:00" and frame.time <= "2026-06-30 10:00:00"'

# 特定端口
tshark -r <pcap> -f "port 445 or port 3389"

# 特定 IP
tshark -r <pcap> -Y "ip.addr == 192.168.1.100"

# 特定源到目的
tshark -r <pcap> -Y "ip.src == 192.168.1.100 and ip.dst == 203.0.113.5"
```

---

## 附录 B：常用 Wireshark 显示过滤器

方便蓝队跨工具切换（tshark filter 与 Wireshark display filter 语法一致）。

| 场景 | Wireshark display filter |
|---|---|
| 只看 HTTP POST | `http.request.method == "POST"` |
| 只看 DNS 查询失败 | `dns.flags.rcode == 3` |
| SMB2 Create 请求 | `smb2.cmd == 5` |
| Kerberos TGS 请求 | `kerberos.msg_type == 12` |
| WebSocket 升级 | `http.upgrade contains "websocket"` |
| TLS 握手 | `tls.handshake` |
| ICMP | `icmp` |
| TCP 重传 | `tcp.analysis.retransmission` |
| TCP 三次握手 | `tcp.flags.syn == 1 and tcp.flags.ack == 0` |
| TCP RST | `tcp.flags.reset == 1` |

Wireshark 图形化操作：
- **右键 → Follow → HTTP Stream** ：跟踪单个 HTTP 会话
- **Statistics → Conversations**：会话列表 & 按字节数排序
- **Statistics → Endpoints**：端点列表 & 按包数排序
- **Statistics → I/O Graphs**：流量随时间的分布图，看是否有心跳
- **File → Export Objects → HTTP**：导出 pcap 中传输的所有 HTTP 文件

---

## 附录 C：rule_id 分布速查

本 playbook 定义的 rule_id 一览：

| rule_id | 触发条件 | severity |
|---|---|---|
| PLB-TA-001 | pcap 完整性检查通过 | 元规则 |
| PLB-TA-002 | 归一化抠取完成 | 元规则 |
| PLB-TA-003 | IOC 匹配完成 | 元规则 |
| PLB-TA-004 | 异常检测完成 | 元规则 |
| PLB-TA-005 | 横向 & 隧道判定完成 | 元规则 |
| PLB-TA-006 | 交付完成 | 元规则 |
| PLB-TA-011 | 场景 A：SIEM 告警定位 | 处置流程 |
| PLB-TA-012 | 场景 B：主机失陷取证 | 处置流程 |
| PLB-TA-013 | 场景 C：内网横向定位 | 处置流程 |
| PLB-TA-014 | 场景 D：数据外发核查 | 处置流程 |

共计 10 条 `PLB-TA-*` 规则。

---

## 附录 D：与其他文档的交叉索引

- 基础恶意流量 12 类：`references/attack-patterns/malicious-traffic.md`
- Windows 横向流量：`references/attack-patterns/windows-lateral-traffic.md`
- 内网穿透工具流量：`references/attack-patterns/tunnel-tools-traffic.md`
- C2 通信主机 + 网络综合识别：`references/attack-patterns/c2-signatures.md`
- Webshell 处置剧本：`references/playbooks/webshell.md`
- 命令执行 / RCE 处置剧本：`references/playbooks/command-exec.md`
- 横向移动处置剧本：`references/playbooks/lateral-movement.md`
- audit 模式流程：`references/modes/audit.md`
- TLS 指纹深化 `references/attack-patterns/tls-fingerprints.md`
- DNS 隐蔽通道深化 `references/attack-patterns/dns-covert-channels.md`

---

## 十一、TLS/DNS 深化审计

> 本章补充 TLS/DNS 深化的 45 条规则（R-TRAF-050~098）在 traffic 模式下的实战审计路径。
> 与前十章的通用流程互补：前十章是"基础扫描 + 主流类型"，本章是"加密 C2 深挖 + 国内红队工具深挖"。

### 11.1 规则组速览

| 规则组 | ID 范围 | 数量 | 主视图 | 核心场景 |
|---|---|---|---|---|
| TLS 深化 | R-TRAF-050~069 | 20 | tls | JA3/JA3S 指纹、证书元数据、SNI 异常、GM 国密 |
| DNS 深化 | R-TRAF-070~084 | 15 | dns | 长 qname、Shannon 熵、TXT/NULL 比例、beacon 间隔 |
| 国内红队工具 | R-TRAF-085~098 | 14 | http/tls/flow | 冰蝎/哥斯拉/蚁剑/suo5/regeorg/fscan/goby/xray/nuclei/yakit/Viper/Linx/免杀 loader |

R-TRAF-999 关联升级：三大类命中 ≥ 2 类 → `apt-suspect` 标签，升级为 P0。

### 11.2 场景 A：加密 C2 心跳深挖（JA3 命中）

**起因**：主线 SIEM 报"某内网主机长时间 TLS 出方向"，但域名/UA 都正常。

**pcap 采集**：
```bash
# 客户 SPAN 口镜像 30 min
tcpdump -i mirror0 -w /tmp/case-A.pcap -s 0 \
        host 10.0.0.100 and port 443
```

**规则执行**：
```bash
pcap_parser.py --input /tmp/case-A.pcap --views tls,http,flow \
   | traffic_anomaly.py --input - --output findings-A.json -v
```

**关键规则**：`R-TRAF-050`（JA3 命中 CS）、`R-TRAF-054`（证书 CN 默认）、`R-TRAF-057`（短命证书）、`R-TRAF-055`（空 SNI）、`R-TRAF-081`（DNS 间隔均匀，若 DNS beacon 并发）。

**输出解读**：
```json
{
  "rule_id": "R-TRAF-050",
  "severity": "P0",
  "evidence": {
    "src_ip": "10.0.0.100", "dst_ip": "203.0.113.10",
    "hint": {"ja3": "72a589da586844d7f0818ce684948eea",
             "tool": "cobalt-strike",
             "narrative": "JA3 matches known CS beacon fingerprint"}
  }
}
```

**动作**：
1. `dst_ip: 203.0.113.10` 立即进边界防火墙黑名单
2. `src_ip: 10.0.0.100` 主机隔离 → 抓 rss 内存 → 找 loader 进程
3. 复看 `R-TRAF-999` 是否同 src 触发 apt-suspect，若是则**升级到 P0 事件级响应**

### 11.3 场景 B：DNS 隧道数据外发

**起因**：DLP 报"某主机出方向流量少但持续"。

**pcap 采集**：抓该主机的 UDP/53 流量 2h。

**规则执行**：
```bash
pcap_parser.py --input /tmp/case-B.pcap --views dns \
   | traffic_anomaly.py --input - --output findings-B.json -v
```

**关键规则**：`R-TRAF-070`（avg qname > 40）、`R-TRAF-071`（Shannon > 4.0）、`R-TRAF-073`（TXT > 30%）、`R-TRAF-076`（base32/base64）、`R-TRAF-081`（间隔均匀）。

**输出解读**：
```json
{"rule_id": "R-TRAF-073",
 "evidence": {"src_ip": "10.0.0.200",
              "hint": {"txt_ratio": "0.85",
                       "narrative": "TXT ratio 340/400 > 30%"}}}
```

**动作**：
1. 立即断该主机 DNS 出站（防火墙 UDP/53 白名单只留内部 DNS 服务器）
2. 主机 IR：找 iodine / dnscat2 / 自研 DNS tunnel 客户端进程
3. 复看 pcap 中的 qname 首标签，判断是否为 iodine（base32）/ dnscat2（TXT+base64）/ 自研

**注意**：**不要**尝试解码 qname 首标签 —— 保留原始样本给客户 IR 团队。

### 11.4 场景 C：suo5 / neo-regeorg 内网穿透

**起因**：护网中期，客户报"某 web 应用突然出现大量 POST + WebSocket 请求"。

**pcap 采集**：抓该 web server 前 30 min 流量。

**规则执行**：
```bash
pcap_parser.py --input /tmp/case-C.pcap --views http,flow \
   | traffic_anomaly.py --input - -v
```

**关键规则**：`R-TRAF-095`（suo5 URI + Upgrade websocket）、`R-TRAF-096`（regeorg X-CMD header）、`SIG-TRAF-117~120`。

**输出解读**：
```json
{"rule_id": "R-TRAF-095",
 "evidence": {"src_ip": "1.2.3.4", "dst_ip": "10.0.0.50",
              "hint": {"narrative": "suo5 tunnel marker (HTTP/2 upgrade)",
                       "tool": "suo5"}}}
```

**动作**：
1. `dst_ip` 是 web server → **该 web server 已被 webshell 落地**
2. 关闭该 web 应用 + 立即 web IR（找 webshell 文件 + 清理）
3. 复盘 `src_ip` 是否内部办公网 IP（内鬼）或外网攻击方 IP

### 11.5 场景 D：域前置攻击（SNI vs Host 不一致）

**起因**：CDN 侧告警"某源 IP 发起大量小请求"，回溯 pcap。

**规则执行**：
```bash
pcap_parser.py --input /tmp/case-D.pcap --views tls,http \
   | traffic_anomaly.py --input - -v
```

**关键规则**：`R-TRAF-053`（SNI vs Host 不一致）、`R-TRAF-050`（若命中已知 JA3）、`R-TRAF-054`（若命中默认 CN）。

**输出解读**：
```json
{"rule_id": "R-TRAF-053",
 "evidence": {"hint": {"sni": "cdn.cloudflare.com",
                       "host": "bad.attacker.example",
                       "narrative": "SNI/Host mismatch (domain fronting suspect)"}}}
```

**动作**：
1. 边界防火墙封禁 `bad.attacker.example`（DNS resolve 后的 IP）
2. 联系 CDN 侧（如 CloudFlare abuse），要求下线该域
3. 排查同 src_ip 是否有其他类似域前置行为

### 11.6 场景 E：国密 TLS 异常出现

**起因**：普通企业环境，突然出现非白名单业务的国密 TLS 握手。

**规则执行**：
```bash
pcap_parser.py --input /tmp/case-E.pcap --views tls \
   | traffic_anomaly.py --input - -v
```

**关键规则**：`R-TRAF-056`（SM2/SM4 cipher）、`SIG-TRAF-096`。

**输出解读**：
```json
{"rule_id": "R-TRAF-056",
 "evidence": {"hint": {"cipher": "ECDHE-SM2-SM4-GCM-SM3",
                       "narrative": "GM (SM2/SM3/SM4) TLS cipher outside whitelist"}}}
```

**动作**：
1. 与客户合规团队核对：该 `dst_ip` 是否在国密业务白名单
2. **不在白名单** → 视为国产化红队工具嫌疑，进入 P1 观察
3. 主机侧看是否有国密相关的加载器进程

### 11.7 场景 F：R-TRAF-999 apt-suspect 触发

**起因**：批量跑 pcap 时，R-TRAF-999 输出带 `tag: apt-suspect`。

**输出解读**：
```json
{"rule_id": "R-TRAF-999",
 "evidence": {"src_ip": "10.0.0.150", "view": "correlation",
              "hint": {"tag": "apt-suspect",
                       "cluster_hits": ["tls-deep", "dns-covert", "cn-redteam"],
                       "distinct_rules": ["R-TRAF-051", "R-TRAF-076", "R-TRAF-085"],
                       "narrative": "src_ip 10.0.0.150 hit 3 distinct rules; apt-suspect (crossed 3 clusters: tls-deep, dns-covert, cn-redteam)"}}}
```

**含义**：同一个 src_ip 同时触发了 TLS 深化 + DNS 深化 + 国内工具三大类 → **高置信 APT 组织行为**。

**动作**：
1. **立即事件级响应**（客户 IR leader + 蓝队 leader 同步）
2. 该 src_ip 全流量隔离
3. 复看 pcap，把命中的具体证据打包给客户 IR
4. 上报客户 SOC / 走 CI 通道

### 11.8 tshark 字段依赖

部分规则依赖 tshark >= 3.6 的字段：

| 规则 | 依赖字段 | tshark 版本 |
|---|---|---|
| R-TRAF-050~052 | `tls.handshake.ja3` / `ja3s` | >= 3.6 |
| R-TRAF-056 | `tls.handshake.ciphersuite`（含 GM 名称） | >= 3.6 |
| R-TRAF-057 | 证书 `not_before / not_after` | >= 3.4 |
| R-TRAF-060 | Client Hello extensions 列表 | >= 3.4 |

**若客户使用 tshark 3.2 或更老**：
- 相关规则会**无声跳过**（`raw` 字段缺失 → 判定不触发）
- 建议升级到 wireshark 4.0+（`brew install wireshark` / `apt install wireshark`）

### 11.9 命中率预期

在标准红蓝演练 pcap（约 30 min 流量、10-20 GB）中，深化规则的预期命中：

| 规则组 | 预期命中数 | 备注 |
|---|---|---|
| R-TRAF-050~069 (TLS) | 5-15 条 | 主要是 R-TRAF-055（空 SNI）、054（默认 CN）、050~051（JA3） |
| R-TRAF-070~084 (DNS) | 10-30 条 | 若客户内网有 DNS 隧道嫌疑；否则 < 5 条 |
| R-TRAF-085~098 (CN 工具) | 20-60 条 | 护网期高频，尤其 fscan/xray/nuclei |
| R-TRAF-999 apt-suspect | 0-3 条 | 出现即高置信，务必优先处置 |

命中数量与客户业务规模、pcap 时长、被攻击程度强相关，此处仅供**校准基线**参考。

### 11.10 附录：深化规则速查表

| rule_id | 主视图 | severity | 命中条件（一句话） |
|---|---|---|---|
| R-TRAF-050 | tls | P0 | JA3 命中已知 CS |
| R-TRAF-051 | tls | P0 | JA3 命中 Sliver/Mythic/Havoc/BRC4 |
| R-TRAF-052 | tls | P1 | JA3S 命中国内魔改 CS server |
| R-TRAF-053 | tls | P1 | SNI vs Host 不一致 |
| R-TRAF-054 | tls | P1 | 证书 CN/O 默认自签 |
| R-TRAF-055 | tls | P2 | SNI 空 / 数字-only |
| R-TRAF-056 | tls | P2 | GM 国密 cipher（非白名单） |
| R-TRAF-057 | tls | P1 | 短命自签证书 (<24h) |
| R-TRAF-058 | tls | P2 | ALPN 声明 h2 但流量像 h1 |
| R-TRAF-059 | tls | P1 | 私域 SNI 出公网 |
| R-TRAF-060 | tls | P3 | Client Hello 无 GREASE |
| R-TRAF-061 | tls | P3 | ECH 扩展出现 |
| R-TRAF-062 | tls | P3 | Extension 数量 < 4 |
| R-TRAF-063 | tls | P3 | SNI 是 IP literal |
| R-TRAF-064 | tls | P2 | 单密码套件提案 |
| R-TRAF-065 | tls | P3 | 空 session ticket + id |
| R-TRAF-066 | tls | P3 | 握手失败 spike |
| R-TRAF-067 | tls | P2 | SNI 大量切换 |
| R-TRAF-068 | tls | P3 | 浏览器 UA 但无 ALPN |
| R-TRAF-069 | tls | P2 | SNI + ALPN 全空 |
| R-TRAF-070 | dns | P1 | avg qname > 40 |
| R-TRAF-071 | dns | P1 | Shannon 熵 > 4.0 |
| R-TRAF-072 | dns | P1 | 子域爆炸 > 100 |
| R-TRAF-073 | dns | P0 | TXT 占比 > 30% |
| R-TRAF-074 | dns | P0 | NULL 占比 > 5% |
| R-TRAF-075 | dns | P2 | UDP/53 payload 异常 |
| R-TRAF-076 | dns | P1 | 首标签 base32/64 > 85% |
| R-TRAF-077 | dns | P2 | NXDOMAIN 风暴 |
| R-TRAF-078 | dns | P0 | CS DNS beacon 前缀 |
| R-TRAF-079 | dns | P2 | DoH/DoT 非白名单 |
| R-TRAF-080 | dns | P2 | n-gram DGA 辅音簇 |
| R-TRAF-081 | dns | P1 | 间隔均匀 CV < 0.15 |
| R-TRAF-082 | dns | P2 | answer >> query |
| R-TRAF-083 | dns | P3 | TTL 异常 |
| R-TRAF-084 | dns | P2 | 重复 qname burst |
| R-TRAF-085 | http | P0 | 冰蝎 Behinder |
| R-TRAF-086 | http | P0 | 哥斯拉 Godzilla |
| R-TRAF-087 | http | P1 | 蚁剑 AntSword |
| R-TRAF-088 | http | P1 | 灵蜥 Linx |
| R-TRAF-089 | http/tls | P0 | Viper C2 |
| R-TRAF-090 | http/flow | P1 | fscan |
| R-TRAF-091 | http | P2 | goby |
| R-TRAF-092 | http | P2 | xray |
| R-TRAF-093 | http | P2 | nuclei |
| R-TRAF-094 | http | P2 | Yakit |
| R-TRAF-095 | http | P0 | suo5 |
| R-TRAF-096 | http | P0 | neo-regeorg / reGeorg |
| R-TRAF-097 | http | P1 | 弱口令暴破 |
| R-TRAF-098 | flow | P1 | 免杀 loader 脉冲 beacon |

**END OF §十一**

---

## 十二、收尾：统一终报 + findings.json

traffic 六步审计 + TLS/DNS 深化完成后，**必须**输出跨模式统一终报与机器可读伴生文件（见 `SKILL.md §输出契约`）：

- **`final-report.md`（traffic 形态）**：按 `assets/final-report.md` 渲染——
  - §2 判定与影响：verdict 多为 `high_suspicion`（疑似 C2 / 隧道）或 `confirmed_intrusion`（与 ir 联动定性后）；填异常源数 + 是否升级 ir
  - §3 攻击路径地图：渲染为 **flow + C2 通道图**形态（src→dst HTTP/TLS/DNS 节点 + JA3/JA3S 指纹 + DNS 隧道通道），`tactic_chain` 多为 `[TA0011_C2]`
  - §4 分层发现详情：P0/P1 全文 8 字段卡，rule_id 含 `R-TRAF-*`
  - §5 证据与时间线：✅ 必填（pcap 时间窗 + C2 beacon 间隔）
  - §6 IOC 清单：ip / domain / ja3 / ua 等流量侧 IOC
  - §7 处置建议与优先级：取**封堵建议**变体（封 IP / 域名 / 加 WAF 规则，未执行）
  - §8 检测改进：IDS/IPS 规则缺口 + JA3 hash 库校准建议
  - §10 附件：`ioc-extract.md`；若升级 ir 则挂 `incident-report.md`
- **`findings.json`**：按 `assets/findings-schema.md` 生成，`mode=traffic`，`findings[]` rule_id 含 `R-TRAF-*`，`attack_paths[]` nodes 为 flow/conn 节点（src→dst + 检测规则）

> traffic 发现 webshell 落地 / C2 确认 / 横向移动等入侵信号 → 升级 ir，终报改走 ir 形态，traffic 形态作为网络侧证据挂附件。

> **与其他文档的交叉索引**：见原 §附录 D。
