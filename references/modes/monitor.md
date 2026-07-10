# Monitor 模式 —— 值守监管详细流程

> 应用场景：日常值守、告警批次分诊、误报研判、值守日报。
> 关联：分级标准见 `../grading.md`，脱敏与红线见 `../compliance.md`，输出 schema 见 `SKILL.md`。

---

## 一、何时进入 monitor

用户措辞匹配以下任一即进入本模式：

- 名词类：「告警」「值守」「日报」「分诊」「SIEM 导出」「批次」「这批」
- 动词类：「看一下」「研判一下」「过一遍」「哪些是误报」「升级哪些」
- 显式调用：`/hvv-defender monitor ...`
- 输入文件类型：扩展名为 `.json/.csv` 且文件名包含 `alerts/alarms/events/incidents` 或第一行字段命中告警 schema

不进入 monitor 的反例：
- 输入是原始日志（nginx access、auth.log）→ 走 audit
- 用户描述「某主机失陷 / 怀疑被入侵 / 已经被打了」→ 走 ir

---

## 二、输入格式与字段映射

告警 JSON / CSV 字段差异巨大，本 Skill 通过字段别名表归一化到统一 schema。

### 2.1 核心字段（≥ 8 个）与别名

| 标准字段 | 含义 | 常见别名 |
|---|---|---|
| `ts` | 告警时间戳 | `timestamp` / `event_time` / `alert_time` / `detect_time` / `@timestamp` / `occur_time` / `time` |
| `src_ip` | 攻击源 IP | `srcip` / `source_ip` / `attacker_ip` / `client_ip` / `remote_addr` / `from_ip` / `s_ip` |
| `dst_ip` | 目标 IP | `dstip` / `destination_ip` / `target_ip` / `server_ip` / `d_ip` |
| `dst_port` | 目标端口 | `dport` / `destination_port` / `server_port` / `port` |
| `proto` | 协议 | `protocol` / `transport_protocol` / `app_protocol` |
| `rule_name` | 触发规则名 | `signature` / `alert_name` / `detect_rule` / `rule_id` / `event_name` |
| `severity` | 厂商分级 | `level` / `risk_level` / `priority` / `seriousness` |
| `payload` | 关键负载 | `request_body` / `raw` / `url` / `query_string` / `cmd` |
| `user_agent` | UA | `ua` / `http_user_agent` / `agent` |
| `username` | 关联账号 | `user` / `account` / `login_name` |
| `hostname` | 被攻击主机名 | `asset_name` / `host` / `endpoint_name` |
| `action` | 设备处置 | `disposal` / `policy_action` / `verdict`（block/allow/log） |

### 2.2 字段缺失策略

- 缺 `ts` → 拒绝处理，要求用户提供（无时间无关联）
- 缺 `src_ip` → 降级为「资产侧异常」，不计入 IP 维度关联
- 缺 `rule_name` → 用 `category` / `event_type` 替代，否则标 `unknown_rule`
- 缺 `payload` → 不影响分诊，但 evidence 字段标 `payload_unavailable`

### 2.3 输入示例

```json
{
  "ts": "2026-06-30T08:14:23+08:00",
  "src_ip": "203.0.113.50",
  "dst_ip": "192.168.1.100",
  "dst_port": 8080,
  "proto": "HTTP",
  "rule_name": "fastjson_rce_attempt",
  "severity": "high",
  "payload": "{\"@type\":\"com.sun.rowset...\"}",
  "user_agent": "Java/1.8.0_181",
  "action": "block"
}
```

---

## 三、6 步详细流程

### 步骤 1：归一化与去噪

**主会话做什么**：调用 `scripts/log_parser.py --mode alerts --input <file> --schema auto` 把告警归到统一 schema。

**调用脚本**：
```bash
python3 scripts/log_parser.py \
  --mode alerts \
  --input ./alerts-20260630.json \
  --aliases references/log-fields/waf-fw-generic.md \
  --output /tmp/hvv-monitor-normalized.jsonl
```

**子 agent 介入**：不介入。这一步纯字段映射，无判定。确定性步骤，正常不放行不调 LLM，异常时（0 记录 / 字段全空 / 非 0 退出）触发检查点 A。

**产出**：归一化的 JSONL，每行一条告警 + 标准字段。

#### 3.1.1 通过 `--vendor <name>` 消费厂商专属告警

当输入是 4 家国产安全设备中任意一家导出的告警 JSON/CSV 时，主流程不必手写字段映射，可直接调用 `scripts/vendor_field_mapper.py` 生成标准 12 字段 NDJSON，随后喂给步骤 2 的 `ioc_match.py`。

```bash
python3 scripts/vendor_field_mapper.py \
  --input ./alerts-qax-20260630.json \
  --vendor qax-ngsoc \
  --output /tmp/hvv-monitor-normalized.jsonl
```

支持的 4 家 vendor 及其抽屉参考：

| vendor-key | display_name | 常见触发词 | 参考 md 路径 |
|---|---|---|---|
| qax-ngsoc | 奇安信 NGSOC | "奇安信告警 / NGSOC 导出 / QAX 分诊 / 天眼" | `references/log-fields/vendor-qax-ngsoc.md` |
| sangfor-sip | 深信服 SIP | "深信服告警 / SIP 感知平台 / Sangfor XDR" | `references/log-fields/vendor-sangfor-sip.md` |
| changting-safeline | 长亭雷池 SafeLine WAF | "雷池 / SafeLine / 长亭 WAF / Chaitin" | `references/log-fields/vendor-changting-safeline.md` |
| dbappsec-mingyu | 安恒明御 WAF | "明御 / 安恒 WAF / DAS-WAF / DBAppSec" | `references/log-fields/vendor-dbappsec-mingyu.md` |

**何时使用**：告警文件来自上表任一厂商且未经过内部 SIEM 二次归一化时。若客户已在 SIEM（例如 QAX NGSOC 汇聚层、Splunk）做过统一字段命名，则直接走通用 `log_parser.py --mode alerts` 即可。

**strict 模式**：`--strict` 遇到字段缺失或 severity 未映射时直接退出（退出码 2），适合驻场首日核对字段映射；日常值守走宽松模式（默认），字段缺失填 null、severity 未映射降级为 P2。

**校准红线**：4 家 vendor 抽屉里明确写出"驻场时需校准"的字段，主会话在首次接入新客户时必须与客户驻场安全工程师逐条对齐，避免 category / severity 语义歧义。

### 步骤 2：内置 IOC + 工具特征匹配

**主会话做什么**：跑 `scripts/ioc_match.py` 把告警里的 IP / UA / payload 与 `data/ioc-builtin.json` + `data/tool-signatures.json` 对一遍，命中的打 `ioc_match` 标签。

**调用脚本**：
```bash
python3 scripts/ioc_match.py \
  --input /tmp/hvv-monitor-normalized.jsonl \
  --ioc data/ioc-builtin.json \
  --tools data/tool-signatures.json \
  --output /tmp/hvv-monitor-tagged.jsonl
```

**子 agent 介入**：不介入。

**产出**：带 `ioc_match` / `tool_match` 标签的 JSONL，命中条目 `confidence` 自动 +1 档。

> **🔍 检查点 A（审核）**：本步完成后**必跑** `agents/checkpoint-reviewer`（确定性步骤仅异常时触发）。审核命中合理性 + 误报剔除（P2/P3 聚合统计，P0/P1 抽样逐条）。审核通过进检查点 B。

### 步骤 3：alert-triage 子 agent 分诊 —— **必跑**（检查点 B 决策）

**主会话做什么**：把归一化 + 标签化后的告警分批（每批 ≤ 200 条）喂给 `agents/alert-triage` 子 agent，要求按 P0-P3 打分并附理由。

**调用方式**：
```
Agent (general-purpose, alert-triage):
  Input: /tmp/hvv-monitor-tagged.jsonl 的第 1-200 条
  Task: 按 references/grading.md 给每条打分；输出 8 字段 schema JSONL
  Budget: ≤ 25 工具调用，≤ 15 分钟
```

**子 agent 何时介入**：**必跑**。alert-triage 是检查点 B 的决策 agent，无论批次大小都必须调用以完成分诊决策。

**产出**：每条告警一个 8 字段 schema 条目，含 `severity` / `category` / `false_positive_prob` / `recommended_action`。

### 步骤 4：关联升级

**主会话做什么**：跑关联规则引擎对分诊后的列表做升级。

> 注：关联升级结果纳入检查点 B（步骤 3 alert-triage 决策）的输出，作为 verdict 的一部分送入后续检查点 C，不单独再开 LLM 决策。

**关联规则**（最小集，与 `grading.md` 第三节一致）：

```python
# 伪代码
for ip in unique(src_ip):
    events = filter_by_ip_and_window(ip, window="5m")
    if len(unique(rule_name(events))) >= 3:
        for e in events: e.severity = upgrade(e.severity, 1)
    if any(e.severity == "P0" for e in events) and len(events) >= 5:
        tag_all(events, "campaign")  # 标记为团伙行为

for user in unique(username):
    events = filter_by_user_and_window(user, window="10m")
    hosts = unique(hostname(events))
    if len(hosts) >= 3 and any(e.category == "auth_success" for e in events):
        for e in events:
            e.severity = upgrade(e.severity, 1)
            e.tags.append("lateral_suspect")
```

### 步骤 5：脱敏

**主会话做什么**：调 `scripts/desensitize.py` 把 evidence / username / hostname / 内部 IP 全部脱敏。

```bash
python3 scripts/desensitize.py \
  --input /tmp/hvv-monitor-triaged.jsonl \
  --internal-domain "*.corp.example.com" \
  --customer-name "<customer>" \
  --mode strict \
  --output /tmp/hvv-monitor-final.jsonl
```

> 私网 IP 段由脚本按 RFC1918 自动识别（10/8、172.16/12、192.168/16、100.64/10）。若需保留公网 IP（红队溯源），加 `--keep-public-ip` 或 `--mode relaxed`。

### 步骤 6：渲染日报 + 待跟进列表

> **✅ 检查点 C（验证）**：出日报前**必跑** `agents/verdict-validator` 验证 verdict 证据闭环 + 待跟进列表无漏标。rejected 打回步骤 3 重做。

**主会话做什么**：用 `assets/daily-report.md` 渲染日报，并单独输出待跟进列表（仅 P0 + P1 + 标记 `lateral_suspect` 的条目）。

---

## 四、分诊决策树（P0-P3 速判）

```
告警进入
  │
  ├─ 厂商 severity == high 且 action == "block" 且无后续命中
  │   → 候选 P2（已拦截，工具扫描）
  │
  ├─ 命中 webshell-落地特征（payload 含 jsp/php 上传 + 200）
  │   → P0
  │
  ├─ 命中 fastjson/log4j/shiro 反序列化
  │   ├─ action != block 且 dst 返回 200 → P0
  │   ├─ action != block 但 dst 4xx/5xx   → P1
  │   └─ action == block                  → P2
  │
  ├─ SSH 暴破
  │   ├─ 出现 success 字段 = true → P0
  │   ├─ 失败次数 >= 100/min     → P1
  │   ├─ 失败次数 >= 20/min      → P2
  │   └─ 失败次数 <  20/min      → P3
  │
  ├─ SQL 注入工具 UA（sqlmap）
  │   ├─ 4xx 比例 < 50% + 含敏感关键字（union/sleep） → P1
  │   ├─ 4xx 比例 >= 50%                              → P2
  │   └─ 100% 4xx + 内部白名单                        → P3
  │
  ├─ 通用扫描器 UA（nuclei/xray/dirsearch/fscan）
  │   ├─ 命中后接 200 敏感路径 → P1
  │   └─ 否则                  → P2
  │
  ├─ 命中内部漏扫白名单 IP + 合规扫描时段
  │   → P3
  │
  └─ 默认 → P2（保守）
```

---

## 五、误报常见 pattern

| Pattern | 特征 | 处置 |
|---|---|---|
| 内部漏扫白名单 | 源 IP 在 `--scanner-whitelist` 列表 | 直接 P3 + 归档 |
| 健康检查 | 固定 UA + 固定路径 `/healthz` / `/ping` / `/actuator/health` | P3 |
| 监控探针 | UA 含 `prometheus` / `zabbix` / `nagios` 且固定来源 IP | P3 |
| 搜索引擎爬虫 | UA 是 Googlebot/Bingbot 且 reverse DNS 验证通过 | P3 |
| 业务回调 | 同段内部 IP 短时间高频固定路径 | P3，但提示用户确认 |
| 开发联调 | 工作时段 + 内部 IP + 一次性 4xx 集群 | P3，下值守班前归档 |
| 安全设备误判 | 同一规则全天 > 500 次且全部 block | P3 + 反馈给安全运维优化规则 |
| 长 URL 误报 | URL 长度 > 1000 但是合法业务参数 | P3，加入白名单规则 |

**注**：误报归档不等于忽略；P3 列表周复查一次，避免规则漂移把真攻击降级了。

---

## 六、关联升级规则（详）

### 6.1 IP 维度

- 同 IP 5 分钟内命中 ≥ 3 类不同 `rule_name` → 当前级别 +1
- 同 IP 1 小时内命中 ≥ 10 条 P2+ → 升 P1
- 同 IP 同时打 `tool_match` + 敏感路径 200 → 直接 P1

### 6.2 账号维度

- 同 username 10 分钟内出现在 ≥ 3 台不同 hostname → `lateral_suspect` + 当前级别 +1
- 同 username 非工作时段（22:00-06:00）+ 异常源 IP 首次出现 → +1

### 6.3 资产维度

- 同 dst_ip 30 分钟内被 ≥ 5 个不同源 IP 命中 → 升级为「资产受关注」标签，所有命中条目 +1

### 6.4 时序维度

- 同 IP 出现 `recon`（探测）→ `exploit attempt`（尝试利用）→ `auth_success` 序列 → 直接 P0 + `kill_chain_complete` 标签

---

## 七、输出格式范例

### 7.1 值守日报片段（脱敏后）

```markdown
# 值守日报 2026-06-30

## 概览
- 告警总量：2031 条
- 分级：P0 3 / P1 12 / P2 87 / P3 1929
- 待跟进：6 条（详见附表）

## P0 重点（共 3 条）

| ID | 时间 | 攻击类型 | 源 IP | 资产 | 证据摘要 |
|---|---|---|---|---|---|
| MON-001 | 08:14:23 | fastjson_rce | 203.0.113.50 | 192.168.1.xxx:8080 | `@type:com.sun.rowset...` payload + 200 返回 |
| MON-002 | 08:14:25 | fastjson_rce | 203.0.113.50 | 192.168.1.xxx:8080 | 同上，second-stage 探测 cmd 回显 |
| MON-003 | 11:32:08 | webshell_drop | 198.51.100.7 | 192.168.1.xxx:443 | 上传 `/upload/x.jsp`，content 含 java.lang.Runtime |

## 异常 IP TOP 5
| 源 IP | 命中次数 | 规则种类 | 最高级别 |
|---|---|---|---|
| 203.0.113.50 | 47 | 5 | P0 |
| 198.51.100.7 | 22 | 3 | P0 |
| 198.51.100.99 | 18 | 2 | P1 |
| ... | ... | ... | ... |

## 误报归档（P3 摘要）
- 内部漏扫 192.168.99.xxx 段：812 条
- 健康检查 /healthz：534 条
- ...
```

### 7.2 待跟进列表 JSON

```json
[
  {
    "id": "MON-001",
    "severity": "P0",
    "category": "rce",
    "evidence": "alerts-20260630.json:line 1832; payload contains '@type:com.sun.rowset...'",
    "rule_id": "R-WAF-FASTJSON-001",
    "false_positive_prob": 0.05,
    "recommended_action": "立即升 IR；保留主机快照；封 203.0.113.50；详见 playbooks/command-exec.md",
    "iocs": [
      {"type":"ip","value":"203.0.113.50","confidence":"high","first_seen":"2026-06-30T08:14:23+08:00","source":"alerts-20260630.json:1832","tag":"attacker"}
    ],
    "tags": ["campaign","kill_chain_complete"]
  }
]
```

---

## 八、状态机

每条告警在本次值守会话内的生命周期：

```
new ── 字段归一化、初次入库
 │
 │ triage（步骤 3 完成）
 ▼
triaged ── 已打 severity / category / fp_prob
 │
 ├─ 关联或人工复核认为是误报
 │   ▼
 │  false_positive ── 归档，纳入白名单复查
 │
 ├─ 关联或人工复核确认是真实攻击
 │   ▼
 │  confirmed ── 进入待跟进列表
 │   │
 │   │ 升 audit 或 ir
 │   ▼
 │  handed_off ── 已转 audit / ir 处理
 │
 └─ 未判定
     ▼
    pending ── 下值守班继续跟踪
```

状态字段建议保存为 `state`，配合 `state_changed_at` / `state_changed_by` 留痕。

---

## 九、与 audit / ir 的衔接

- monitor 命中 P0 / P1 但证据不充分 → 主会话主动建议「转 audit 模式深挖该 IP 在 nginx 日志的完整足迹」
- monitor 命中 webshell_drop + 200 → 直接建议「转 ir 模式，让客户跑 linux_quick_check.sh」

会话内顺序升级不需要重新 enter skill，只切模式即可，状态机和 IOC 列表跨模式共享。

---

## 十、收尾：统一终报 + findings.json

monitor 批次处理完毕后，**必须**输出跨模式统一终报与机器可读伴生文件（见 `SKILL.md §输出契约`）：

- **`final-report.md`（monitor 形态，轻量变体）**：按 `assets/final-report.md` 渲染——
  - §1 执行摘要：本批一句话总结 + P0-P3 分层计数
  - §2 判定与影响：verdict 多为 `no_intrusion` / `high_suspicion`，填误报率 + 待跟进 P1 数
  - §3 攻击路径地图：渲染为**告警关联簇（CLU-*）**形态（同源 IP/UA/账号跨规则命中簇）
  - §4 分层发现详情：P0/P1 全文 8 字段卡，P2/P3 汇总计数
  - §7 处置建议与优先级：取**待跟进列表**变体
  - §10 附件：`daily-report.md`（运营日报，作详尽附件）/ `ioc-extract.md` / `handover.md`
- **`findings.json`**：按 `assets/findings-schema.md` 生成，`mode=monitor`，`findings[]` 为本批 P0-P3 条目（8 字段），`attack_paths=[]`（monitor 用关联簇替代，簇信息进 `findings[].evidence` 的 CLU-* 标注）

> monitor 形态终报是"批次结论封面"；`daily-report.md` 仍是运营日报主体（时序趋势 / 交接备忘详尽内容），作为终报附件，两者不互替。

---

## 相关引用

- 输出 schema：`SKILL.md` 输出契约
- 统一终报：`../../assets/final-report.md`（monitor 形态）+ `../../assets/findings-schema.md`
- 攻击 playbook：`../playbooks/`
- 字段对照：`../log-fields/waf-fw-generic.md`
- 分级公式：`../grading.md`

