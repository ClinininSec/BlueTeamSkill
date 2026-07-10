# Audit 模式 —— 日志审计详细流程

> 应用场景：主动审计指定时段/系统日志、专项排查（webshell / 暴破 / 漏洞利用尝试）、给出异常清单 + IOC。
> 关联：分级 `../grading.md`、脱敏 `../compliance.md`、playbook `../playbooks/`。

---

## 一、何时进入 audit

用户措辞匹配：
- 名词类：「nginx 日志」「access.log」「auth.log」「secure」「evtx」「应用 audit 日志」
- 动词类：「审计一下」「排查一下」「过一遍 …… 日志」「查 ssh 暴破」「找 webshell」
- 时间窗：「最近 24 小时」「昨天 8 点到 12 点」「上周」
- 显式：`/hvv-defender audit ...`

反例：
- 输入是结构化告警（JSON 含 rule_name 等字段）→ 走 monitor
- 用户已经知道某主机失陷 → 走 ir

---

## 二、审计范围对齐（4 个问题）

进入 audit 后，主会话第一步必须向用户确认（即使用户已提供文件路径）：

1. **日志类型**：
   - nginx access? Apache access? 应用层访问 json? auth.log? secure? Windows EVTX 导出 CSV? 还是混合？
   - 不同类型走不同脚本，错配会导致误报暴增

2. **时间窗口**：
   - 起止时间精确到分钟（如 `2026-06-30 08:00 ~ 2026-06-30 18:00`）
   - 无明确窗口时默认「最近 24 小时」并提示用户确认

3. **涉及主机 / 资产**：
   - 是单台主机还是集群？
   - 给出 hostname / IP 列表，便于在异常聚合时按资产维度切片

4. **关注的攻击类型**（可多选）：
   - 通用：扫描器探测 / 漏洞利用尝试 / 异常访问
   - 专项：webshell / SQL 注入 / 暴力破解 / 命令执行 / 横向移动 / 数据泄露
   - 不指定时走全量规则但优先级降低

未对齐就开跑容易出现「跑了几小时发现日志类型错了 / 时间窗口对不上」的尴尬。

---

## 三、按日志类型分流

### 3.1 nginx access

**脚本**：`scripts/nginx_anomaly.py`

**字段假设**（combined 格式 + 常见扩展）：
- `remote_addr` / `time_local` / `request_method` / `request_uri` / `status` / `body_bytes_sent`
- `http_referer` / `http_user_agent` / `request_time` / `upstream_addr`

**调用**：
```bash
python3 scripts/nginx_anomaly.py \
  --input /var/log/nginx/access.log \
  --since "2026-06-30T08:00" \
  --until "2026-06-30T18:00" \
  --rules references/attack-patterns/tool-fingerprints.md \
  --output /tmp/hvv-audit-nginx.jsonl
```

**检测维度**：
- 工具 UA 指纹（sqlmap / nuclei / xray / fscan / dirsearch / feroxbuster / nikto / acunetix / nessus / burpsuite）
- 4xx 突增 IP（每分钟 4xx > 50 视为爆破/扫描）
- 敏感路径（`.git/config` / `.env` / `wp-admin` / `phpmyadmin` / `actuator/env`）
- 异常 payload 关键字（`${jndi:` / `Runtime.getRuntime` / `phpinfo()` / `system(` / `eval(` / `union+select`）
- 长 URL（> 1500 字符）
- 编码套娃（URL 含 `%25%`、`%2e%2e%2f` 等多层 url-encode 路径穿越）
- 路径穿越（`../../` `..\\..\\`、`%2e%2e`、`\\..\\`）
- 异常 Method（OPTIONS 大量 / PROPFIND / DEBUG / TRACE）
- 异常 status 序列（同 IP 大量 200 后突然 500，可能是 RCE 触发）

### 3.2 Apache access

**脚本**：同 `nginx_anomaly.py`，参数 `--format apache-combined`

**字段差异**：
- Apache 默认 combined 字段顺序与 nginx 一致
- 自定义 log_format 时需用户提供 LogFormat 字符串

**注意点**：
- mod_security 拦截会生成 `403` 而非 `444`
- `request_method` 含 OPTIONS 的合法预检需排除

### 3.3 auth.log / secure（Linux SSH 审计）

**脚本**：`scripts/auth_log_audit.py`

**字段假设**：
- 时间 / hostname / 进程 / 消息体（`sshd[pid]: Failed password for <user> from <ip> port <port> ssh2`）

**调用**：
```bash
python3 scripts/auth_log_audit.py \
  --input /var/log/auth.log \
  --since "2026-06-29T00:00" \
  --output /tmp/hvv-audit-auth.jsonl
```

**检测维度**：
- 暴破：同源 IP 单位时间失败次数（默认 60s 阈值 20）
- 暴破成功：失败序列后紧跟 `Accepted password/publickey`
- 不存在用户名（`invalid user xxx`）批量尝试（典型字典攻击）
- 非常用账号成功登录（root / oracle / admin / test 应高度警觉）
- 异常时段登录（22:00 - 06:00）
- 异常源 IP 国别（基于本地 GeoIP 库可选）
- sudo 滥用：短时间内 sudo 切到 root 后 history 异常

### 3.4 Windows EVTX-CSV

**前置**：用户先在客户机用 `wevtutil epl Security ./security.evtx` 或 `Get-WinEvent ... | Export-Csv` 导出为 CSV。

**关键 EventID**：

| EventID | 含义 | 关注点 |
|---|---|---|
| 4624 | 成功登录 | LogonType 3（网络）/ 10（RDP）异常源 |
| 4625 | 失败登录 | 暴破阈值 |
| 4634/4647 | 注销 | 配对 4624 计算驻留时间 |
| 4672 | 特权登录 | 非管理员账号触发即异常 |
| 4688 | 进程创建 | 父子进程链异常（office → cmd / powershell） |
| 4720 | 新增账户 | 演习期间任何新增均高危 |
| 4722/4724 | 启用账户/重置密码 | 同上 |
| 4732 | 加入管理员组 | 高危 |
| 7045 | 新服务安装 | 持久化关键信号 |
| 4698 | 计划任务创建 | 持久化关键信号 |
| 1102 | 安全日志被清除 | 反取证强信号，立即 P0 |

**处理**：用通用 `ioc_match.py` + 关键 EventID 过滤即可，无独立脚本。

### 3.5 应用 audit log（JSON）

**脚本**：`scripts/ioc_match.py --schema custom --field-map <yaml>`

**字段示例**（业务自定义）：
```yaml
field_map:
  ts: "@timestamp"
  user: "audit.user"
  action: "audit.action"
  resource: "audit.target"
  result: "audit.result"
  client_ip: "audit.source_ip"
```

**检测维度**：
- 高危 action（删除 / 导出 / 权限变更 / 配置变更）
- 同 user 短时间内大量 action
- 同 client_ip 跨多个 user 的 action 序列
- 非工作时段的高危 action

### 3.6 厂商 vendor 告警审计

当审计对象不是原始 nginx/auth 日志、而是**厂商安全设备产生的告警**（例如客户拿来一批"最近一周奇安信 NGSOC 告警"要求做深度审计而非日常分诊）时，audit 模式的入口不再是 `log_parser.py`，而是 `vendor_field_mapper.py`。

**典型场景**：
- 客户驻场问："帮我把最近 7 天的深信服 SIP 告警过一遍，重点看有没有真实横向证据"
- 事后复盘："这一批雷池 SafeLine 高危告警里，哪些是真实的 RCE 尝试？"
- 演习复盘："演习期间明御 WAF 拦截了这些高危 payload，帮我审计一遍是否有绕过的"

**流程差异**（相对 3.1-3.5 的原始日志审计）：

1. **入口脚本**：`python3 scripts/vendor_field_mapper.py --input <厂商导出> --vendor <name> --output /tmp/hvv-audit-vendor.jsonl`
2. **字段抽屉**：读 `references/log-fields/vendor-<name>.md` frontmatter（4 家：qax-ngsoc / sangfor-sip / changting-safeline / dbappsec-mingyu），完成 12 字段 + severity + category 归一化。
3. **审计视角切换**：厂商告警是"设备已判定"结果，audit 关注**误报 / 漏报 / 真实命中的深度证据**：
   - 高危批次的 TP/FP 抽样评估（每 50 条抽 5 条人工核）
   - 单 src_ip 在 24h 内的规则命中谱系（多少种 category / 多少个 dst）
   - 拦截失败（`action=alert / monitor`）的高危告警清单（真实威胁排查重点）
4. **关联脚本**：归一化后的 NDJSON 仍可喂给 `ioc_match.py / timeline_build.py`，与其他日志源做跨源关联，不影响 audit 主流程。
5. **校准环节**：4 份 vendor md 里的"驻场时需校准"字段（如 SIP 的 `confidence`、明御的"高"级别语义），驻场首日必须与客户驻场安全工程师人工对齐，避免 audit 结论偏差。

**vendor 快速参考表**：

| vendor-key | display_name | 关键校准点 |
|---|---|---|
| qax-ngsoc | 奇安信 NGSOC | 高危→P1 保守映射；tenant_id 分组 |
| sangfor-sip | 深信服 SIP | AI 引擎误报去噪；kill_chain_stage 字段 |
| changting-safeline | 长亭雷池 SafeLine | X-Forwarded-For 真实 IP；raw_request 隐私脱敏 |
| dbappsec-mingyu | 安恒明御 WAF | 高级别→P0 激进映射；target_domain 站点归组 |

**与 monitor 的分工**：monitor 关注**当日告警的分诊速度**（在值守窗口内处理完），audit 关注**多日告警的深度语义**（挖历史证据），两者共用 vendor_field_mapper.py 归一化产物但下游脚本不同。

---

## 四、关联分析模式

audit 模式的核心价值不在单日志，而在**多源关联**。常用关联模式：

### 4.1 同 IP 跨日志

- 同 IP 在 nginx 出现工具 UA + 在 auth.log 同一时段尝试 ssh → 升级为「多面攻击」
- 同 IP 在 nginx 触发漏洞 + 在 webshell_scan 命中新增文件 → 直接 P0

### 4.2 同 UA 多次出现

- 异常 UA 横跨多个 hostname → 攻击者批量扫描，提取 IP 列表作 IOC
- 同 UA 短时间内 IP 变化（10 个 IP 同 UA）→ 走代理池，仍按 UA 维度聚合

### 4.3 同账号异常时段

- 同 username 在 auth.log 非常用时段成功登录 + 在应用 audit log 出现高危 action
- 该账号在历史 30 天从未在该 hostname 出现过

### 4.4 时间线合并

- 通过 `scripts/timeline_build.py` 把 auth / nginx / app-audit / syslog 时间线合并，发现 1 分钟内的「探测 → 利用 → 登录 → 横移」全链路
- 任何全链路命中 → P0

---

## 五、典型异常 pattern 速查表（≥ 15 项）

| Pattern 名称 | 触发字段 / 关键词 | 误报概率 | 处置去向 |
|---|---|---|---|
| sqlmap 探测 | UA 含 `sqlmap` | 低 | playbook/sql-injection |
| nuclei 模板扫描 | UA 含 `Nuclei`/`Mozilla/5.0 (compatible; Nuclei`  | 低 | 工具溯源 + playbook 对照 |
| fscan 内网扫描 | UA `Go-http-client` + 多端口探测 + 字典路径 | 中 | playbook/lateral-movement |
| dirsearch 目录爆破 | 短时间内大量 4xx + 字典命中 | 低 | 节流封禁 + 监控 200 |
| Log4Shell jndi | URL/Header 含 `${jndi:` | 极低 | playbook/command-exec |
| fastjson 反序列化 | payload 含 `@type` 且短时间内 POST | 极低 | playbook/command-exec |
| shiro 反序列化 | Cookie `rememberMe=` 异常大 + status 5xx | 低 | playbook/command-exec |
| Spring4Shell | URL 含 `class.module.classLoader` | 低 | playbook/command-exec |
| webshell 落地 | POST `*.jsp/*.php/*.aspx` 200 + body 体小 | 中 | playbook/webshell |
| webshell 访问 | GET 异常 `.jsp/.php` 路径 200 + 非业务路径 | 中 | playbook/webshell |
| 路径穿越 | URL 含 `../` / `%2e%2e` | 中 | 看 status 是否 200 |
| 文件读取尝试 | URL 含 `/etc/passwd` / `web.config` / `.git/config` | 低 | 即使 4xx 也升 P1 标 IOC |
| SSRF 探测 | URL 含 `http://169.254.169.254` / `metadata` | 低 | playbook |
| ssh 暴破 | `Failed password` 同 IP 60s 内 >= 20 | 低 | playbook/brute-force |
| ssh 暴破成功 | failed 序列后 `Accepted password` | 极低 | 立即 P0 + IR |
| sudo 异常 | sudo 切换到 root 后大量 `apt`/`yum`/`useradd`/`crontab` | 中 | 关联 bash_history |
| 新增账户 | EventID 4720 / `useradd` 在 auth.log | 低 | 直接 P0 |
| 计划任务异动 | `/etc/cron.d/.*` 修改 / EventID 4698 | 中 | playbook/persistence |
| C2 心跳 | 同 dst 周期性外联（间隔 30s/60s/300s） | 中 | playbook |
| DNS 隧道 | 异常长 subdomain + 高频 TXT 查询 | 高 | 需流量层，audit 仅给线索 |

---

## 六、输出格式

### 6.1 异常清单条目（脱敏）

```json
{
  "id": "AUD-014",
  "severity": "P1",
  "category": "sqli",
  "evidence": "nginx access.log:line 18223; GET /api/order?id=1' UNION SELECT 1,2,3-- HTTP/1.1 status=200 ua=sqlmap/1.6",
  "rule_id": "R-NGX-SQLMAP-001",
  "false_positive_prob": 0.15,
  "recommended_action": "立即审计该 IP 在 audit log 是否出现数据导出 action；详见 playbooks/sql-injection.md",
  "iocs": [
    {"type":"ip","value":"203.0.113.50","confidence":"high","first_seen":"2026-06-30T09:12:33+08:00","source":"access.log:18223","tag":"attacker"},
    {"type":"ua","value":"sqlmap/1.6","confidence":"high","first_seen":"2026-06-30T09:12:33+08:00","source":"access.log:18223","tag":"tool:sqlmap"}
  ]
}
```

### 6.2 IOC 列表

```json
[
  {"type":"ip","value":"203.0.113.50","confidence":"high","first_seen":"2026-06-30T08:14:23+08:00","source":"nginx access.log; auth.log","tag":"attacker;multi-vector"},
  {"type":"ua","value":"sqlmap/1.6","confidence":"high","first_seen":"2026-06-30T09:12:33+08:00","source":"nginx access.log","tag":"tool:sqlmap"},
  {"type":"path","value":"/var/www/<app>/upload/x.jsp","confidence":"medium","first_seen":"2026-06-30T11:32:08+08:00","source":"filesystem ls","tag":"webshell-suspect"}
]
```

---

## 七、与 monitor / ir 的衔接

- audit 命中 webshell 落地 + 行为证据 → 主动建议「转 ir 让客户跑 quick_check」
- audit 仅找到「探测但未利用」证据 → 回到 monitor 列表加注 + 持续观察
- audit 阶段的 IOC 自动反哺 monitor 的 IOC 库（本次会话内）

---

## 八、6 步流程总览

1. **范围对齐**（4 问）
2. **解析 + 字段标准化**（`scripts/log_parser.py`；厂商告警走 `scripts/vendor_field_mapper.py --vendor <name>`）— 确定性步骤，异常时触发检查点 A
3. **专用脚本检测**（按日志类型分流到 nginx_anomaly / auth_log_audit / ioc_match）

   > **🔍 检查点 A（审核）**：本步完成后**必跑** `agents/checkpoint-reviewer`（确定性步骤仅异常时触发）。审核命中合理性 + 误报剔除（P2/P3 聚合统计，P0/P1 抽样逐条）。审核通过进检查点 B。

4. **关联分析**（IP / UA / 账号 / 时间线，调用 `agents/log-analyzer` 子 agent）**必跑**（检查点 B 决策）
5. **脱敏**
6. **渲染异常清单 + IOC 列表**

   > **✅ 检查点 C（验证）**：出终报前**必跑** `agents/verdict-validator` 验证 verdict 证据闭环 + 待跟进列表无漏标。rejected 打回检查点 B 重做。

7. **收尾：渲染 `final-report.md`（audit 形态）+ `findings.json`**（见下）

---

## 九、收尾：统一终报 + findings.json

audit 完成异常清单 + IOC 后，**必须**输出跨模式统一终报与机器可读伴生文件（见 `SKILL.md §输出契约`）：

- **`final-report.md`（audit 形态）**：按 `assets/final-report.md` 渲染——
  - §2 判定与影响：verdict 多为 `high_suspicion` / `inconclusive` / `no_intrusion`，填异常源数 + 是否升级 ir
  - §3 攻击路径地图：渲染为**跨源异常链**形态（nginx → auth → nginx 等跨日志源同 IP/账号关联链）
  - §4 分层发现详情：P0/P1 全文 8 字段卡（evidence 带文件:行号）
  - §5 证据与时间线：✅ 必填（audit 的时间线是核心产出）
  - §7 处置建议与优先级：取**修复建议清单**变体（未执行，给 owner + 截止）
  - §10 附件：`ioc-extract.md`（IOC json）；若升级 ir 则挂 `incident-report.md`
- **`findings.json`**：按 `assets/findings-schema.md` 生成，`mode=audit`，`findings[]` 为异常清单条目（8 字段），`attack_paths[]` 在有跨源链时填、否则空

> audit 发现 webshell 落地 / RCE 成功等确认入侵信号 → verdict 升 `confirmed_intrusion` 并升级 ir，终报改走 ir 形态（详尽），audit 形态作为证据来源挂附件。

---

## 相关引用

- 字段速查：`../log-fields/web-access.md` `../log-fields/linux-auth.md` `../log-fields/windows-evtx.md`
- 厂商字段抽屉：`../log-fields/vendor-{qax-ngsoc,sangfor-sip,changting-safeline,dbappsec-mingyu}.md`
- 攻击特征库：`../attack-patterns/`
- 处置剧本：`../playbooks/`
- 分级标准：`../grading.md`
