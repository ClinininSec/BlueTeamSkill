# 值守日报 · {{report_date}}

> 客户：`<customer>` | 项目：`<project>` | 值守班组：`<shift>` | 班次：`{{shift_window}}` | 起草：`<analyst>` | 复核：`<reviewer>`

---

## 1. 概览（一句话总结）

`{{one_liner}}`

> 示例：「今日累计告警 1832 条，**3 条 P0**（fastjson 反序列化真实命中 + ssh 暴破成功 + actuator 信息泄露），均已通知客户并完成临时封堵；**12 条 P1**待客户复核；其余 P2/P3 已归档。」

---

## 2. 告警分级统计

| 级别 | 数量 | 同比昨日 | 处置完成率 | 备注 |
|---|---|---|---|---|
| **P0** | {{p0_count}} | {{p0_delta}} | {{p0_done_rate}} | 立即响应 |
| **P1** | {{p1_count}} | {{p1_delta}} | {{p1_done_rate}} | < 1h |
| **P2** | {{p2_count}} | {{p2_delta}} | {{p2_done_rate}} | < 4h |
| **P3** | {{p3_count}} | {{p3_delta}} | — | < 24h，归档 |
| **合计** | {{total}} | {{total_delta}} | {{overall_rate}} | |

---

## 3. 按攻击类型分布

| 类型 | 数量 | TOP 来源 IP（脱敏） | 主要规则 ID | 备注 |
|---|---|---|---|---|
| webshell 利用 / 上传 | {{webshell_n}} | {{webshell_top_ip}} | PLB-WS-* | |
| 暴力破解 | {{brute_n}} | {{brute_top_ip}} | PLB-BF-* | |
| SQL 注入 | {{sqli_n}} | {{sqli_top_ip}} | PLB-SQ-* | |
| 命令执行 / 反序列化 / JNDI | {{rce_n}} | {{rce_top_ip}} | PLB-CE-* | |
| 横向移动 / 内网探测 | {{lateral_n}} | {{lateral_top_ip}} | PLB-LM-* | |
| 扫描器 / 信息收集 | {{recon_n}} | {{recon_top_ip}} | SIG-TF-* | 多为低风险背景噪声 |
| 其他 | {{other_n}} | — | — | |

---

## 4. P0 / P1 详情（每条独立小节）

### P0-001：{{p0_001_title}}

- **告警 ID（本批）**：MON-001
- **首次出现**：{{p0_001_first_seen}}
- **末次出现**：{{p0_001_last_seen}}
- **来源 IP**：`192.168.1.xxx`（脱敏）
- **目标**：`<internal>` / `8080/tcp` / 系统 = OA 系统
- **命中规则**：PLB-CE-006、SIG-TF-018
- **证据片段**（脱敏后）：
  ```
  ts=2026-06-30T10:23:45 src_ip=192.168.1.xxx
  uri=/api/login method=POST status=200 body_bytes=1832
  ua=Apache-HttpClient
  payload_excerpt=...特征字符串截断...
  ```
- **关联分析**：同源 IP 在 8:23~10:24 跨 R-NGX-001 / R-NGX-008 / PLB-CE-006 共 3 类规则命中，强关联簇
- **误报概率**：0.05
- **处置动作**：
  | 时间 | 动作 | 执行人 | 结果 |
  |---|---|---|---|
  | 10:25 | 通报客户 SOC | `<analyst>` | 已确认接收 |
  | 10:32 | WAF 紧急规则封禁特征 | 客户运维 | 已下发 |
  | 10:40 | 临时封禁 src_ip | 客户运维 | 完成 |
  | 10:55 | 引导客户跑 `scripts/linux_quick_check.sh` 取证 | `<analyst>` | 已回传，转 ir 模式 |
- **后续待办**：转 ir 模式 → 输出 incident-report

### P0-002：…（同结构）

### P1-001：…（同结构，可简化字段）

---

## 5. 关联与趋势

### 5.1 强关联簇
| 簇 ID | 关联源 | 涉及规则数 | 首/末时间 | 升级判定 |
|---|---|---|---|---|
| CLU-001 | src_ip=`192.168.1.xxx` | 3 | 08:23 / 10:24 | 升 P0 → MON-001 |
| CLU-002 | ua=`Mozilla/5.0...xray` | 5 类 path 模式 | 09:11 / 17:46 | P2，归档 |

### 5.2 时序趋势（每小时告警计数）
```
08: ###
09: ######
10: ##############  ← P0 起始
11: ##########
12: #####
13: ####
14: ######
15: ########
16: ####
17: ###
```

### 5.3 业务低谷时段异常（02:00-06:00）
- 无异常 / 或：发现 `192.168.1.yyy` 在 03:12-03:31 短窗高频访问 `/admin/login` → 详见 MON-007

---

## 6. 待跟进列表（次日值守接班用）

| 序号 | 关联告警 ID | 主题 | 阶段 | 责任方 | 截止时间 |
|---|---|---|---|---|---|
| 1 | MON-001 | 8080 OA fastjson 利用 → ir 取证 | 取证中 | 蓝队 + 客户 OA owner | 2026-07-01 12:00 |
| 2 | MON-005 | 12 条 sqlmap 扫描，疑似真实命中 1 条 | 待客户复核 | 客户应用组 | 2026-07-01 18:00 |
| 3 | MON-018 | `<external-ip>` 多次扫描 `actuator/*` | WAF 规则跟进 | 客户运维 | 2026-07-01 12:00 |

---

## 7. IOC 提取（导入 SIEM 持续监控）

完整 IOC 列表见附件 `iocs-{{report_date}}.json`，按 `templates/ioc-extract.md` 标准 schema 输出。本日新增高置信 IOC 数量：

| 类型 | 数量 | 备注 |
|---|---|---|
| ip | 7 | 含 1 个 P0 关联 |
| domain | 2 | 疑似 C2 |
| ua | 4 | xray / nuclei / fscan / apache-httpclient |
| path | 5 | 含 1 个 webshell 路径 |
| hash | 0 | 本批未提取 |

---

## 8. 工具与流程改进建议（可选）

- {{improvement_1}}
  - 示例：「nginx 日志格式建议加 `$request_time` 字段，便于发现 time-based sqli」
- {{improvement_2}}

---

## 9. 交接备忘

- 下一班值守人：`<next_analyst>`
- 关键关注点：见第 6 节"待跟进列表"
- 异常临界点：MON-001 取证若 12:00 前无果，升级到客户应急 owner
- 联系电话：客户应急热线 `<masked>` / SIEM 值班 `<masked>`

---

> 本报告所有 IP / 用户名 / 域名 / 客户名 / 内部路径已通过 `scripts/desensitize.py` 强制脱敏；如需未脱敏版本，需客户授权 + 走加密渠道交付。
>
> 本报告由 `hvv-defender` v{{skill_version}} 生成，分诊使用 `agents/alert-triage` 子 agent，规则版本见 `data/ioc-builtin.json` 与 `data/tool-signatures.json`。
