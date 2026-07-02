# Rule ID 命名与分层

> hvv-defender 内所有规则 / 检查项 ID 的命名空间总表。SKILL.md 只保留一句"规则 ID 命名规范见此文"，细节在这里。

## 一、命名空间总表

| 前缀 | 含义 | 落地位置 | 是否被脚本 emit |
|---|---|---|---|
| `PLB-<XX>-NNN` | Playbook 指引规则 | `references/playbooks/*.md` 中的建议规则 | ❌ 供蓝队照此写客户 SIEM 规则 |
| `SIG-<XX>-NNN` | 攻击特征 | `references/attack-patterns/*.md` 知识库 + `data/{tool-signatures, webshell-patterns, traffic-signatures, windows-persistence-patterns, sysmon-detection-rules}.json` | ✅ 316 条已落地为脚本运行时数据（v0.3-M1：webshell 36 + tool 60 + traffic 126 + windows-persistence 48 + sysmon 38 = 308；外加 8 条 SIG-AD / HP 预留），其余作为知识库供人工检索 |
| `R-<AUTH/NGX>-NNN` | 日志运行时规则（Linux） | `scripts/{auth_log_audit, nginx_anomaly}.py` | ✅ 全部由脚本 emit |
| `R-TRAF-NNN` | 流量运行时规则 | `scripts/traffic_anomaly.py` | ✅ 68 类 + `R-TRAF-999` 关联簇 = 共 69 条（基础 12 + Win 横向 4 + 内网穿透 3 + TLS 深化 20 + DNS 深化 15 + 国内红队工具 14 + 关联簇 1） |
| `R-WIN-NNN` | Windows evtx 运行时规则 | `scripts/evtx_hunt.py` | ✅ 22 条，Security / Kerberos / PowerShell / Sysmon 四组 |
| `R-REM-NNN` | Remote 只读 / 采集运行时 | `scripts/remote/ssh_probe.py` `remote_collect.py` | ✅ 每次成功执行 emit 一条 8 字段告警 + 一条 audit.jsonl 审计条目 |
| `R-REM-DISP-NNN` | Remote Tier 3 处置类 | 同上，`allow_mutating=true` 时 emit | ✅ 独立命名空间便于告警审计区分只读 vs 处置 |
| `CHECK-LIN-N.N` | Linux 主机核查项 | `references/ioc-checklist/linux-host-check.md` | ❌ `linux_quick_check.sh` 采集后照清单人工核，14 章 |
| `CHECK-WIN-N.N` | Windows 主机核查项 | `references/ioc-checklist/windows-host-check.md` | ❌ `windows_quick_check.ps1` 采集后照清单人工核，14 章 48 项 |
| `IOC-<type>` | ioc_match 命中分类 | `scripts/ioc_match.py` 输出的分类 tag；匹配库位于 `data/ioc-builtin.json`（51 条基线 IOC） | ✅ 由 `ioc_match.py` emit |
| `VENDOR-<name>` | 厂商归一化标签 | `scripts/vendor_field_mapper.py` 输出中的 `vendor` 字段 | ✅ 由 mapper emit，用于告警按厂商切片 |
| `SESSION-AUDIT-<action>` | Remote 会话审计 | `~/.hvv-defender/audit.jsonl` 中 `action` 字段值 | ✅ `ssh_probe` / `remote_collect` / `session_recorder` 每次调用追加一条 |

## 二、为什么分层

不是所有规则都适合让脚本运行：

- **`PLB-*`** 是给人看的处置剧本，覆盖 SIEM 逻辑 + 关联升级 + 沟通话术，天然不由 Python 匹配
- **`CHECK-*`** 是给蓝队照单跑命令的清单，需要人工判断"这个进程是否眼熟"、"这个 crontab 是否甲方运维自己加的"
- **`R-*`** 是脚本运行时规则，输入日志 / pcap，emit 告警条目
- **`SIG-*`** 一部分落 JSON 供脚本查表，一部分留 markdown 供检索
- **`IOC-*`** / **`VENDOR-*`** / **`SESSION-AUDIT-*`** 是脚本 emit 的分类 tag

## 三、告警条目 8 字段（跨模式一致）

所有 `R-*` / `PLB-*` 命中都输出统一 8 字段。SKILL.md 「输出契约 §1」有摘要，完整样例见 `references/modes/monitor.md §七`。

| 字段 | 取值 | 必填 |
|---|---|---|
| `id` | 本次会话唯一（`MON-001` / `AUD-001` / `IR-001` / `TRAF-001` / `REM-001`） | ✅ |
| `severity` | `P0` / `P1` / `P2` / `P3` | ✅ |
| `category` | webshell / brute-force / sqli / rce / lateral / recon / data-exfil / 其他 | ✅ |
| `evidence` | 日志原文（脱敏后）+ 行号 / 文件路径 | ✅ |
| `rule_id` | 命中规则 ID（`R-NGX-001` / `PLB-WS-002` / …） | ✅ |
| `false_positive_prob` | 0.0 - 1.0 | ✅ |
| `recommended_action` | 处置建议（参考对应 playbook） | ✅ |
| `iocs` | 提取出的 IOC 列表（按 IOC schema） | ⛔ 可空 |

## 四、IOC 标准 schema（用于 `assets/ioc-extract.md`）

| 字段 | 取值 | 说明 |
|---|---|---|
| `type` | `ip` / `domain` / `url` / `hash:md5` / `hash:sha1` / `hash:sha256` / `ua` / `path` / `email` / `tool` | |
| `value` | IOC 实际值 | 输出前脱敏 |
| `confidence` | `high` / `medium` / `low` | |
| `first_seen` | 日志中首次出现的时间戳 | |
| `source` | 提取来源：日志文件 + 行号 / 规则 ID | |
| `tag` | 可选：`tool:fscan` / `c2:cobaltstrike` / `fp-suspect` | |

## 五、findings.json 伴生 schema（用于 `assets/findings-schema.md`）

> v0.4-M1 新增。任意模式收尾与 `final-report.md` 同生的机器可读文件 `findings.json` 遵此 schema。

| 顶层字段 | 取值 | 说明 |
|---|---|---|
| `findings[]` | 每条 = §三 的 8 字段 + `blast_radius` + `confidence` + `mode` | 8 字段与本表 §三 严格一致 |
| `attack_paths[]` | `tactic_chain` + `nodes[]`（消费 `agents/ir-investigator` 的 `kill_chain`） | ir/traffic/audit 必填，monitor/remote 可空 |
| `ioc_ref` | 指向 `iocs-<case_id>.json` | IOC 文件遵 §四 schema |
| `summary` | `{p0,p1,p2,p3,total}` | = `findings[]` 按 severity 聚合 |
| `verdict` | `confirmed_intrusion` / `high_suspicion` / `inconclusive` / `no_intrusion` | 与 `final-report.md §2` 一致 |

完整字段表、校验清单、SIEM 导入说明、ir/monitor 两形态完整示例见 `assets/findings-schema.md`。
