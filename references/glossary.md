# 术语表（Glossary）

> 蓝队 / 红队 / 监管侧术语统一映射，中英文对照。所有写入日报、audit 异常清单、incident-report 的术语应优先采用本表的标准译法。

---

## 一、蓝队术语（Defender）

| 术语 | 中文 | 英文全称 | 简述 |
|---|---|---|---|
| IOC | 失陷指标 | Indicator of Compromise | 可观察的入侵痕迹（IP/域名/hash/路径/UA 等） |
| IOA | 行为指标 | Indicator of Attack | 攻击行为模式（如「父进程 word.exe 起 powershell」） |
| TTP | 战术-技术-过程 | Tactics, Techniques, Procedures | 攻击方手法画像，高于 IOC，难以快速变更 |
| MITRE ATT&CK | 攻击战术框架 | MITRE ATT&CK | 行业标准的攻击战术/技术枚举矩阵 |
| Kill Chain | 杀伤链 | Cyber Kill Chain | Lockheed 提出的 7 阶段攻击模型 |
| Dwell Time | 驻留时长 | Dwell Time | 攻击者进入到被发现之间的时间 |
| Lateral Movement | 横向移动 | Lateral Movement | 内网中从一台失陷主机扩展到其他主机 |
| Persistence | 持久化 | Persistence | 维持立足点（计划任务/服务/启动项/SSH key） |
| C2 | 命令与控制 | Command and Control | 攻击者与失陷主机的通信通道 |
| Beacon | 心跳信标 | Beacon | C2 客户端定期外联的小流量包 |
| EDR | 终端检测响应 | Endpoint Detection and Response | 主机层检测/响应产品 |
| SIEM | 安全事件管理 | Security Information and Event Management | 日志聚合 + 关联分析平台 |
| SOAR | 安全编排响应 | Security Orchestration, Automation, Response | 安全 playbook 自动化编排 |
| NDR | 网络检测响应 | Network Detection and Response | 流量侧检测/响应 |
| XDR | 扩展检测响应 | Extended Detection and Response | EDR/NDR/邮件/云等多源融合 |
| SOC | 安全运营中心 | Security Operations Center | 7×24 安全监控团队 |
| Threat Hunting | 主动狩猎 | Threat Hunting | 基于假设主动搜寻未被告警的入侵 |
| Threat Intel | 威胁情报 | Threat Intelligence | 外部 IOC / TTP / 对手画像 |
| Playbook | 处置剧本 | Playbook | 针对特定攻击类型的标准化处置流程 |
| DFIR | 数字取证与应急 | Digital Forensics & Incident Response | 取证 + 应急响应统称 |
| Triage | 分诊 | Triage | 告警快速优先级判定 |
| Containment | 止血 / 遏制 | Containment | 切断攻击者继续行动的能力 |
| Eradication | 根除 | Eradication | 清除攻击者残留 |
| Recovery | 恢复 | Recovery | 业务恢复到清洁基线 |
| Post-mortem | 复盘 | Post-mortem | 事件结束后的复盘改进 |

---

## 二、攻击侧术语（Attacker）

| 术语 | 中文 | 英文 | 简述 |
|---|---|---|---|
| Webshell | 网页后门 | Web Shell | 通过 web 接口执行命令的脚本马 |
| 反序列化 | 反序列化漏洞 | Deserialization | 不可信对象反序列化触发代码执行 |
| SSRF | 服务端请求伪造 | Server-Side Request Forgery | 服务端代攻击者发起内网请求 |
| RCE | 远程代码执行 | Remote Code Execution | 攻击者远程触发任意代码 |
| LFI / RFI | 本地 / 远程文件包含 | Local/Remote File Inclusion | 通过包含文件读取或执行 |
| 内网穿透 | 内网隧道 | Pivot / Tunnel | 把内网服务穿出公网（frp/nps/ssh -R） |
| 横向移动 | 内网横移 | Lateral Movement | 同蓝队术语 |
| 提权 | 权限提升 | Privilege Escalation | 从低权用户升到 root / SYSTEM |
| 0day | 零日漏洞 | Zero-day | 公开补丁前的漏洞 |
| 1day | 一日漏洞 | One-day | 公开补丁但未广泛应用的漏洞 |
| Nday | N 日漏洞 | N-day | 已公开较久但仍有未修补主机的漏洞 |
| Fastjson | Fastjson RCE | fastjson | 阿里 JSON 库历史多发反序列化 RCE 系列 |
| Log4j | Log4Shell | CVE-2021-44228 | JNDI 注入触发 RCE |
| Shiro | Shiro 反序列化 | Apache Shiro | `rememberMe` cookie AES key 默认值导致反序列化 |
| 冰蝎 | 冰蝎 | Behinder | 国产加密 webshell 管理工具 |
| 哥斯拉 | 哥斯拉 | Godzilla | 国产加密 webshell 管理工具 |
| 蚁剑 | 蚁剑 | AntSword | 跨平台 webshell 管理工具 |
| CobaltStrike | CS 上线 | Cobalt Strike | 商业红队 C2 框架 |
| Metasploit | MSF | Metasploit Framework | 开源渗透 / 利用框架 |
| Sliver | Sliver | Sliver C2 | 开源跨平台 C2 框架 |

---

## 三、监管侧术语（Regulator / Exercise）

| 术语 | 中文 | 英文 | 简述 |
|---|---|---|---|
| 护网 | 护网行动 | HVV / Cyber Defense Exercise | 国家级网络安全攻防演习 |
| HVV | Hu Wang | HVV | 「护网」拼音缩写，业内常用代称 |
| 红队 | 红方 | Red Team | 攻击方 |
| 蓝队 | 蓝方 | Blue Team | 防守方，本 Skill 所处角色 |
| 紫队 | 紫方 | Purple Team | 演练裁判 / 协同方 |
| 监管单位 | 监管方 | Regulator | 组织方（如公安部 / 网信办 / 省厅） |
| 演习 | 演练 | Exercise | 通称 |
| 评分规则 | 计分规则 | Scoring Rules | 攻防双方按规则得失分 |
| 通报机制 | 通报 | Reporting | 防守方向监管单位通报事件的格式与时限 |
| 重保 | 重大活动保障 | Critical Event Protection | 重大活动（两会 / 进博 / 世博）期间安保 |
| 大型活动安保 | 同上 | Large Event Security | 通用术语 |
| 驻场 | 驻场服务 | On-site Service | 乙方人员到甲方现场作业 |
| 值守 | 值班 | On-duty / Watch | 7×24 监控告警 |

---

## 四、本 Skill 内部用语

| 术语 | 含义 |
|---|---|
| MON / AUD / TRAF / IR / REM | 五模式 finding ID 前缀（monitor/audit/traffic/ir/remote） |
| R-NGX-001 | 规则 ID 命名约定：`R-<日志类型缩写>-<序号>` |
| PLB-WS-002 | playbook 规则 ID：`PLB-<类型缩写>-<序号>` |
| FP / TP | False Positive / True Positive，误报 / 真报 |
| FP-suspect | 疑似误报标签 |
| 待跟进列表 | 当日值守需追踪到闭环的真实 / 疑似真实告警子集 |
| 升级链 | monitor → audit → ir 的会话内顺序流转 |

---

## 五、缩写速查

| 缩写 | 全称 |
|---|---|
| APT | Advanced Persistent Threat |
| SSO | Single Sign-On |
| MFA | Multi-Factor Authentication |
| WAF | Web Application Firewall |
| FW | Firewall |
| IDS / IPS | Intrusion Detection / Prevention System |
| DLP | Data Loss Prevention |
| HIDS | Host-based IDS |
| NIDS | Network-based IDS |
| PoC | Proof of Concept |
| CVE | Common Vulnerabilities and Exposures |
| CVSS | Common Vulnerability Scoring System |
| TLP | Traffic Light Protocol（情报共享分级） |
| YARA | 文件特征匹配规则语言 |
| Sigma | 通用 SIEM 规则语言 |
| LOLBin | Living-Off-the-Land Binary（利用系统自带工具的攻击） |

---

## 六、相关引用

- 攻击战术映射详见 `references/modes/ir.md` 攻击链还原章节
- 分级 SLA 详见 `references/grading.md`
- 脱敏与红线详见 `references/compliance.md`
