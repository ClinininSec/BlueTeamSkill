# hvv-defender CHANGELOG

> 各版本历史与命名空间演化。SKILL.md 只保留"当前版本"标记，历史细节看这里。

---

## v0.4-M2（当前）— 激活死规则 + 规则源同步框架

**让既有规则真正生效 + 引入外部规则源离线同步**

- **激活 evtx_hunt 死规则**：
  - `R-WIN-023`（sysmon 补充规则命中告警）—— 之前 sysmon 规则能匹配但命中后不 emit（硬编码 gate），现真正告警，severity 按规则自身 severity 映射
  - `R-WIN-024`（持久化位置命中告警）—— 之前 `persistence_rules` 是死参数完全没消费，现按 Sysmon EID 11/12/13 的 `location` contains 匹配告警
- **打通 JA3 数据流**：
  - `traffic_anomaly.py` tls 分发补 `ja3`/`ja3s`/`cipher` case —— `SIG-TRAF-087+` JA3 签名 + 硬编码 `KNOWN_JA3_C2` dict 真正生效（之前 tls 分发只认 sni/cert_cn/cert_issuer）
  - `pcap_parser.py` view_tls 补 `tls.handshake.ja3`/`ja3s` 输出 —— 之前 pcap_parser 根本不输出 ja3，导致整个 JA3 检测链路是死的
- **规则源同步框架** `scripts/feeds/`：
  - `sync_owasp_crs.py` —— OWASP CRS 通用 Web 攻击正则 → `traffic-signatures.json`（+149 条，http view）；状态机解析 SecRule `@rx`，正确处理转义双引号 + 续行，Python re 兼容性校验，幂等合并去重
  - `sync_yara.py` —— YARA 通用 webshell 正则 → `webshell-patterns.json`（+4 条）；解析 YARA `strings`，提取正则类特征，nocase → `(?i)`
  - `sync_et_open.py` —— ET Open 通用流量规则 → `traffic-signatures.json`（+1512 条，http view）；解析 Suricata `content`/`pcre`，策展 web_server/user_agents/coinminer/exploit_kit/current_events
  - `sync_sigma.py` —— Sigma 通用 Windows 检测规则 → `sysmon-detection-rules.json`（+437 条）；解析 Sigma `detection`（`|contains`/`|endswith`/`|startswith`/`|re`）转 Python 正则；logsource→event_id 映射；level high/critical 策展
  - `README.md` —— feeds 设计原则（离线优先/红线/幂等）+ 已实现/待实现同步器清单
  - 所有同步器支持 `--local` 指定本地已下载源目录（跳过克隆），`--dry-run` 预览
- **消费端补强** `traffic_anomaly.py` http 分发补 `sqli`/`rce`/`xss`/`lfi`/`rfi` category 分支 —— CRS/ET 规则命中后承载 emit（R-TRAF-003 SQLi / R-TRAF-004 RCE / R-TRAF-002 XSS·LFI·RFI）
- **路线图** `todo.md`（项目根）—— 阶段 0 已完成项 + 6 个待实现规则源 + 国产设备扩充 + 国内威胁情报 + MITRE ATT&CK 映射 + MCP 工具化

**设计决策**：① 激活死规则优先于灌新规则（否则灌进去不告警）；② 规则源同步器构建期离线拉取，运行时零外发，兼容离线优先；③ 国外通用源（OWASP CRS/Sigma/ET Open/YARA）+ 国内针对性源（kunpeng/wsm 等）结合；④ 红线贯穿——同步器只提取检测特征，不输出可复现 PoC。

---

## v0.4-M1 — 规范化统一终报

**跨模式统一结论报告 + 机器可读伴生文件**

- 新模板：`assets/final-report.md` —— 5 模式收尾统一终报，按**攻击路径**组织（防御者视角，借用代码审计模板的分层优先级 / 路径地图 / 评分卡 / 时间线模拟 / MRS 骨架，守红线不出 PoC）；10 节 spine + 模式激活表（ir 形态最厚 / monitor·remote 形态最薄）
- 新 schema：`assets/findings-schema.md` —— 终报的机器可读伴生文件 `findings.json`；`findings[]` 严格遵循 8 字段契约（`rule-id-namespaces.md §三`），`attack_paths[]` 消费 `ir-investigator` 的 `kill_chain`，`ioc_ref` 指向 `ioc-extract.md` 的 IOC 文件
- 现有 4 模板（`incident-report` / `daily-report` / `ioc-extract` / `handover`）降为终报的**模式专属附件**
- 5 模式 + 1 playbook 接入收尾步骤：`modes/{monitor,audit,ir,remote}.md` + `playbooks/traffic-audit.md` 各新增"收尾：渲染 final-report.md（X 形态）+ findings.json"节
- 3 个子 agent（`alert-triage` / `log-analyzer` / `ir-investigator`）标注其 `findings[]` / `kill_chain` 为 findings.json 直接来源
- `SKILL.md` 输出契约段加"收尾统一报告"；关键参考文件表 +2 行；Quick Reference +1 行；版本升 v0.4-M1
- `rule-id-namespaces.md` 新增 §五 findings.json schema 指针（与 §四 IOC schema 对称）

**设计决策**（用户对齐）：① 防御者视角借用攻击路径骨架；② 新增统一终报保留现有 4 个为附件；③ 全部 5 模式收尾都出统一报告（spine + 模式分支）；④ 同时输出 findings.json 对齐 8 字段契约。

---

## v0.4-M0 — remote 模式：授权 SSH 分析

**新增第 5 模式：remote（SSH 远程分析）**

- 新脚本：`scripts/remote/ssh_probe.py` / `remote_collect.py` / `session_recorder.sh`
- 新数据：`data/remote-command-whitelist.json`（59 条命令，3 tier：40 只读 + 8 采集 + 11 处置）
- 新引用：`references/modes/remote.md` + `references/remote-command-whitelist.md` + `references/log-fields/audit-session.md`
- 新命名空间：`R-REM-*` / `R-REM-DISP-*` / `SESSION-AUDIT-*`
- **合规四要素**（授权 + 白名单 + 审计 + 录制）在 `references/modes/remote.md §二` 展开
- **操作红线**调整为"只管破坏性 / 不可逆 / 攻击复用三类硬操作"；脱敏、白名单管理、审计留痕等下沉为默认工作流规范（见 `references/compliance.md`）
- **堡垒机降级**：客户走 JumpServer / 齐治 / Coco 等场景时，Skill 不接堡垒机 API，只生成命令清单让驻场人员在堡垒机 web 端粘贴（H-I-L）

---

## v0.3-M1 — 三大能力包

1. **国产厂商告警研判**：4 家（QAX NGSOC / Sangfor SIP / 长亭雷池 SafeLine / 安恒明御 WAF）+ `scripts/vendor_field_mapper.py`
2. **Windows 主机 IR 全套**：
   - `scripts/windows_quick_check.ps1` 采集脚本
   - `scripts/evtx_hunt.py` 22 条 `R-WIN-*` 规则（Security / Kerberos / PowerShell / Sysmon 四组）
   - `references/ioc-checklist/windows-host-check.md` 14 章 48 项（`CHECK-WIN-*`）
   - `references/log-fields/windows-sysmon.md` 19 类字段速查
   - `data/windows-persistence-patterns.json` 48 条
   - `data/sysmon-detection-rules.json` 38 条
3. **流量深化**：新增 `R-TRAF-050~098` 共 49 条 + `data/traffic-signatures.json` 由 86 → 126 条 + 2 份新参考

**新增命名空间**：`R-WIN-*` / `CHECK-WIN-*` / `SIG-WIN-*` / `SIG-SYSMON-*` / `VENDOR-*`

---

## v0.2.1 — 一键环境初始化

- `scripts/hvv_init.sh`：装 tshark + python3.11 + sshpass + expect（后两者是 remote 密码认证依赖）
- 触发词：`/hvv-defender init`

---

## v0.2 — traffic 模式（pcap 离线审计）

- 新脚本：`scripts/pcap_parser.py` + `scripts/traffic_anomaly.py`
- 新数据：`data/traffic-signatures.json` 初版 86 条
- 新引用：4 份 traffic 参考（`references/playbooks/traffic-audit.md` 等）
- 新命名空间：`R-TRAF-*` / `SIG-TRAF-*`

---

## v0.1 — MVP

- 三模式：monitor / audit / ir
- 6 类攻击 playbook（webshell / brute-force / sqli / rce / lateral / recon）
- 8 个核心脚本
- 内置 IOC 库：51 条（`data/ioc-builtin.json`）
- 仅 Linux 主机取证（`scripts/linux_quick_check.sh` + `references/ioc-checklist/linux-host-check.md` 14 章）

---

## 规划中（未落地）

- **v0.3-M2**：新增 phishing / ransomware / data-exfil / 0day-emerge / AD 攻击检测的 playbook 与规则集
- 接客户 SIEM / EDR API（当前离线优先，未来走脱敏审批）
- 接第三方威胁情报（VirusTotal / 微步 / ThreatBook）走脱敏审批
