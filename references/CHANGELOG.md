# hvv-defender CHANGELOG

> 各版本历史与命名空间演化。SKILL.md 只保留"当前版本"标记，历史细节看这里。

---

## v0.4-M0（当前）— remote 模式：授权 SSH 分析

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

- `scripts/hvv_init.sh`：装 tshark + python3 + sshpass + expect（后两者是 remote 密码认证依赖）
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
