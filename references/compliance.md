# 合规与红线（Compliance）

> 本文件展开 SKILL.md 中「七条红线」的细节与脱敏规则，所有模式（monitor / audit / ir / traffic / remote）通用。
> 红线 4 从"完全禁止 SSH 远连"改为"四要素约束下允许"；新增红线 7（白名单强制 + Tier 3 默认关）。

---

## 一、七条操作红线

红线编号与 SKILL.md 一致。每条说明：**为什么 / 违反后影响 / 例外情形**。

### 红线 1：不连接客户 SIEM / EDR API

- **为什么**：定位「乙方驻场 + 离线作业」，对客户主网无写入授权；接 API 会触发审计、可能被视为擅自联网，违反驻场规约。
- **影响**：轻则被甲方安全运维 escalate；重则被认为越权访问数据，触发安全合规事件。
- **例外**：暂不支持。

### 红线 2：不调第三方威胁情报 API

- **为什么**：调用 VirusTotal / 微步 / ThreatBook 等会将客户 IP / hash / 域名外发到第三方，等同数据出境。
- **影响**：客户敏感资产指纹流出，可能违反《数据安全法》《个人信息保护法》。
- **例外**：v0.4+ 计划接入需脱敏审批。当前版本仅用本地 `data/ioc-builtin.json`，**不允许**任何 outbound 调用，包括「测试一下网络」性质的 ping。

### 红线 3：不输出可复现 PoC payload

- **为什么**：Skill 在乙方驻场环境运行，输出物（日报 / audit 异常清单 / incident-report）可能进入甲方文档库；包含 PoC 等于把武器留在客户站点。
- **影响**：被反向利用（内部红队 / 外部攻击者读取报告复现攻击）。
- **例外**：无例外。识别特征写到「触发字段 + 关键词」层级即可，可以写"URL 包含 `${jndi:ldap`"，不可以写完整 Log4Shell payload。

### 红线 4：不擅自远连；远连必须四要素达标

- **为什么**：Skill 定位为「离线副驾驶」，支持 remote 模式（SSH 远程分析）；但远连是甲方合规敏感动作，必须四要素齐全才能启动。
- **四要素**：
  a) **客户书面授权**：工单 / 邮件 / 群消息留痕；`ssh_probe.py --authorized-by` 强制必填
  b) **命令来自白名单**：所有远程命令必须匹配 `data/remote-command-whitelist.json` 的 cmd_id；Tier 3 需二次开关
  c) **每命令记入审计**：`~/.hvv-defender/audit.jsonl` 追加式，每次调用一条
  d) **会话全程录制**：`ssh_probe.py` 内置 tee-fork 录制到 `~/.hvv-defender/sessions/<host>-<ts>.log`；交互式会话用 `session_recorder.sh`
- **未满足即视为违规**，Skill 在 SSH 层拒绝执行（退出码 2 或 3）
- **例外**：
  a) 堡垒机（JumpServer / 齐治 / Coco）场景：Skill **不接堡垒机 API**，只生成命令清单让驻场人员在堡垒机 web 端粘贴执行（H-I-L 降级）
  b) 客户明确禁止乙方任何 outbound 时，全程走 ir mode 的离线采集包流程
- **审计留存**：审计日志与 session log 演习结束 + 30 天销毁（`shred -u`）
- **详细流程**：见 `references/modes/remote.md`；命令白名单见 `references/remote-command-whitelist.md`

### 红线 5：不未脱敏直接回显客户数据

- **为什么**：会话窗口、日志副本、报告草稿都可能被截图传播；任何明文敏感数据都是泄露风险。
- **影响**：客户名、内部 IP、用户名、文件路径出现在公开渠道，触发数据安全事件。
- **例外**：用户明确加 `--no-desensitize` 时可临时关闭，须满足：(1) 用户书面说明用途；(2) 本次操作记入 Skill 审计日志；(3) 关闭仅在单条命令范围内有效，不跨会话。

### 红线 6：不擅自删除 / 修改客户主机文件

- **为什么**：Skill 是「建议者」非「操作者」。即使确定 webshell，删除动作也应由客户执行（保留取证证据、避免误删生产文件）。
- **影响**：破坏取证现场；误删导致业务受损；触发问责。
- **例外**：无例外。所有「删除 / 移动 / 改名」动作以「建议路径 + 操作命令」形式给客户，由客户决策执行。
- **命令族禁令**（Skill 生成的任何命令拼接前必须过一遍自检，命中即拒绝）：
  - **删除类**：`rm` / `rmdir` / `unlink` / `shred`；尤其针对高危目录 `/` / `/etc` / `/root` / `/home` / `/var` / `/usr` / `/boot` / `/lib` / `/lib64` / `/opt` / `/data` / `/srv` / `/mnt` / `/media` 及其子路径；Windows 侧 `C:\` / `C:\Windows` / `C:\Users` / `C:\ProgramData` 系统关键目录
  - **移动 / 覆盖类**：`mv` / `rename` 覆盖系统文件或核心配置
  - **权限篡改**：`chmod` / `chown` / `chgrp` 修改 `/etc/passwd` / `/etc/shadow` / `/etc/sudoers` / `authorized_keys` 等系统关键文件
  - **账户系统**：`useradd` / `userdel` / `usermod` / `passwd`（Tier 3 明确白名单的 `passwd -l` 锁账户除外）
  - **主机控制**：`reboot` / `shutdown` / `poweroff` / `halt` / `init 0` / `init 6`
  - **磁盘写入**：`dd` / `mkfs.*` / `fdisk` / `parted` / `wipefs` / `blkdiscard`
  - **数据库高危**：`DROP DATABASE/TABLE` / `TRUNCATE` / `DELETE` 未带 `WHERE` / 未加 `LIMIT`
  - **防火墙全清**：`iptables -F` / `nft flush ruleset` / 修改默认策略为 DROP
- **横移禁令**：即便 remote 已在客户机取得会话，也不允许从客户机再 SSH / SCP / SFTP / nc / curl / wget 到第二跳，防止 Skill 变成攻击链跳板

### 红线 7：未授权命令不入白名单，Tier 3 默认关

- **为什么**：白名单是 remote 模式的合规护栏；一旦允许"临时加命令"，护栏形同虚设。
- **约束**：
  a) 所有 cmd_id 必须先落到 `data/remote-command-whitelist.json` 且经过一次冒烟验证
  b) Tier 3 处置类（kill / block / disable / stop 等）**默认关闭**；需 `--allow-mutating` + 客户显式书面授权 + 每次二次口头确认
  c) 永远禁止入白名单的命令族：`rm` / `mv` / `chmod` / `chown` / `useradd` / `userdel` / `reboot` / `shutdown` / `nc` / `curl` / `wget` / `ssh` / `scp` / `sftp` / `dd` / `mkfs` / 通用 `bash -c '...'`（防 pivot 与不可逆操作）
- **影响**：绕过白名单 → 变成攻击工具；Tier 3 误触发 → 生产业务中断
- **例外**：无例外。Tier 3 需要新增 cmd_id 时，走"提 PR → e2e 冒烟 → 双人 review"的正规扩展流程（见 `references/remote-command-whitelist.md` §七）

---

## 二、脱敏规则细则

所有面向用户的输出默认先过 `scripts/desensitize.py`。

### 2.1 IP 地址

| 类型 | 脱敏前 | 脱敏后 | 备注 |
|---|---|---|---|
| 私网 IPv4 | `192.168.1.100` | `192.168.1.xxx` | 保留 /24 网段便于关联 |
| 公网 IPv4（攻击者源 IP） | `203.0.113.50` | `203.0.113.50` | 不脱敏，IOC 价值高 |
| 公网 IPv4（客户出口 IP） | `198.51.100.10` | `198.51.100.xxx` | 客户出口属敏感资产 |
| IPv6 | `fe80::a1b2:c3d4:e5f6:1234` | `fe80::a1b2:xxxx:xxxx:xxxx` | 后 64 位隐藏 |

**公 / 私网区分**：用户启动时通过 `--internal-cidr` 声明私网段；未声明的默认按 RFC1918（10/8、172.16/12、192.168/16）+ 100.64/10 处理。

### 2.2 用户名

| 长度 | 脱敏前 | 脱敏后 | 备注 |
|---|---|---|---|
| ≥ 4 | `zhangsan` | `z*******` | 首字符 + 长度 |
| 3 | `abc` | `a**` | 首字符 + 长度 |
| ≤ 2 | `ab` / `a` | `**` / `*` | 全部隐藏，长度信息也丢弃避免猜出 |
| 含特殊字符 | `svc-admin` | `s********` | 长度按字符总数计，特殊字符不保留位置 |
| 邮箱格式 | `user@corp.com` | `u***@<internal>` | 本地段 + 域名分别脱敏 |

### 2.3 域名

| 类型 | 识别规则 | 脱敏后 |
|---|---|---|
| 内部域名 | 命中 `--internal-domain` 通配（如 `*.corp.example.com`） | `<internal>` |
| 客户外部域名 | 命中 `--customer-domain` 通配 | `<customer>` |
| 公网攻击者 / C2 域名 | 不命中以上两类，且在 IOC 或异常列表 | 不脱敏（IOC 价值高） |
| 公开服务（github.com 等） | 命中白名单 | 不脱敏 |

### 2.4 文件路径

| 路径前缀 | 脱敏前 | 脱敏后 | 备注 |
|---|---|---|---|
| `/data/` | `/data/app/log/` | `/data/<app>/log/` | 第二段视为应用名脱敏 |
| `/home/<user>/` | `/home/zhangsan/.ssh/` | `/home/z*******/.ssh/` | 用户名按 2.2 处理 |
| `/opt/<customer>/` | `/opt/acme-bank/svc/` | `/opt/<customer>/svc/` | 客户 / 项目代号脱敏 |
| `/var/www/` | `/var/www/html/` | `/var/www/html/` | 通用路径不脱敏 |
| `C:\Users\zhangsan\` | `C:\Users\zhangsan\` | `C:\Users\z*******\` | Windows 同 Linux 规则 |

**默认敏感目录**（无需匹配即按敏感处理）：`/data/`、`/home/`、`/opt/<customer>/`、`/var/lib/<app>/`、Windows `C:\Users\`、`C:\ProgramData\`。

### 2.5 Hash 值

- **MD5 / SHA1 / SHA256**：不脱敏（已不可逆，本身就是脱敏后的指纹）
- **Hash 出处**：如"在 `/data/app/upload/x.jsp` 发现 MD5: abc..."，路径按 2.4 脱敏、hash 保留

### 2.6 其他敏感数据

- **手机号 / 身份证 / 银行卡**：全部隐藏（`********`），不保留任何位
- **API key / token / 密钥**：完全隐藏并标记 `[CREDENTIAL REDACTED]`
- **业务字段（订单号 / 交易号）**：保留前 4 后 4，中间 `****`
- **客户名 / 项目代号**：全程使用 `<customer>` / `<project>`

---

## 三、数据保留与销毁

| 类别 | 保留位置 | 保留时长 | 销毁方式 |
|---|---|---|---|
| 原始日志副本 | 用户本机加密磁盘 | 演习结束 + 7 天 | `shred -u` 或 BitLocker 卷销毁 |
| 采集压缩包 | 同上 | 同上 | 同上 |
| Skill 中间产物（`/tmp/hvv-*`） | 临时目录 | 单次会话内 | 会话结束 `rm -rf` |
| 最终报告（脱敏后） | 客户文档库 | 按客户合同 | 由客户决定 |
| Skill 操作审计日志 | 用户本机 | 演习结束 + 30 天 | `shred -u` |

**驻场结束流程**：(1) 与甲方对齐保留期；(2) 到期前自查；(3) 安全销毁；(4) 出具销毁声明邮件给甲方。

---

## 四、客户授权要点

下列动作必须有客户书面授权（邮件 / 工单 / 群消息留痕均可），授权未到位禁止执行：

| 动作 | 授权方 | 留痕证据 |
|---|---|---|
| 在客户主机本地执行 `linux_quick_check.sh` 等采集脚本 | 主机 owner（运维 / 业务负责人） | 工单号 |
| 调取生产 nginx / auth 日志副本 | 系统 owner | 邮件审批 |
| 调取 SIEM 历史告警导出 | SOC 负责人 | 邮件审批 |
| 关闭脱敏（`--no-desensitize`）查看完整数据 | 现场总指挥 | 群消息记录 |
| 把分析报告外发到乙方公司邮箱备份 | 客户安全合规 | 邮件审批 |
| 把 IOC 共享到外部情报平台 | 客户安全合规 + 法务 | 邮件审批 |

未授权时 Skill 应主动提示用户先取得授权，并拒绝执行直到用户确认到位。

---

## 五、Skill 自身审计日志

本 Skill 在用户本机记录以下操作日志（建议路径：`~/.hvv-defender/audit.log`，JSONL 格式）：

```jsonl
{"ts":"2026-06-30T09:15:23Z","mode":"monitor","action":"parse_alerts","input_file":"alerts-20260630.json","input_lines":2031}
{"ts":"2026-06-30T09:16:01Z","mode":"monitor","action":"desensitize_disabled","scope":"single_command","reason":"用户口头确认现场总指挥批准"}
{"ts":"2026-06-30T09:25:44Z","mode":"audit","action":"ioc_match","ruleset":"builtin-v0.1","matches":14}
```

**审计字段**：`ts` / `mode` / `action` / 必要参数 / 结果概要。**禁止记录客户原始数据**，只记录元数据。

---

## 六、违规处置

驻场人员发现自己或同事违反上述红线时：

1. **立即停止当前操作**，不要试图删除痕迹（删除本身也是违规）
2. **告知现场带队负责人**
3. **配合客户安全合规取证**
4. 如已产生客户数据外发：通报乙方安全合规 + 客户安全合规，启动数据泄露应急流程
5. **复盘**：在 Skill 审计日志中标注事件，演习后做 post-mortem 改进 Skill 提示词

---

## 相关引用

- 脱敏脚本：`scripts/desensitize.py`
- 分级 SLA：`references/grading.md`
- 术语对照：`references/glossary.md`
