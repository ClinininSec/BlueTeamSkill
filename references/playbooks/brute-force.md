# Playbook: 暴力破解处置剧本

> 适用模式：monitor / audit / ir
> 难度：★★☆☆☆
> 平均处置时间：20-60 分钟

## 1. 攻击概述

- **攻击者目的**：通过自动化尝试用户名/密码组合，获取目标系统的合法凭据；是「最便宜」的初始访问手段，也是 RDP/SSH/数据库类资产最常见的被打方式。
- **典型攻击链位置**：
  - MITRE ATT&CK 战术映射：`Credential Access (T1110 Brute Force)` 系列
    - `T1110.001` 密码猜测（Password Guessing）
    - `T1110.002` 密码破解（Password Cracking）
    - `T1110.003` 密码喷洒（Password Spraying，一个口令打多账号）
    - `T1110.004` 凭据填充（Credential Stuffing，撞库）
  - 多数发生在「外部边界资产」或「内部已立足后横向」两个阶段。
- **护网期间出现频次**：最高。值守期间外部 ssh / rdp / web 后台几乎是 24h 持续被打，绝大部分是机扫噪音，但**真正命中**的事件每场护网都会出现 1-2 起。
- **常见目标**：
  - SSH (22 / 自定义端口)
  - RDP (3389)
  - Web 后台（OA、CMS、Jenkins、Gitlab、Confluence、phpMyAdmin、Solr admin、Tomcat manager）
  - 数据库（MySQL 3306、Redis 6379、MSSQL 1433、PostgreSQL 5432、MongoDB 27017、ElasticSearch 9200）
  - 中间件管理界面（Weblogic、WebSphere、ActiveMQ）
  - VPN（IPSec/SSL-VPN 登录页）

## 2. 识别特征

> 只描述「识别这是暴破」的特征，不描述「如何执行暴破」。

### 2.1 静态特征

- **失败响应特征**：
  - HTTP 401 / 403 / 200（含「密码错误」文案）的高频请求
  - SSH 日志连续 `Failed password` / `Invalid user`
  - RDP Windows 安全日志 `EventID 4625`（登录失败）
  - 数据库错误日志连续 `Access denied for user` / `authentication failed`
- **请求特征**：
  - 同一 URI / 同一登录接口的请求计数显著高于业务正常水位
  - User-Agent 异常（`hydra` / `medusa` / `patator` / `ncrack` / 空 UA / Python-urllib）
  - 请求间隔过于规律（毫秒级一致，机器人特征）
- **字典特征**：
  - 用户名命中常见弱口令字典（admin / root / test / oracle / mysql / postgres / guest）
  - 密码字段含明显字典特征（如 base64 后是明文 password / 123456 / Admin@123）

### 2.2 行为特征

按攻击节奏，分三档：

| 类型 | 节奏 | 识别阈值 |
|---|---|---|
| 字典探测（高速） | 1-10 次/秒 | 5min 内 ≥ 20 次失败 → 候选；1h 内 ≥ 100 次 → 确认；24h 内 ≥ 500 次 → 高置信 |
| 凭据填充（撞库） | 较高速但用户名变化大 | 同 IP 短时间内尝试 ≥ 20 个不同用户名（每个用户名只试 1-3 次） |
| 慢速暴破（low-and-slow） | 1-10 次/分钟 / 小时 | 日级别同 IP / 同账户失败 ≥ 50 次但短窗口阈值不触发 → 需要 24h 累计统计 |

进一步分类：
- **针对单账户**：固定一个用户名，密码字典轮一遍 → 字典探测
- **针对单密码**：固定一个密码（如 `Admin@123`），用户名遍历 → 密码喷洒（绕过单账户锁定）
- **拿现成凭据库撞**：用户名 + 密码组合来自之前泄漏的库 → 凭据填充

### 2.3 上下文特征

- **多账户在短时间被相同 IP 尝试** → 喷洒
- **同账户从多个国家/地区 IP 被尝试** → 凭据填充
- **失败之后突然成功一次** → 最危险，立即升级
- **业务低峰时段（凌晨 3-6 点）出现登录尝试** → 加分项
- **来源 IP 是已知扫描器 / 云服务商出口 / Tor / 代理池** → 加分项

## 3. 日志查询模式（按日志类型）

### 3.1 auth.log / secure（SSH）

```bash
# 失败 ssh 登录的源 IP 统计（按次数倒序）
grep -E 'Failed password|Invalid user' /var/log/auth.log* \
  | awk '{for(i=1;i<=NF;i++) if($i=="from") print $(i+1)}' \
  | sort | uniq -c | sort -rn | head -20

# 同 IP 失败之后突然成功 —— 最关键的关联
# 1) 列出该 IP 所有失败时间
grep -E 'Failed password.*from 192\.168\.1\.xxx' /var/log/auth.log* | awk '{print $1,$2,$3}'
# 2) 列出该 IP 成功登录时间
grep -E 'Accepted (password|publickey).*from 192\.168\.1\.xxx' /var/log/auth.log*

# 高频用户名（攻击字典暴露）
grep -E 'Invalid user' /var/log/auth.log* | awk '{print $8}' | sort | uniq -c | sort -rn | head -30

# 公钥 vs 密码登录占比异常（突然出现 password 登录而平时是 key only）
grep -E 'Accepted' /var/log/auth.log* | awk '{print $6}' | sort | uniq -c
```

字段过滤逻辑：
- 单 IP 在 5min 内失败 ≥ 20 → P2
- 单 IP 在 1h 内失败 ≥ 100 → P1
- 失败窗口内出现一次 Accepted → P0（无论失败计数多少）

### 3.2 Windows EventID（RDP / 域账户）

- `4625` —— 登录失败，关注 `LogonType=10`（RDP）/ `LogonType=3`（网络登录）
- `4624` —— 登录成功，必须与 `4625` 关联看（同账户同 IP 失败后突然 4624 = 高危）
- `4740` —— 账户锁定（多次失败触发锁定 → 反向证明被打）
- `4771` —— Kerberos 预认证失败（域内喷洒典型特征）
- `4776` —— NTLM 认证审计（看 Source Workstation 是否异常）
- `4648` —— 显式凭据登录（常见于横向移动后的暴破阶段）

### 3.3 web access.log（Web 后台）

```bash
# 同 IP 对登录接口的高频 POST
awk '$7 ~ /\/(login|admin|signin|auth)/ && $6 ~ /POST/' access.log \
  | awk '{print $1}' | sort | uniq -c | sort -rn | head -20

# 响应 401/403/422 的高频（业务可能返回 200 但 body 含「密码错误」，需要后处理）
awk '$9 ~ /401|403|422/ {print $1, $7}' access.log | sort | uniq -c | sort -rn

# 工具 UA（hydra / patator / 自动化测试库默认 UA）
grep -iE 'hydra|patator|medusa|ncrack|python-requests|python-urllib|libwww-perl|go-http-client' access.log
```

### 3.4 数据库 / 中间件错误日志

- MySQL：`Access denied for user 'root'@'192.168.1.xxx'`
- Redis：`-WRONGPASS invalid username-password pair`（6.0+）/ 连接但未 auth 就执行命令的 INFO/CONFIG
- MSSQL：`Login failed for user`
- ElasticSearch：`401 unauthorized`
- Tomcat manager：`/manager/html` 401 高频

### 3.5 WAF / FW 告警关键字

- `brute force`, `brute-force`, `bruteforce`
- `password spray`, `credential stuffing`
- `excessive login failures`, `login anomaly`
- 工具名：`hydra`, `medusa`, `patator`, `ncrack`, `hashcat`（hashcat 在线场景少，但日志可能记录）

## 4. 误报排查清单

| # | 误报特征 | 如何排除 |
|---|---|---|
| 1 | 业务监控 / 健康检查脚本配置了错误的口令，持续探测失败 | 看源 IP 是否是已登记的监控节点；账号是否是监控专用账号；失败模式高度规律（同样的时间间隔） |
| 2 | 用户改了密码但客户端（手机邮箱客户端、保存的 SSH key）还在用旧密码反复重连 | 看源 IP 是否是该用户的固定办公 IP；账号只针对单一用户；失败次数有限（几十次而非几千次） |
| 3 | 应用本身的「忘记密码」 / 「找回密码」流程产生 4625 / Failed password 类似的日志（不同系统映射不同） | 看日志的 LogonType / EventID 子类型；找回流程通常不计入失败暴破阈值 |
| 4 | 合法的渗透测试 / 红蓝演练 / 安全扫描器 | 与团队对账日程；扫描器 IP 在白名单内；测试时段是已报备 |
| 5 | 业务 API 调用方密钥过期导致 401 高频（典型于 B2B 接口） | 看路径是 `/api/` 而非 `/login/`；UA 是业务 SDK 不是浏览器；客户端账户是 API 账户 |
| 6 | NAT 出口下多人共用同一公网 IP，同时输错密码 | 看用户名是否是多个完全不同的合法账号；失败模式不规律（每个人手输节奏不同） |
| 7 | CI/CD 流水线认证用错凭据导致短时间内大量失败 | 看 UA 是否是 git/docker/kubectl 类客户端；IP 是 CI 节点 |
| 8 | DDOS 工具误打到登录页（攻击者目标是带宽不是凭据） | 看 POST body 是否是有效的登录字段；如果是空 POST 或乱码就是 DDOS 而非暴破 |

**误报判定原则**：失败次数高但「无成功 + 来源能解释 + 业务侧已认领」时，标 `false_positive_prob >= 0.7`，进 P3 但保留 24h 复检。

## 5. 关联升级规则

### 5.1 严重性升级（P2 → P1 → P0）

- **P2 → P1**：
  - 单 IP 1h 内失败 ≥ 100 → P1
  - 同 IP 跨多个账户 / 多个服务（ssh + rdp + web）同时打 → P1
  - 攻击 IP 命中已知威胁情报 → P1
- **P1 → P0**：
  - 失败窗口后 24h 内出现一次 Accepted / 4624 / 登录成功 → **立即 P0**
  - 暴破成功后该账户出现任何「非业务」命令（whoami / id / cat /etc/passwd / 创建新用户） → **立即 P0**
  - 暴破成功后该账户在另一台主机上首次出现 → 横向起点，P0

### 5.2 模式升级

- **monitor → audit**：单 IP 高频暴破触发 P1，需要回看更长时间窗（72h）确认是不是 low-and-slow
- **audit → ir**：暴破成功（哪怕一次）确认后立即转 ir，重点排查该账户的所有后续操作

### 5.3 「首次有效登录」是核心信号

暴破最难判定的不是「失败」，而是「成功之后是不是合法用户在登录」。

判定原则：
- 该账户**历史登录 IP 段**与当前是否一致？
- 该账户**历史登录时段**与当前是否一致？（凌晨 3 点登录 root 极少是正常运维）
- 该账户登录后**第一条命令**是不是正常运维操作？（whoami / uname -a / id / cat /etc/shadow / wget 工具 → 高度可疑）
- 该账户登录后**是否立即修改密码 / 加 authorized_keys / 加 sudoers** → 持久化典型动作

## 6. 止血动作（containment）

### 6.1 网络层

| 动作 | 操作要点 | 副作用 | 回退路径 |
|---|---|---|---|
| 边界封 IP | iptables / 安全组拒绝源 IP（先 /32 后 /24，不要一上来 /16） | NAT 出口共享 IP 时误伤 | 24h 后观察，无误报固化 |
| 改 SSH 端口（治标） | 改 `Port` 配置 + 重启 sshd | 客户端连接配置全部要改 | 不建议作为主防御，仅作降噪手段 |
| 关 RDP 公网暴露 | 改为 VPN 接入 / 跳板机 | 需要前置 VPN 部署 | 紧急时先用安全组限制源 IP |

### 6.2 主机层

| 动作 | 操作要点 | 副作用 | 回退路径 |
|---|---|---|---|
| 启用 fail2ban | 配置 `[sshd]` jail，bantime 30min 起 | 误伤同 NAT 的正常用户 | bantime 期满自动解封 |
| sshd 改 key-only | `PasswordAuthentication no` + `PubkeyAuthentication yes` | 需要先给所有合法用户分发公钥 | 保留口令登录的备用账户（仅限本地登录） |
| 启用 PAM 锁定 | `pam_tally2` / `pam_faillock`，N 次失败锁 M 分钟 | 误伤忘密码的正常用户 | 锁定期满或运维手动解锁 |
| Windows 加锁定策略 | 组策略：`Account Lockout Threshold = 5`、`Lockout Duration = 30min` | 内部用户失误锁定增加 helpdesk 工作 | 组策略可立即回滚 |

### 6.3 应用层

| 动作 | 操作要点 | 副作用 | 回退路径 |
|---|---|---|---|
| 登录页加验证码 | 图片码 / 滑块 / reCAPTCHA | 影响用户体验 | 仅暴破期间启用，过后可撤 |
| 应用层限速 | nginx limit_req_zone 限制 `/login` 接口的 RPS | 正常用户高峰期可能触发限速 | 调整阈值 |
| 多因素认证（MFA） | 短信 / TOTP / 硬件 token | 增加用户负担 | 不易回退（不应该回退） |
| 临时下线管理后台 | 把 `/admin` location 设为内部访问 | 管理员需走 VPN | 等加固完成后回滚 |

### 6.4 账号层

| 动作 | 操作要点 | 副作用 | 回退路径 |
|---|---|---|---|
| 强制重置被打账户口令 | 通知用户并强制下次登录修改 | 短期影响该账户 | 标准流程 |
| 锁定可疑账户 | `usermod -L` / `passwd -l` / AD 账户禁用 | 该账户暂不可用 | `usermod -U` 解锁 |
| 全面口令轮换 | 范围根据失陷面：从单账户 → 整个 server group → 整个 zone | 工作量大，需要分阶段执行 | 标准流程 |
| 检查并清理 `authorized_keys` | 比对基线，删除非授权 key | 误删合法 key 需要重新分发 | 保留旧 keys 副本 |

## 7. 根除与恢复（eradication & recovery）

### 7.1 根除步骤

1. **确认暴破是否成功**（最优先）：
   - 时间窗内任何 Accepted / 4624 都要逐条审计
   - 用 last / lastb / utmpdump 看登录历史
   - 用 sshd 的 LogLevel VERBOSE 拿到登录用的公钥指纹（如有）
2. **若成功**：
   - 取该账户登录后所有 bash_history / 进程树
   - 排查持久化（authorized_keys / cron / systemd / sudoers）
   - 排查横向（该账户对其他主机的连接）
   - 进入 ir 模式跑完整链
3. **若仅失败**：
   - 封 IP + 启用 fail2ban + 加锁定策略
   - 全员强制改弱口令账户（特别是字典命中的 admin/test/root）
   - 关闭不必要的暴露面（公网 RDP / 数据库直连）

### 7.2 恢复步骤

- 失败但已加固 → 24h 监测无新增即可视为恢复
- 成功但根除完整 → 走 ir 流程恢复
- 不确定是否成功 → 假设成功，按 ir 流程处理

### 7.3 验证点

1. **认证日志验证**：加固后 24h 内同 IP / 同账户的失败计数明显下降到背景水位
2. **配置验证**：sshd_config 中 `PasswordAuthentication no`（如适用）、PAM 锁定生效（人工尝试 N+1 次被锁）
3. **账户验证**：所有曾被暴破命中的账户密码已重置，弱口令账户已清理
4. **入口验证**：fail2ban 状态 `sudo fail2ban-client status sshd` 显示有 ban 列表运行正常
5. **暴露面验证**：原本公网暴露的管理端口已下线或加 VPN

## 8. IOC 提取模板

```json
[
  {
    "type": "ip",
    "value": "192.168.1.xxx",
    "confidence": "high",
    "first_seen": "2026-06-30T03:01:22+08:00",
    "source": "auth.log:line-8821",
    "tag": "brute-force,ssh,attacker-ip",
    "description": "1h 内 ssh 失败 412 次，命中 root/admin/test 等弱口令字典"
  },
  {
    "type": "ua",
    "value": "Python-urllib/3.x",
    "confidence": "medium",
    "first_seen": "2026-06-30T03:05:11+08:00",
    "source": "nginx-access.log:line-9210",
    "tag": "tool:hydra-like,brute-force"
  },
  {
    "type": "tool",
    "value": "hydra",
    "confidence": "medium",
    "first_seen": "2026-06-30T03:05:11+08:00",
    "source": "rule:PLB-BF-005",
    "tag": "brute-force-tool"
  }
]
```

提取重点：
- 攻击源 IP（必含）
- 攻击工具指纹（UA / 行为模式）
- 被打中的账户名（高置信，用于全网横向排查同名账户）
- 时间窗（first_seen / last_seen）
- 关联资产（被打的目标主机 IP / 域名）

---

## rule_id 命名约定

- 前缀：`PLB-BF-NNN`（PlayBook-BruteForce）

### 已建议规则一览

| rule_id | 规则名 | 触发条件 |
|---|---|---|
| PLB-BF-001 | SSH 5min 失败阈值 | 同源 IP 5min 内 SSH `Failed password`/`Invalid user` ≥ 20 |
| PLB-BF-002 | SSH 1h 失败阈值 | 同源 IP 1h 内 SSH 失败 ≥ 100 |
| PLB-BF-003 | SSH 24h 累计失败 | 同源 IP 24h 内 SSH 失败 ≥ 500（low-and-slow） |
| PLB-BF-004 | RDP 失败阈值 | 同源 IP 1h 内 EventID 4625 ≥ 50 |
| PLB-BF-005 | 暴破工具 UA 指纹 | UA 命中 hydra/medusa/patator/ncrack 或 Python-* 等 |
| PLB-BF-006 | 密码喷洒（用户名横扫） | 同源 IP 短时间内尝试 ≥ 20 个不同用户名，每个 ≤ 3 次 |
| PLB-BF-007 | 凭据填充（多 IP 多用户） | 跨多 IP 但用户名/密码组合命中已知泄漏库 |
| PLB-BF-008 | 暴破成功告警 | 失败窗口（≥ 50 次）后出现同 IP/同账户 Accepted/4624 |
| PLB-BF-009 | 弱口令字典命中 | 失败用户名命中 root/admin/test/oracle/mysql/postgres 等 |
| PLB-BF-010 | Web 后台 login 接口高频 POST | `/login`/`/admin/login` 同 IP 1h 内 POST ≥ 100，且 401/403 占比 > 70% |
| PLB-BF-011 | 数据库暴破 | MySQL/Redis/MSSQL 错误日志连续 auth failed ≥ 30 |
| PLB-BF-012 | 中间件管理面暴破 | tomcat-manager/jenkins/gitlab/solr admin 路径 401/403 高频 |
| PLB-BF-013 | 异常时段登录 | 业务低峰时段（凌晨 0-6 点）该账户出现首次登录 |
| PLB-BF-014 | 异常地理位置登录 | 同账户从地理上不可能的两个位置短时间登录（不可能旅行） |
| PLB-BF-015 | 暴破后首次有效登录 | 暴破窗口后 24h 内该账户成功登录 + 立即执行非业务命令 |
