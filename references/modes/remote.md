# Remote 模式 —— SSH 远程分析详细流程

> 应用场景：授权前提下对客户主机远程执行只读采集/审计命令，或（Tier 3 + 二次授权后）远程处置。
> 关联：分级 `../grading.md`、脱敏与红线 `../compliance.md`、白名单知识库 `../remote-command-whitelist.md`、审计字段 `../log-fields/audit-session.md`。

---

## 一、何时进入 remote

用户措辞匹配以下任一即进入本模式：

- 名词类：「远程」「SSH」「跳板机」「堡垒机」「远连」「远程采集」「远程处置」「跨主机」
- 动词类：「远程跑一下」「SSH 上去看看」「帮我远连到 xxx」「拉一下 xxx 主机的日志」「远程处置一下」
- 显式调用：`/hvv-defender remote ...`
- 组合线索：用户已提供 `user@host` / SSH 密钥路径 / 跳板机 IP / 工单号

不进入 remote 的反例：
- 用户已经手工登录客户主机并把日志文件放到本地 → 直接走 audit
- 用户已确认失陷、需要本机快速排查（客户机上跑脚本回传结果）→ 走 ir
- 未提供工单号/邮件授权时，主会话应主动回绝并要求用户先补授权，不进入 remote

---

## 二、入场前对齐（强制 5 问）

**未对齐 5 问不允许启动 `ssh_probe.py` / `remote_collect.py`**。任何一问回答不达标，主会话必须拒绝远连并给出补齐建议。

1. **客户书面授权是否到位？**（工单号 / 邮件 ID / 群消息截图，缺一不可）
   - 授权文书需明确"允许对 host X 执行只读采集"；处置类需额外单独授权
   - `ssh_probe.py --authorized-by <ticket>` 必填字段，缺失即退出码 2

2. **目标主机的 SSH 连通性？**
   - 能否 ping 通、端口是否开、上一次成功登录的时刻
   - 如目标不通 → 主会话建议改走驻场人员本机采集 + `scp` 回传，不勉强直连

3. **是否走跳板机？**
   - 跳板机地址 / 端口 / 密钥；若是**堡垒机**（JumpServer / 齐治 / Coco / 麒麟堡垒等）→ 降级为 H-I-L：Skill 仅生成命令清单，让驻场人员在堡垒机 web 端粘贴执行
   - 明确跳板机是否也需要 `authorized-by`（多数客户要求）

4. **使用哪个 SSH 密钥？**
   - Ed25519 优先；RSA ≥ 3072 位
   - 密钥文件权限必须 0600，否则 OpenSSH 会拒绝加载
   - 密钥是否已在目标机 `authorized_keys`（如未，用户必须先自行部署，Skill 不替用户 `ssh-copy-id`）

5. **本次会话是否需要开 Tier 3？**
   - 默认关闭（`--allow-mutating=false`）
   - 若需要，用户必须：a) 出示客户"允许处置"的书面授权，b) 完成一次二次口头确认（例如驻场群内 `@现场总指挥 已确认 kill PID 12345 副作用`），c) 二次确认内容写入 audit.jsonl 的 `authorized_by` 字段

未通过 5 问 → 主会话回复"入场对齐未完成，无法启动 remote，请补齐 [具体项]"，明确回绝。

---

## 三、SSH 环境准备

### 3.1 密钥要求

- 算法：Ed25519 > ECDSA P-256 > RSA ≥ 3072；不允许 DSA / RSA < 2048
- 权限：`~/.ssh/id_ed25519` 必须 `0600`；父目录 `0700`
- 密钥用途分离：驻场专用密钥不与个人开发/生产运维密钥共用
- 密钥过期：驻场结束当天自 `authorized_keys` 移除公钥（由客户运维执行）

### 3.2 known_hosts 首次连接策略

- 默认 `StrictHostKeyChecking=accept-new`：首次自动接受并记录 fingerprint，后续变更立即拒绝
- **不允许** `StrictHostKeyChecking=no`（会静默接受任意 MITM）
- `ssh_probe.py` 内置在配置里，用户无需手改 `~/.ssh/config`

### 3.3 跳板机场景（`--proxy-jump`）

```bash
python3.11 scripts/ssh_probe.py \
  --target ops@svc-01 \
  --proxy-jump bastion@jump.corp.example.com \
  --cmd-id list-processes \
  --authorized-by "ticket-#20260701-042"
```

底层等价于 OpenSSH `-J bastion@jump.corp.example.com`，中间节点也走 known_hosts 校验。

### 3.4 会话超时

- `ConnectTimeout=8`（连接握手 8 秒不通即失败，避免长时间阻塞）
- `ServerAliveInterval=30 / ServerAliveCountMax=3`（30 秒 keepalive，3 次无响应断连）
- `ssh_probe.py` 单命令硬超时：Tier 1 默认 60s，Tier 2 默认 300s，Tier 3 默认 30s（处置类快速止血）
- 超时后自动记入 audit.jsonl（`exit_code=124`）

### 3.5 客户堡垒机场景（H-I-L 降级）

**Skill 不接堡垒机 API**（合规红线 4：不擅自远连；堡垒机 API 属于额外的甲方审计敏感面）。降级流程：

1. 主会话仍完成 5 问对齐
2. `ssh_probe.py --render-only` 只生成命令清单（含 cmd_id / 展开后的命令 / 预期输出行为 / Tier）
3. 用户把清单**逐条**粘到堡垒机 web 端执行
4. 用户把 stdout 回贴给主会话
5. 主会话跑 `desensitize.py` 处理 stdout，然后进入 audit / ir
6. audit.jsonl 手工补记（用户口头描述哪条被执行、结果）

**H-I-L 场景下 Tier 3 一律不允许由 Skill 生成**——处置命令由客户/驻场负责人在堡垒机上手工输入，Skill 不留下"处置指令模板"作为攻击工具。

---

## 四、6 步详细流程

### 步骤 1：授权对齐（5 问）

见 §二。主会话把 5 问与用户答案落到会话头部，供后续步骤引用；如授权工单变更需重新对齐。

### 步骤 2：`remote_collect.py --dry-run` 预演

**为什么要预演**：让用户在执行前看到"要发出的命令 / 涉及的主机 / 涉及的 Tier"清单，避免误执行。

```bash
python3.11 scripts/remote_collect.py \
  --target ops@svc-01 \
  --profile linux-basic \
  --authorized-by "ticket-#20260701-042" \
  --dry-run
```

`--dry-run` 输出示例：
```
Would execute on ops@svc-01:
  [T1] list-processes  →  ps -eo pid,ppid,user,stat,pcpu,pmem,etime,cmd --sort=-pcpu | head -50
  [T1] list-listen     →  ss -tnlp
  [T1] recent-logins   →  last -F -i -n 20
  ...
Total: 12 commands (T1=12 / T2=0 / T3=0)
Session log: ~/.hvv-defender/sessions/svc-01-20260701T143012Z.log
Audit log: ~/.hvv-defender/audit.jsonl (12 entries will be appended)
Proceed? [y/N]
```

### 步骤 3：正式执行 `ssh_probe.py` 或 `remote_collect.py`

- `ssh_probe.py`：单命令执行（适合 targeted 排查，如"看一下 PID 1234 是哪个进程"）
- `remote_collect.py`：批量执行采集 profile（适合"linux-basic 全套跑一遍"）

```bash
# 单命令
python3.11 scripts/ssh_probe.py \
  --target ops@svc-01 \
  --cmd-id list-processes \
  --authorized-by "ticket-#20260701-042"

# 批量
python3.11 scripts/remote_collect.py \
  --target ops@svc-01 \
  --profile linux-basic \
  --authorized-by "ticket-#20260701-042" \
  --output ~/.hvv-defender/collects/svc-01-20260701.tar.gz
```

主会话在此步骤**不解析 stdout**，只落地文件。分析在后续步骤或转 ir。

### 步骤 4：结果落地三份产物

每次执行必然产生：

1. **stdout / stderr**：命令原始输出，写入 `~/.hvv-defender/sessions/<host>-<ts>/stdout-<cmd_id>.txt`
2. **session log**：完整会话录制（tee-fork，含所有交互）`~/.hvv-defender/sessions/<host>-<ts>.log`
3. **audit.jsonl**：追加一行结构化审计（字段见 `../log-fields/audit-session.md`）

### 步骤 5：主会话跑 `desensitize.py` 处理 stdout

远程拿回的 stdout 内含真实内网 IP / hostname / 用户名，直接送入下游前必须脱敏：

```bash
python3.11 scripts/desensitize.py \
  --input ~/.hvv-defender/sessions/svc-01-20260701T143012Z/stdout-list-processes.txt \
  --internal-cidr "10.0.0.0/8,192.168.0.0/16" \
  --internal-domain "*.corp.example.com" \
  --mode strict \
  --output /tmp/hvv-remote-desens.txt
```

audit.jsonl 本地保留原始版本；对外交付（如给客户看的报告、给乙方乙方公司复盘）时对 audit.jsonl 也过一次 `desensitize.py --mode strict`。

### 步骤 6：结果送入 ir 或 audit 分析

- 拿回单个日志文件（如 `/var/log/nginx/access.log` 的某段）→ 进 audit
- 拿回完整采集包（tar.gz，含进程/网络/文件/日志等 20+ 个产物）→ 进 ir
- 主会话在 §十 明确升级链的判定逻辑

---

## 五、命令白名单速览（3 tier）

| Tier | 语义 | 默认状态 | 典型 cmd_id |
|---|---|---|---|
| T1 | 只读单命令 | 默认开 | `list-processes` / `list-listen` / `recent-logins` / `check-crontab` |
| T2 | 采集脚本（多命令打包） | 默认开，全部走审计 | `run-linux-collect` / `run-windows-collect` / `fetch-nginx-log` |
| T3 | 处置类（会改变主机状态） | **默认关**，需 `--allow-mutating` + 客户书面授权 + 二次口头确认 | `kill-pid` / `block-ip-iptables` / `disable-user` / `stop-service` |

详细命令清单、参数模板、风险评估、常见误报 → `../remote-command-whitelist.md`。

---

## 六、审计日志字段（audit.jsonl）

每次调用 `ssh_probe.py` / `remote_collect.py` 追加一行 JSONL：

```jsonl
{"ts":"2026-07-01T14:30:12Z","action":"ssh_probe","target":"ops@svc-01","proxy_jump":"bastion@jump.corp.example.com","cmd_id":"list-processes","cmd_expanded":"ps -eo pid,ppid,user,stat,pcpu,pmem,etime,cmd --sort=-pcpu | head -50","tier":1,"authorized_by":"ticket-#20260701-042","allow_mutating":false,"exit_code":0,"stdout_bytes":4821,"stderr_bytes":0,"duration_ms":842,"desensitized":false,"session_log":"~/.hvv-defender/sessions/svc-01-20260701T143012Z.log","dry_run":false}
```

字段完整定义见 `../log-fields/audit-session.md`。

---

## 七、Tier 3 处置类的二次确认流程

### 7.1 何时会用到 Tier 3

- 已经通过 monitor / audit / ir 定性为真实入侵（P0 / P1，false_positive_prob ≤ 0.1）
- 客户明确要求乙方现场协助止血（工单类型 = "应急处置"）
- 处置窗口内客户运维不能立即接手（例如凌晨值守班次）

**只是"怀疑"不允许开 Tier 3**——怀疑先走 audit / ir 深挖到定性，再谈处置。

### 7.2 二次授权话术模板

驻场群里的口头确认（截图或消息 ID 需入 audit）：

```
@现场总指挥 @客户安全接口人
本次将对主机 svc-01（内网 IP <redacted>）执行处置动作：
  cmd_id: kill-pid
  参数: PID=12345 (进程 java, cwd=/opt/<customer>/svc)
  副作用: 中断该 Java 进程；无自动恢复；如需恢复请重启 svc 服务
  依据: 该进程 ppid=1 且监听 4444，符合 R-IR-BEACON-001；证据见 ir-report-20260701.md
  预计执行时间: 2026-07-01 14:35 CST
  已具备: 工单 #20260701-042 授权处置 + 现场总指挥语音确认
请回复"确认执行"以继续。
```

回复"确认执行"后 3 分钟内执行有效；超时需重新确认。

### 7.3 处置动作与副作用清单

必须在执行前对齐（详细逐条见 `../remote-command-whitelist.md` §四）：

| cmd_id | 副作用 | 回滚成本 | 客户话术要点 |
|---|---|---|---|
| `kill-pid` | 目标进程立即退出 | 需重启服务 | "该进程 PID 的父服务、是否被 systemd 管理" |
| `block-ip-iptables` | 该 IP 到主机所有连接被拒 | `iptables -D` 可回滚 | "是否影响合法流量、是否有 NAT 出口" |
| `disable-user` | 账户被 `usermod -L` | `usermod -U` 可回滚 | "是否是系统账户、是否被计划任务使用" |
| `stop-service` | 服务停止 | `systemctl start` 可回滚 | "该服务是否有健康检查、是否有依赖服务" |
| `revoke-ssh-key` | authorized_keys 中该条被注释 | 手工恢复 | "该密钥属于谁、是否是合法运维用" |

### 7.4 处置后验证

处置完成后**必须**再跑一次只读 T1 命令验证是否达到预期：

- `kill-pid` 后跑 `list-processes | grep <pid>` 确认进程不存在
- `block-ip-iptables` 后跑 `iptables -L -n | grep <ip>` 确认规则存在
- `disable-user` 后跑 `passwd -S <user>` 应显示 `L`（locked）
- `stop-service` 后跑 `systemctl status <svc>` 应显示 `inactive`

验证结果同样落 audit.jsonl（`action=post_action_verify`）。

---

## 八、常见误报模式（vendor-specific）

远程命令在不同发行版 / 版本上会有兼容性问题，主会话看到以下信号时不要直接报"命令失败=攻击"：

| 命令 / cmd_id | 症状 | 根因 | 处置 |
|---|---|---|---|
| `ss -tnlp` | 部分列缺失 / `-p` 拿不到进程名 | CentOS 7 上非 root 或 iproute2 老版 | 用 `netstat -tnlp` 兜底，或提示用户加 sudo |
| `journalctl -u sshd` | `-- No entries --` 但 sshd 明显在跑 | 系统无 journald（Alpine / 老 CentOS 6） | 退到 `/var/log/messages` 或 `/var/log/secure` |
| `ps -eo ... --sort=-pcpu` | `--sort` 报错 | busybox ps（容器场景） | 退到 `ps aux` |
| `last -F -i` | `-F` / `-i` 不识别 | util-linux 老版本 | 退到 `last -n 20`，时间信息降精度 |
| `find /etc/cron.d -mtime -7` | 无输出 | 目录不存在（Alpine） | 补 `-o -path /etc/periodic` 兜底 |
| `crontab -l -u <user>` | `no crontab for user` | 该账户确实无 cron | 记为 `NEGATIVE`，不是异常 |
| `iptables -L` | `command not found` | 客户改用 nftables | 切 `nft list ruleset` 或 `firewall-cmd --list-all` |
| `wevtutil` | Windows 命令，但目标是 Linux | 用户 profile 选错 | 主会话检测 OS 后拒绝，返回 profile 建议 |

主会话看到 exit_code ≠ 0 时应先查此表，再判定是否是"命令被拦截"这种攻防信号。

---

## 九、输出格式范例

### 9.1 远程采集异常清单条目

```jsonl
{"id":"REM-001","severity":"P2","category":"recon","evidence":"target=svc-01 cmd=list-processes tier=1 authorized_by=ticket-#20260701-042 stdout_bytes=4821 exit_code=0","rule_id":"R-REM-001","false_positive_prob":0.0,"recommended_action":"复用 stdout 进入 audit 模式关联分析","iocs":[]}
```

### 9.2 processing action 记录（Tier 3 之后）

```jsonl
{"id":"REM-014","severity":"P0","category":"disposal","evidence":"target=svc-01 cmd=kill-pid pid=12345 tier=3 authorized_by=ticket-#20260701-042+voice-confirm-20260701T1432 allow_mutating=true exit_code=0 post_verify=OK","rule_id":"R-REM-DISP-KILL","false_positive_prob":0.0,"recommended_action":"通知客户运维检查依赖服务是否需要重启；处置证据已归档 audit.jsonl","iocs":[]}
```

### 9.3 dry-run 预览

见 §四 步骤 2 的清单示例。

---

## 十、与 ir / audit 的衔接

`remote` 与 `ir` 是**协作**而非替代关系。分工：

| 场景 | remote 负责 | ir 负责 |
|---|---|---|
| 拉回单个日志文件 | 远程 tail / scp 拉数据 | — |
| 拉回完整采集包 | `remote_collect.py --profile linux-full` | 分析 tar.gz 生成 incident-report |
| 定性已入侵 | — | ir 输出 incident-report + 处置建议 |
| 触发处置 | Tier 3 命令 | — |

升级链（典型）：

```
用户："帮我远程看看 svc-01 上有没有异常进程"
  ↓
remote §二 5 问对齐 → ssh_probe.py --cmd-id list-processes
  ↓
拿回 stdout（含可疑 PID 12345 监听 4444 端口）
  ↓
主会话建议：转 ir 深挖
  ↓
ir 模式：分析 process tree / connections / files / persistence → 定性入侵
  ↓
ir 输出建议："立即处置 PID 12345 + 封 C2 IP"
  ↓
回 remote：二次授权 → ssh_probe.py --cmd-id kill-pid --allow-mutating ...
  ↓
处置完成 → post_action_verify → audit.jsonl 归档
```

反向不允许：ir 不得自动触发 remote 的 Tier 3 命令。ir 只能"建议"，触发必须由主会话回到 remote 走完二次授权流程。

audit 与 remote 的衔接：audit 需要新的日志片段时可以生成 `fetch-*` 类 T2 命令请求，主会话拉取后回填给 audit 继续分析——中间必然经过 remote 的授权 + 审计闭环。

---

## 十一、收尾：统一终报 + findings.json

remote 采集 / 处置会话结束后，**必须**输出跨模式统一终报与机器可读伴生文件（见 `SKILL.md §输出契约`）：

- **`final-report.md`（remote 形态，轻量变体）**：按 `assets/final-report.md` 渲染——
  - §2 判定与影响：verdict 多为 `inconclusive`（采集完成待 ir 分析）或沿用 ir 判定；填采集命令数 + Tier 3 处置数
  - §3 攻击路径地图：渲染为**采集→发现链**形态（Tier 1 只读采集节点 → 发现 → 若有 Tier 3 处置则接处置节点，每节点带 SESSION-AUDIT-* 审计 ID）
  - §4 分层发现详情：P0/P1 全文 8 字段卡，rule_id 含 `R-REM-*` / `R-REM-DISP-*`
  - §7 处置建议与优先级：取 **Tier 3 处置变体**（每条带授权状态 + 审计 ID + 录制文件）；未授权的处置建议只生成命令清单（H-I-L 堡垒机降级）
  - §10 附件：`sessions/*.log`（会话录制）/ `audit.jsonl`（命令审计）/ 若转 ir 则挂 `incident-report.md`
- **`findings.json`**：按 `assets/findings-schema.md` 生成，`mode=remote`，`findings[]` 的 rule_id 含 `R-REM-*`，`attack_paths[]` nodes 带 Tier 命令节点

> remote 与 ir 协作时：remote 拉数据 → ir 分析 → 定性入侵 → 回 remote 触发 Tier 3（二次授权）。终报以 ir 形态为主，remote 形态作为采集/处置证据挂附件。

---

## 相关引用

