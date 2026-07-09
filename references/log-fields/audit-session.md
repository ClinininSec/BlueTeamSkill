# 远程会话审计日志字段（audit.jsonl）

> `~/.hvv-defender/audit.jsonl` 由 `ssh_probe.py` / `remote_collect.py` / `session_recorder.sh` 每次调用**追加**一条。
> 每一行都是独立 JSON（NDJSON / JSONL），便于 `jq` / 直接 `grep` / 用 pandas 读。
> 关联：`../modes/remote.md`、`../compliance.md` §红线 4 / 7、`../remote-command-whitelist.md`。

---

## 一、字段总览

| 字段 | 类型 | 必填 | 说明 |
|---|---|---|---|
| `ts` | ISO8601 (UTC, 秒精度) | ✅ | 命令发起时刻（不是完成时刻）；例 `2026-07-01T14:30:12Z` |
| `action` | enum | ✅ | 见 §二；例 `ssh_probe` / `remote_collect` / `session_recorder` / `post_action_verify` / `validation_failed` |
| `target` | string | ✅ | `user@host`（脱敏前）；例 `ops@svc-01` |
| `proxy_jump` | string | ⛔ | 若走跳板机；`bastion_user@bastion_host`；无则字段缺省 |
| `cmd_id` | string | ✅ | 白名单枚举名；例 `list-processes`；`session_recorder` 类事件填 `<session>` |
| `cmd_expanded` | string | ✅ | 实际展开后的命令（arg 已 `shlex.quote`）；长度 > 4KB 时截断并附 `...[truncated]` |
| `tier` | int | ✅ | 1 / 2 / 3；`session_recorder` 类填 `0` |
| `authorized_by` | string | ✅ | 工单号 / 邮件 ID / 群消息 ID；Tier 3 需拼上二次口头确认标识（如 `ticket-#42+voice-confirm-20260701T1432`） |
| `allow_mutating` | bool | ✅ | 本次调用是否启用 Tier 3；Tier 1/2 恒为 `false` |
| `exit_code` | int | ✅ | 命令退出码；见 §四 |
| `stdout_bytes` | int | ✅ | stdout 字节数（未压缩） |
| `stderr_bytes` | int | ✅ | stderr 字节数 |
| `duration_ms` | int | ✅ | 命令从发出到返回耗时（毫秒）；超时时也如实记录 |
| `desensitized` | bool | ✅ | 本条 audit 记录**自身**是否已脱敏；本机原始 audit.jsonl 为 `false`，对外交付版为 `true` |
| `session_log` | string | ⛔ | session log 文件路径（相对驻场机 `~`）；无 session recorder 时缺省 |
| `dry_run` | bool | ✅ | 是否 `--dry-run` 预演；预演不产生远端调用 |
| `os` | enum | ⛔ | `linux` / `windows` / `unknown`；从 target 主机的 `os-info` 结果缓存推断 |
| `skill_version` | string | ⛔ | 本次执行时 skill 的版本号，如 `v0.4-M0`；用于事后回溯 |
| `client_user` | string | ⛔ | 驻场机上执行命令的账户名（脱敏前）；用于多人共用驻场机时定位 |
| `error_hint` | string | ⛔ | 校验失败 / 拒绝执行时的原因，例 `arg-shell-metachar` / `cmd-id-not-in-whitelist` / `tier3-not-authorized` |

**字段总数**：核心 16 + 可选 4 = 20 个。核心 16 字段中 `proxy_jump` 与 `session_log` 允许缺省，其余 14 个必填。

---

## 二、审计事件类型（`action` 枚举）

| action | 触发条件 | tier | 关键差异字段 |
|---|---|---|---|
| `ssh_probe` | 单命令远程执行成功发起（无论 exit_code 如何） | 1/2/3 | `cmd_id` / `cmd_expanded` |
| `remote_collect` | 批量采集 profile 触发 | 2 | `cmd_id=run-linux-collect/run-windows-collect/...` |
| `session_recorder` | 交互式会话开始 / 结束 | 0 | `cmd_id=<session-start>` / `<session-end>`，配 `session_log` |
| `post_action_verify` | Tier 3 处置后主动跑 T1 验证 | 1 | `cmd_id` 是被验证的 T1；`error_hint` 记录预期与实际的对比结果 |
| `validation_failed` | 参数校验 / cmd_id 不在白名单 / Tier 3 未授权等**发起前**拒绝 | 0 | `exit_code=2/3`，`error_hint` 必填；不会产生实际的 SSH 连接 |
| `authorization_denied` | 5 问对齐未通过 | 0 | `exit_code=2`，`error_hint` 记录缺哪一项 |
| `desensitize_run` | 对采集结果跑 `desensitize.py` | 0 | `cmd_id=desensitize`；`cmd_expanded` 记录输入 / 输出路径 |

**为什么把 `validation_failed` / `authorization_denied` 也记入 audit**：这些"被拒绝"的动作恰恰是最有分析价值的——事后审计可以看到哪些误操作被 Skill 拦住了；也可作为培训材料改进驻场人员流程。

---

## 三、脱敏边界

审计日志的存储与流转要区分**本机保留**和**对外交付**两个场景：

### 3.1 本机保留（`~/.hvv-defender/audit.jsonl`）

- **允许**包含内网 IP、hostname、用户名、路径等敏感字段（本地磁盘加密，仅驻场人员本人可访问）
- 目的：完整审计留痕，事后能精确回溯执行了什么
- `desensitized` 字段 = `false`

### 3.2 对外交付（驻场交接 / 复盘 / 客户索取）

**必须**过一次 `desensitize.py`：

```bash
python3.11 scripts/desensitize.py \
  --input ~/.hvv-defender/audit.jsonl \
  --output ~/.hvv-defender/audit-desens.jsonl \
  --mode strict \
  --internal-cidr "10.0.0.0/8,192.168.0.0/16" \
  --internal-domain "*.corp.example.com"
```

- 处理后 `desensitized` 字段 = `true`
- 处理项：`target` 的 host 部分、`cmd_expanded` 中的内网 IP / 用户名 / 路径
- **不脱敏**：`cmd_id` / `tier` / `authorized_by` / 时间戳（这些是审计价值本身）
- **完全隐藏**：`cmd_expanded` 中若含意外的 credential-like 字符串（token / hash）替换为 `[CREDENTIAL REDACTED]`

### 3.3 session_log 的脱敏

- `session_log` 本身是完整的交互录像（stdout + stderr + user input 时间戳）
- 交付前也要过 `desensitize.py --mode strict`
- 大文件（> 10 MB）建议 gzip 后再脱敏，`desensitize.py --input session.log.gz` 支持透明解压

---

## 四、故障与合规排查

### 4.1 通过 exit_code 定位问题

| exit_code | 语义 | 典型场景 |
|---|---|---|
| `0` | 命令成功 | 正常路径 |
| `1` | 命令本身失败（远端） | 例如 `crontab -l` 对无 cron 的账户返回 1；`grep` 无匹配返回 1 |
| `2` | Skill 拒绝执行（合规违规） | 缺 `authorized-by` / arg 含 shell metachar / cmd_id 不在白名单 |
| `3` | Skill 拒绝执行（授权级别不足） | Tier 3 未开 `--allow-mutating` |
| `124` | 命令超时（本地判定） | 超过 tier 默认超时 |
| `126` | 命令找不到 shell（远端） | 目标机 `sh` / `bash` 不存在 |
| `127` | 命令不存在（远端） | 例如目标是 CentOS 6，跑 `journalctl` 会返回 127 |
| `130` | 用户中断（Ctrl+C） | 本地 |
| `255` | SSH 连接失败 | 网络 / 密钥 / known_hosts 问题 |

### 4.2 合规违规排查

发生 `validation_failed` / `authorization_denied` 后，主会话必须给出 explicit 反馈，示例：

- `error_hint=cmd-id-not-in-whitelist` → 提示"cmd_id `foo` 不在白名单，请查 `remote-command-whitelist.md`"
- `error_hint=arg-shell-metachar` → 提示"参数 `<pid>` 值 `123;whoami` 包含 shell 元字符，被拒绝"
- `error_hint=tier3-not-authorized` → 提示"Tier 3 未开启，请追加 `--allow-mutating` 并完成二次口头确认"

### 4.3 SSH 层排查（exit_code 255）

按顺序排查：

1. 主机能否 ping 通（`ping -c 3 <host>`）
2. SSH 端口是否开（`nc -vz <host> 22`）
3. 本机 known_hosts 是否需要清（客户主机重装后 fingerprint 变化）
4. 密钥是否在 `authorized_keys`（`ssh -v -i <key> <target>` 看握手日志）
5. 跳板机是否可用（同样按 1-4 检查跳板机）

排查完成后**不允许**用 `-o StrictHostKeyChecking=no` 绕过，需要走正规 known_hosts 更新流程。

---

## 五、审计日志的驻场保留期

保留策略与 `../compliance.md` §三 数据保留章节严格对齐：

| 内容 | 位置 | 保留时长 | 销毁方式 |
|---|---|---|---|
| `~/.hvv-defender/audit.jsonl` | 驻场机本地加密磁盘 | 演习结束 + 30 天 | `shred -u ~/.hvv-defender/audit.jsonl` |
| `~/.hvv-defender/sessions/*.log` | 同上 | 演习结束 + 30 天 | `shred -u ~/.hvv-defender/sessions/*.log` |
| `~/.hvv-defender/collects/*.tar.gz` | 同上 | 演习结束 + 7 天 | `shred -u` 或磁盘卷销毁 |
| 对外交付版 `audit-desens.jsonl` | 客户文档库 | 按客户合同 | 由客户决定 |

**驻场结束流程**（与 compliance.md §三 一致）：

1. 与甲方对齐保留期是否需要延长（例如复盘会议后 60 天）
2. 到期前自查：`ls -la ~/.hvv-defender/`
3. `shred -u` 单个文件销毁（不允许 `rm`——`shred` 保证数据不可恢复）
4. 出具销毁声明邮件给甲方，附销毁前的**文件哈希列表**（`sha256sum ~/.hvv-defender/*` 结果作证据）
5. 销毁邮件本身抄送乙方安全合规

---

## 六、样例

### 6.1 一次典型 Tier 1 调用（成功）

```jsonl
{"ts":"2026-07-01T14:30:12Z","action":"ssh_probe","target":"ops@svc-01","cmd_id":"list-processes","cmd_expanded":"ps -eo pid,ppid,user,stat,pcpu,pmem,etime,cmd --sort=-pcpu | head -50","tier":1,"authorized_by":"ticket-#20260701-042","allow_mutating":false,"exit_code":0,"stdout_bytes":4821,"stderr_bytes":0,"duration_ms":842,"desensitized":false,"os":"linux","skill_version":"v0.4-M0","client_user":"engineer-a","dry_run":false}
```

### 6.2 一次 Tier 3 处置 + 后置验证（两条 audit）

```jsonl
{"ts":"2026-07-01T14:35:22Z","action":"ssh_probe","target":"ops@svc-01","cmd_id":"kill-pid","cmd_expanded":"kill -TERM 12345","tier":3,"authorized_by":"ticket-#20260701-042+voice-confirm-20260701T1432","allow_mutating":true,"exit_code":0,"stdout_bytes":0,"stderr_bytes":0,"duration_ms":314,"desensitized":false,"os":"linux","skill_version":"v0.4-M0","client_user":"engineer-a","dry_run":false}
{"ts":"2026-07-01T14:35:26Z","action":"post_action_verify","target":"ops@svc-01","cmd_id":"list-processes","cmd_expanded":"ps -eo pid,ppid,user,stat,pcpu,pmem,etime,cmd --sort=-pcpu | head -50","tier":1,"authorized_by":"ticket-#20260701-042+voice-confirm-20260701T1432","allow_mutating":false,"exit_code":0,"stdout_bytes":4732,"stderr_bytes":0,"duration_ms":798,"desensitized":false,"error_hint":"target-pid-absent-verified","os":"linux","skill_version":"v0.4-M0","client_user":"engineer-a","dry_run":false}
```

### 6.3 参数校验失败（未产生远端调用）

```jsonl
{"ts":"2026-07-01T14:40:03Z","action":"validation_failed","target":"ops@svc-01","cmd_id":"process-inspect","cmd_expanded":"","tier":1,"authorized_by":"ticket-#20260701-042","allow_mutating":false,"exit_code":2,"stdout_bytes":0,"stderr_bytes":0,"duration_ms":3,"desensitized":false,"error_hint":"arg-shell-metachar: pid=123;whoami","skill_version":"v0.4-M0","client_user":"engineer-a","dry_run":false}
```

### 6.4 dry-run 预演

```jsonl
{"ts":"2026-07-01T14:29:00Z","action":"remote_collect","target":"ops@svc-01","cmd_id":"run-linux-collect","cmd_expanded":"(12 subcommands, see profile 'linux-basic')","tier":2,"authorized_by":"ticket-#20260701-042","allow_mutating":false,"exit_code":0,"stdout_bytes":0,"stderr_bytes":0,"duration_ms":8,"desensitized":false,"dry_run":true,"skill_version":"v0.4-M0","client_user":"engineer-a"}
```

---

## 七、常用 jq 一线

```bash
# 今天所有 Tier 3 调用
jq -r 'select(.tier==3 and (.ts | startswith("2026-07-01")))' ~/.hvv-defender/audit.jsonl

# 所有被拒绝执行的命令 + 原因
jq -r 'select(.action=="validation_failed" or .action=="authorization_denied") | "\(.ts) \(.cmd_id) \(.error_hint)"' ~/.hvv-defender/audit.jsonl

# 单 target 的完整调用序列
jq -r 'select(.target=="ops@svc-01") | "\(.ts) [T\(.tier)] \(.cmd_id) exit=\(.exit_code)"' ~/.hvv-defender/audit.jsonl

# 总耗时 / 总字节
jq -s '{total_calls: length, total_ms: (map(.duration_ms) | add), total_stdout_kb: ((map(.stdout_bytes) | add) / 1024 | floor)}' ~/.hvv-defender/audit.jsonl
```

---

## 相关引用

- 远程模式流程：`../modes/remote.md`
- 白名单知识库：`../remote-command-whitelist.md`
- 脱敏脚本：`../../scripts/desensitize.py`
- 合规红线：`../compliance.md` §红线 4 / 7 / §三 数据保留
