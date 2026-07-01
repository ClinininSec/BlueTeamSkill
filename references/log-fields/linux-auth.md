# Linux Auth 日志字段速查（auth.log / secure / wtmp / btmp）

> Linux 主机登录与权限相关事件的字段速查与抽取模板。
> **何时使用**：audit 模式排查 ssh 暴破 / 提权 / 账户滥用 / 持久化痕迹时。

---

## 一、日志文件位置

| 发行版 | 主登录日志 | 失败二进制 | 成功二进制 | sudo / su |
|---|---|---|---|---|
| Debian / Ubuntu | `/var/log/auth.log` | `/var/log/btmp` | `/var/log/wtmp` | 同 auth.log |
| RHEL / CentOS / Rocky | `/var/log/secure` | `/var/log/btmp` | `/var/log/wtmp` | 同 secure |
| 通用 | journald (`journalctl -u sshd`) | — | — | — |

- `/var/log/wtmp` —— 成功登录历史（二进制），`last` 读取
- `/var/log/btmp` —— 失败登录历史（二进制），`lastb` 读取（需 root）
- `/var/log/lastlog` —— 每用户最后一次登录（二进制），`lastlog` 读取
- `/run/utmp` —— 当前在线（`who` / `w`）

---

## 二、关键事件类型与样例

### 2.1 sshd 登录
- 成功密码：`sshd[1234]: Accepted password for z******* from 192.168.1.xxx port 53412 ssh2`
- 成功公钥：`sshd[1234]: Accepted publickey for z******* from 192.168.1.xxx port 53412 ssh2: RSA SHA256:...`
- 失败密码：`sshd[1234]: Failed password for z******* from 192.168.1.xxx port 53412 ssh2`
- 失败（不存在用户）：`sshd[1234]: Failed password for invalid user admin from 192.168.1.xxx port 53412 ssh2`
- 断开：`sshd[1234]: Disconnected from authenticating user z******* 192.168.1.xxx port 53412 [preauth]`
- 公钥指纹：`sshd[1234]: Connection from 192.168.1.xxx port 53412 on ...`

### 2.2 sudo / su
- `sudo: z******* : TTY=pts/0 ; PWD=/home/z******* ; USER=root ; COMMAND=/bin/cat /etc/shadow`
- `sudo: z******* : 3 incorrect password attempts ; TTY=pts/0`
- `su[1234]: + pts/0 z*******:root` —— `+` 表示成功，`-` 失败

### 2.3 账户变更
- `useradd[1234]: new user: name=backup_xxx, UID=1001, GID=1001, home=/home/backup_xxx`
- `passwd[1234]: pam_unix(passwd:chauthtok): password changed for z*******`
- `userdel[1234]: delete user 'temp'`
- `usermod[1234]: change user 'z*******' UID from '1001' to '0'`  ← **极高危**

### 2.4 PAM 失败
- `sshd[1234]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=192.168.1.xxx user=z*******`

---

## 三、常用 grep 模板

约定：`AUTH=/var/log/auth.log` 或 `/var/log/secure`。

### 3.1 失败登录 IP + 计数 Top 20
```bash
grep -aE 'Failed password|authentication failure' $AUTH \
  | grep -oE 'from [0-9.]+|rhost=[^ ]+' \
  | sed -E 's/from |rhost=//' | sort | uniq -c | sort -rn | head -20
```

### 3.2 成功登录的账户 + IP + 时间
```bash
grep -aE 'Accepted (password|publickey)' $AUTH \
  | awk '{print $1,$2,$3, "user="$9, "ip="$11}'
```

### 3.3 暴破成功的关键信号 —— 同 IP 先失败 N 次后成功（首次成功）
```bash
# 思路：找 Accepted 行，往前回溯 200 行内的 Failed 来自同 IP
grep -aE 'Accepted|Failed password' $AUTH | awk '
  /Failed password/ {fail[$NF]++}
  /Accepted/ {if(fail[$NF] >= 5) print "[SUSP]", $0, "prev_fail=" fail[$NF]}
'
```

### 3.4 新建 / 删除 / 修改账户
```bash
grep -aE 'useradd|userdel|usermod|new user|new group|password changed' $AUTH
```

### 3.5 UID=0 创建或权限修改（极高危）
```bash
grep -aE "UID=0|GID=0|to root|to '0'" $AUTH
```

### 3.6 sudo 滥用 —— 非常规账户跑 sudo / 跑高危命令
```bash
grep -a 'sudo:' $AUTH | grep -vE 'COMMAND=/usr/bin/(apt|yum|systemctl|ls|cat)' \
  | awk -F'COMMAND=' '{print $1, "CMD:"$2}'
```

### 3.7 root 异地登录（非内网段）
```bash
grep -aE 'Accepted (password|publickey) for root' $AUTH \
  | grep -vE 'from (10\\.|172\\.(1[6-9]|2[0-9]|3[01])\\.|192\\.168\\.|127\\.0\\.0\\.1)'
```

### 3.8 非交互式 ssh（执行命令直接退出，常见于自动化但也常见于横向移动）
```bash
grep -aE 'ssh.*\\] Received disconnect' $AUTH | head
```

### 3.9 PAM session opened / closed 配对（核查会话时长）
```bash
grep -aE 'session (opened|closed)' $AUTH
```

### 3.10 公钥首次出现新指纹（结合 ~/.ssh/authorized_keys 核查）
```bash
grep -aE 'Accepted publickey' $AUTH | awk -F'SHA256:' '{print $2}' | awk '{print $1}' | sort -u
```

### 3.11 ssh 端口异常（默认 22 外）
```bash
grep -aE 'sshd.*Accepted' $AUTH | grep -vE 'port (22|2222|22222)\\b'
```

### 3.12 在 1 分钟内多账户暴破（密码喷洒 password-spray）
```bash
grep -aE 'Failed password' $AUTH | awk '{print $1, $2, substr($3,1,5), $9}' \
  | sort | uniq | awk '{print $1, $2, $3}' | uniq -c | sort -rn | head
```

---

## 四、`last` / `lastb` / `who` / `w` 取数姿势

```bash
last -F -i              # 完整时间 + IP，含 reboot
last -F -i -n 100       # 最近 100 条
last -F -i z*******     # 某账户登录历史
lastb -F -i -n 50       # 失败登录（root 权限）
who -a                  # 当前在线（含 boot / runlevel）
w                       # 当前在线 + 正在跑的命令
last -x | head          # 含 shutdown / runlevel 切换
utmpdump /var/log/wtmp  # 文本化 wtmp（核查是否被篡改）
```

---

## 五、反取证信号

- `/var/log/wtmp` 大小 = 0 或时间断档 → 攻击者 `>/var/log/wtmp` 清空
- `/var/log/auth.log` 大小骤减、最近修改时间近期，但 ssh 在跑 → 被截断
- `/var/log/lastlog` 中目标账户 last login 时间显示远古 → 被刷
- `journalctl --verify` 报错 → 二进制日志被篡改
- `/etc/audit/audit.rules` 被清空 → auditd 被破坏

发现以上情形时升级到 ir 模式。
