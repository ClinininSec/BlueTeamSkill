# Playbook: Webshell 处置剧本

> 适用模式：monitor / audit / ir
> 难度：★★★★☆
> 平均处置时间：60-120 分钟（含根除验证）

## 1. 攻击概述

- **攻击者目的**：在 Web 服务器上获得持久化的命令执行能力，作为内网立足点；为后续提权 / 横向 / 数据外传提供跳板。
- **典型攻击链位置**：
  - MITRE ATT&CK 战术映射：`Initial Access (T1190)` → `Persistence (T1505.003 Server Software Component: Web Shell)` → `Execution (T1059)` → `Command and Control (T1071)`
  - 多数 webshell 在「攻陷 Web 应用」之后立即部署，是从「漏洞利用」走向「驻留」的核心交接点。
- **护网期间出现频次**：极高。值守期间几乎每天可见疑似上传，真实命中比例约 1-5%（取决于客户资产暴露面与 WAF 成熟度）。
- **常见入口**：
  - 任意文件上传（OA / CMS / 编辑器 fck / ueditor / kindeditor）
  - 任意文件写入（反序列化写文件、目录穿越写文件）
  - 解析漏洞（IIS .asp;.jpg、Apache 多后缀、Nginx 配置错误）
  - 后台弱口令 + 模板编辑 / 插件上传

## 2. 识别特征

> 只描述「识别这是 webshell」的特征，不描述「如何编写 webshell」。

### 2.1 静态特征（文件层）

- **文件名异常**：
  - 超短文件名：`1.jsp` / `x.php` / `a.aspx` / `s.jsp`
  - 全字母大写或纯数字：`HACK.jsp` / `7758521.php`
  - 与正常业务命名风格明显不符（业务用 `userLogin.jsp`，突然出现 `cmd123.jsp`）
  - 隐藏命名：以 `.` 开头（Linux）、`~$` 开头（Windows）、夹带空格 / 中文 / 特殊字符
- **文件位置异常**：
  - 静态目录（`/upload/`、`/static/`、`/images/`）下出现脚本类后缀
  - 临时目录（`/tmp/`、`/var/tmp/`）下的 web 可访问脚本
  - 业务无关目录中突然出现 `index.jsp` / `default.php`
- **文件内容关键模式**（脱敏描述，不给完整可复现 payload）：
  - 动态求值类：`eval(...)` / `assert(...)` 直接吃 HTTP 入参的写法
  - 反射 / 字节码加载类：`defineClass` / `ClassLoader.defineClass` / `Method.invoke` 拼接执行
  - 进程执行类：`Runtime.getRuntime().exec` / `ProcessBuilder` / `system()` / `shell_exec` / `passthru()`
  - 编码套娃：多层 `base64_decode` / `gzinflate` / `str_rot13` / `urldecode` 嵌套，最终落到 eval
  - 一句话占位符：HTTP 入参直达 eval / exec，无中间业务逻辑
- **文件元信息异常**：
  - mtime 远晚于业务部署时间，或与同目录文件相差几个月
  - 文件 owner 是 web 进程用户而非部署用户
  - 权限带可执行位但同目录正常文件不带

### 2.2 行为特征（流量层）

- **请求长度异常**：
  - 固定 `Content-Length`（很多免杀 webshell 的 AES key 协商首包长度固定）
  - POST body 明显大于同接口正常请求（10KB+ 的 base64 body）
- **请求头异常**：
  - 固定且不常见的 `User-Agent`（哥斯拉默认 `Mozilla/5.0 (Windows NT 10.0; WOW64) ...` 但行为节奏不像浏览器）
  - 固定 `Referer`（攻击者脚本写死，浏览器不会这样）
  - 固定 `Accept` 头（如 `text/html` 但 body 是大段二进制 base64）
  - 缺失浏览器必带头（`Accept-Language` / `Accept-Encoding` 全空）
- **请求节奏异常**：
  - 单 IP / 单 UA 对同一 URI 高频 POST，POST 远多于 GET
  - 上传 + 立即访问（5 秒内对刚上传文件首次访问，且后续高频）
- **响应特征**：
  - 同 URI 不同请求响应体长度差异巨大（一会儿 200B，一会儿 50KB）
  - 响应 Content-Type 与文件名后缀矛盾
  - 响应包含明显的 base64 大段 + 无 HTML 结构

### 2.3 上下文特征（关联）

- **时间相关性**：在 N 分钟内发生过「文件上传接口被打」「编辑器漏洞被扫」「反序列化 payload 被打」 → 紧接着该路径出现 200 → 高度可疑
- **来源 IP**：同一 IP 此前在扫描（4xx 突增）后突然只访问某个新路径并稳定 200
- **WAF 关联**：WAF 拦了上传，但有一个变体绕过成功 → 关注绕过成功的那一条
- **进程关联**（主机侧）：
  - web 容器进程（java / php-fpm / w3wp）拉起非典型子进程（bash / sh / cmd / powershell）
  - 子进程是 `whoami` / `id` / `ifconfig` / `ipconfig` / `net user` / `curl` / `wget` / `nc`

### 2.4 主流 Webshell 管理工具的识别特征

> 仅描述识别特征，不提供工具操作细节。

- **哥斯拉（Godzilla）**：
  - 流量层 AES 加密 + base64 二次编码，body 末尾常有固定 padding 长度
  - 首次握手交换密钥，后续请求 body 长度有规律
  - Cookie 中常带固定标识字段
- **冰蝎（Behinder）**：
  - 早期版本 AES key 是 16 位 md5 前 16，密钥可静态推测
  - 流量 body 是 base64 密文，开头几个字节熵值很高
  - HTTP 头里有 `Pragma`/`Cache-Control` 异常组合
- **蚁剑（AntSword）**：
  - 默认 UA 写死 `antSword/v...`（新版可改但很多人不改）
  - POST body 中 `_0xxxxxx_=` 形如混淆变量名作为参数
  - 命令执行常带固定前后缀分隔符（攻击者方便切割回显）

### 2.5 内存马识别

- **JSP/Java 内存马**：
  - 新增的 Filter / Servlet / Listener / Interceptor / Valve / Controller，但磁盘 `web.xml` / `WEB-INF/classes/` 没有对应类文件
  - jstack 中出现匿名类、Lambda 类、`$Proxy` 类持有可疑 URL 路径
  - `arthas`/`jdk` 工具枚举 Filter 列表，发现注册时间远晚于服务启动
- **PHP 内存马**：
  - `auto_prepend_file` / `auto_append_file` 被设置为非预期文件
  - `disable_functions` 被绕过的痕迹（如 LD_PRELOAD 注入）
- **.NET 内存马**：
  - IIS w3wp 进程内存中发现非编译来源的 HttpHandler / HttpModule

## 3. 日志查询模式（按日志类型）

> 以下为 grep / awk 思路示意，实际由 `scripts/webshell_scan.py` 与 `scripts/nginx_anomaly.py` 实现。

### 3.1 nginx / apache access.log

```bash
# 短文件名脚本访问（注意：业务里有合法短名时会误报，按实际清单排除）
grep -E ' /(static|upload|images|files)/[a-zA-Z0-9_]{1,3}\.(jsp|jspx|php|aspx?)' access.log

# POST 远多于 GET 的 URI（单 URI 维度聚合）
awk '{print $7, $6}' access.log | sort | uniq -c | sort -rn | head -50
# 字段位置按实际 log_format 调整

# 固定 Content-Length 的 POST（拿到 body 长度后聚合）
awk '$6 ~ /POST/ {print $7, $10}' access.log | sort | uniq -c | sort -rn

# 上传后立即访问（先找上传响应 200，再查同路径访问）
grep -E 'POST .* (upload|fileupload)' access.log
```

字段过滤逻辑：
- 同 IP / 同 URI / POST 占比 > 80% 且请求数 > 20 → 候选
- 同 IP / 高频访问某个静态目录下脚本 → 候选
- `Content-Length` 在 5 个以上请求中完全相等且 > 200 → 候选

### 3.2 auth.log / secure（webshell 上下文配套）

```bash
# webshell 拉起的可疑命令通常通过 sudo / su 提权，关注非交互式 sudo
grep -E 'sudo:.*COMMAND=' /var/log/auth.log | grep -v 'TTY='

# 新增账户（持久化常见手段）
grep -E 'new user|new group|useradd|groupadd' /var/log/auth.log
```

### 3.3 Windows EventID（IIS / .NET 场景）

- `EventID 4688` —— 进程创建，关注 `w3wp.exe` 拉起 `cmd.exe` / `powershell.exe` / `whoami.exe`
- `EventID 7045` —— 服务安装，关注新增异常服务
- `EventID 1102` —— 安全日志被清空（疑似掩盖痕迹）
- `EventID 4663` —— 文件访问审计，关注 wwwroot 下新增脚本文件

### 3.4 WAF / FW 告警关键字

- `webshell`, `china chopper`, `godzilla`, `behinder`, `antsword`, `kjie`, `caidao`
- `upload bypass`, `file upload`, `arbitrary file upload`
- `command injection` (常作为 webshell 上传的前置 / 后置告警)
- `deserialization` / `fastjson` / `log4j` / `jndi` (常导致内存马)

## 4. 误报排查清单

| # | 误报特征 | 如何排除 |
|---|---|---|
| 1 | 业务的 CMS 后台「在线编辑模板」功能，正常用户保存模板时也会写入 `.php`/`.jsp` 文件 | 查 mtime + 操作者 IP，若是后台已认证 IP 且对应有登录日志，多为正常 |
| 2 | CI/CD 部署任务拉取代码导致 web 目录大量文件 mtime 刷新 | 与发布平台日志对账，发布时间窗内的变更全部排除 |
| 3 | 同事在做合法的红蓝演练 / 内部测试 | 与红队 / 测试团队对账日程表，时间 + IP + 目标对得上即排除 |
| 4 | 业务接口本身大量 POST（如批量数据上报、IM 长轮询），呈现「POST 多于 GET」特征 | 看接口路径，业务接口（如 `/api/event/report`）有正常 Referer、UA、Accept 链，能与 webshell 区分 |
| 5 | 监控 / 探活脚本固定 UA + 固定路径高频访问 | 看 UA 是否是已登记的探活账号；探活路径通常是固定的健康检查 endpoint |
| 6 | 编辑器（fckeditor / kindeditor）的合法预览/缩略图请求看起来像「上传后立即访问」 | 看请求是否带正确的 token / Referer 链；合法预览路径在编辑器目录而非自定义路径 |
| 7 | 漏洞扫描器（绿盟 / 启明 / nessus）的内部扫描任务命中 webshell 规则 | 扫描器源 IP 在白名单内、扫描时段是已报备时段 → 排除 |
| 8 | 静态资源目录下被合法放置的 `.htaccess` / `web.config` 不是 webshell | 内容审阅：只有重写规则、无 eval / exec 即可放行 |

**误报判定原则**：能与「已知正常运维行为 / 已报备测试 / 已认证后台操作」对账上的，标 `false_positive_prob >= 0.8`，进 P3。

## 5. 关联升级规则

### 5.1 严重性升级（P2 → P1 → P0）

- **P2 → P1**：
  - 同一可疑文件被外部 IP 访问且响应 200
  - 静态特征命中 + 时间窗内有对应的上传告警
- **P1 → P0**：
  - 主机侧确认文件落地（locate / find 找到）
  - 主机侧 web 进程出现可疑子进程（bash / cmd / curl）
  - 文件内容确认含 eval / exec 且能解码到敏感模式
  - 攻击者 IP 同时在打其他主机（横向扩散迹象）

### 5.2 模式升级（monitor → audit → ir）

- **monitor → audit**：单条 P1+ 告警，需要更广时间窗的日志比对（前后 24 小时）
- **audit → ir**：
  - 在主机上找到落地的 webshell 文件
  - 主机侧 bash_history / 进程树证实命令被执行过
  - 出现明显的二阶动作（提权、横向、外联）

## 6. 止血动作（containment）

### 6.1 网络层

| 动作 | 操作要点 | 副作用 | 回退路径 |
|---|---|---|---|
| WAF 加规则 ban 攻击 IP | 在 WAF 控制台对源 IP 加拒绝规则；优先 ban /32，其次 ban /24 | 误伤同 NAT 出口的正常用户 | 24h 后观察无误报再固化；有误伤时立即撤销并改用 URL+IP 联合规则 |
| 边界防火墙 ban 攻击 IP | iptables / 边界 ACL 加 drop | 同上 | 与 WAF ban 联动，互为备份 |
| 临时下线漏洞 URL | nginx location 加 `return 403` | 业务功能不可用 | 等漏洞修补后回滚 |

### 6.2 主机层

| 动作 | 操作要点 | 副作用 | 回退路径 |
|---|---|---|---|
| 隔离主机 | 切换到管理 VLAN / 摘出负载均衡 | 业务流量需切到备机 | 根除 + 验证后回切 |
| 备份证据后再处理文件 | `cp -p` 复制可疑文件到证据目录，记录 sha256 + mtime + stat；再做删除/重命名 | 取证操作本身改变 atime（用 `mount -o remount,noatime` 或先快照） | 证据已落，原文件可还原 |
| **不要直接 rm webshell** | 先重命名到非 web 可访问路径（如 `/root/quarantine/`），等取证完毕再删 | 直接 rm 丢失关联进程、丢失内存中可疑会话 | 通过快照恢复 |

### 6.3 应用层

| 动作 | 操作要点 | 副作用 | 回退路径 |
|---|---|---|---|
| 关闭文件上传接口 | 注释 upload route / 加白名单 | 上传功能不可用 | 修复后回滚 |
| 临时关闭漏洞组件 | 卸载 / 禁用易受影响的 jar / plugin | 业务功能受损 | 升级到安全版本后回滚 |
| 重启 web 服务 | `systemctl restart` web 进程 | **会丢失内存马**（这既是优点也是潜在证据丢失，所以重启前先 jstack / dump） | 服务自愈，无回退 |

### 6.4 账号层

| 动作 | 操作要点 | 副作用 | 回退路径 |
|---|---|---|---|
| 重置 web 容器用户口令 | 修改 `tomcat-users.xml` / 应用后台密码 | 短期影响业务管理员登录 | 已通知运维 |
| 检查 / 回收新增本地账户 | `cat /etc/passwd` + 比对基线 | 误删合法账户可恢复但费事 | `useradd` 重建（前提是有基线） |

## 7. 根除与恢复（eradication & recovery）

### 7.1 根除步骤

1. **定位所有落地文件**：
   - `find <webroot> -mtime -30 -type f \( -name '*.jsp' -o -name '*.php' -o -name '*.aspx' \) -ls`
   - `find / -mtime -7 -type f -size -10k -size +10c 2>/dev/null | xargs grep -l 'eval\|Runtime.exec' 2>/dev/null`
   - 与 `webshell_scan.py` 结果交叉验证
2. **处理内存马**（如果是内存马）：
   - `jstack <pid>` / `jmap -dump:format=b,file=heap.bin <pid>`
   - 用 arthas 类的工具枚举 Filter / Servlet 链，识别非磁盘来源类
   - 热补丁卸载或重启 JVM；重启后必须确认非持久化（否则会复发）
3. **清除持久化**：
   - crontab（root + 各业务用户）
   - `/etc/cron.d/`、`/etc/cron.*/`、`/etc/anacrontab`
   - systemd 单元（`/etc/systemd/system/`、`/usr/lib/systemd/system/`）
   - `~/.bashrc` / `~/.bash_profile` / `/etc/profile.d/` 注入
   - `authorized_keys`（root + 业务用户）
4. **修补入口漏洞**：升级组件 / 改配置 / 加 WAF 规则，三者至少做两个。

### 7.2 恢复步骤

- 优先：基线快照回滚（提前有可信快照的话）
- 次选：保留快照 → 重装系统 → 还原业务数据（数据需经过扫描）
- 末选：原地清理后继续运行（仅在不能停机且根除完整的情况下）

### 7.3 验证点（至少 3 个，逐项确认）

1. **文件层验证**：`find <webroot> -mtime -90 -type f` 列出所有近期文件，逐一审计；新部署的 web 目录用 hash 对账（与可信基线对比）
2. **进程层验证**：web 进程的子进程树 24h 内无 `bash`/`sh`/`cmd`/`powershell`/`curl`/`wget`/`nc`
3. **流量层验证**：原攻击 IP 的请求全部 4xx / 403；同 URI 的请求中 POST/GET 比恢复正常水位
4. **WAF 验证**：原命中规则在 24h 内复发率为 0
5. **内存马验证**：服务重启后，filter / servlet / handler 链与基线一致

## 8. IOC 提取模板

> 沿用 SKILL.md 的 IOC 7 字段 schema：`type / value / confidence / first_seen / source / tag / description（可选）`。

本类攻击应提取以下 IOC 类型：

```json
[
  {
    "type": "ip",
    "value": "192.168.1.xxx",
    "confidence": "high",
    "first_seen": "2026-06-30T09:12:33+08:00",
    "source": "nginx-access.log:line-12453",
    "tag": "webshell:godzilla,attacker-ip",
    "description": "对 /upload/x.jsp 的高频 POST，body 长度固定 384B"
  },
  {
    "type": "ua",
    "value": "Mozilla/5.0 (...) Godzilla-default",
    "confidence": "medium",
    "first_seen": "2026-06-30T09:12:33+08:00",
    "source": "nginx-access.log:line-12453",
    "tag": "tool:godzilla"
  },
  {
    "type": "path",
    "value": "/upload/<random>.jsp",
    "confidence": "high",
    "first_seen": "2026-06-30T09:10:01+08:00",
    "source": "nginx-access.log:line-12410",
    "tag": "webshell:dropped-file"
  },
  {
    "type": "hash:sha256",
    "value": "<webshell-sha256>",
    "confidence": "high",
    "first_seen": "2026-06-30T09:10:01+08:00",
    "source": "host:/data/<app>/web/upload/x.jsp",
    "tag": "webshell:file-hash"
  },
  {
    "type": "tool",
    "value": "godzilla",
    "confidence": "medium",
    "first_seen": "2026-06-30T09:12:33+08:00",
    "source": "rule:PLB-WS-003",
    "tag": "webshell-manager"
  }
]
```

提取重点：
- 攻击者 IP（外部访问 webshell 的 IP，可能与漏洞利用 IP 不同）
- webshell 文件 sha256 / md5
- webshell URL 路径
- 攻击 UA（固定 UA 是高置信指纹）
- 关联的 C2 域名 / IP（如果 webshell 反向连接）
- 工具指纹（godzilla / behinder / antsword / china chopper）

---

## rule_id 命名约定

- 前缀：`PLB-WS-NNN`（PlayBook-WebShell）
- 编号建议从 001 开始，每 10 号留 buffer 给后续插入

### 已建议规则一览

| rule_id | 规则名 | 触发条件 |
|---|---|---|
| PLB-WS-001 | 短文件名脚本访问 | URI 命中 `^/[a-zA-Z0-9]{1,3}\.(jsp\|jspx\|php\|aspx?)$` 且 5xx/2xx 占比异常 |
| PLB-WS-002 | 静态目录脚本执行 | URI 落在静态目录（`upload/static/images/`）但以脚本后缀结尾且响应 200 |
| PLB-WS-003 | Godzilla 流量指纹 | POST body 长度固定 + 特定 Cookie/Header 组合 + 加密载荷熵值 > 7.5 |
| PLB-WS-004 | Behinder 流量指纹 | POST body 为 base64 密文 + 16 字节对齐 + 缺少浏览器特征头 |
| PLB-WS-005 | AntSword UA 指纹 | UA 含 `antSword`（含变体） |
| PLB-WS-006 | 一句话 webshell 文件特征 | 文件内容含 `eval` 直接吃 `$_REQUEST`/`$_POST`/`$_GET` |
| PLB-WS-007 | 编码套娃 webshell | 文件含 ≥3 层 `base64_decode`/`gzinflate`/`str_rot13` 嵌套 |
| PLB-WS-008 | Runtime.exec 类执行 | 文件含 `Runtime.getRuntime().exec`/`ProcessBuilder` 且接受 HTTP 入参 |
| PLB-WS-009 | 上传后立即访问 | 同路径 POST 上传成功后 60s 内出现 GET/POST 访问且响应 200 |
| PLB-WS-010 | Web 进程异常子进程 | `java/php-fpm/w3wp` 拉起 `bash/sh/cmd/whoami/curl/wget/nc` |
| PLB-WS-011 | 内存马 Filter 异常注册 | jstack/arthas 列出的 Filter 没有对应磁盘 class 文件 |
| PLB-WS-012 | webshell 持久化痕迹 | crontab / systemd / authorized_keys 中含可疑路径或外部 IP |
