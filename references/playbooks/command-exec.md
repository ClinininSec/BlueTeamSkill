# Playbook: 命令执行处置剧本

> 适用模式：monitor / audit / ir
> 难度：★★★★★（最严重）
> 平均处置时间：60-180 分钟（含根除验证）

## 1. 攻击概述

- **攻击者目的**：在目标服务器上直接执行任意命令（RCE，Remote Code Execution）；这是攻击链中价值最高的能力，一旦触发往往直接获取应用 / 服务进程权限。
- **典型攻击链位置**：
  - MITRE ATT&CK 战术映射：`Initial Access (T1190)` → `Execution (T1059 Command and Scripting Interpreter)` → `Privilege Escalation` → `Persistence`
  - RCE 通常一击即穿透边界，是护网期间「拿分」最直接的方式（红方）和「失分」最严重的事件（蓝方）。
- **护网期间出现频次**：中等，但**威胁等级最高**。一次成功的 RCE 几乎必然导致主机失陷，因此默认 P0 起跳。
- **常见入口**：5 大子类
  1. 纯 RCE（裸命令注入）：业务直接把用户输入拼到 `Runtime.exec` / `system()` / `os.system` / shell 命令行
  2. 反序列化 RCE：fastjson、jackson、xstream、yaml、weblogic T3、shiro 反序列化等
  3. SSTI（Server-Side Template Injection）：Freemarker、Velocity、Thymeleaf、Jinja2 等
  4. log4j2 JNDI 注入：log4shell（CVE-2021-44228）及变体
  5. 表达式注入：SpEL、OGNL（Struts2 系列）、MVEL

## 2. 识别特征

> 只描述识别特征，不输出完整可复现 PoC payload。

### 2.1 静态特征（请求层关键指纹）

| 子类 | 关键识别词（部分） | 备注 |
|---|---|---|
| log4j2 JNDI | `${jndi:`、`${jndi:ldap://`、`${jndi:rmi://`、`${jndi:dns://`、`${${::-j}${::-n}${::-d}${::-i}:`（混淆） | 出现在任何 HTTP 头 / 参数 / body / UA / cookie 都要警惕 |
| fastjson 反序列化 | `"@type":`、`"@type":"com.sun.rowset.JdbcRowSetImpl"`、`"@type":"org.apache.commons.collections..."`、`autoTypeSupport` | json 入参中出现 `@type` 关键字几乎都要查 |
| jackson 反序列化 | `"@class":`、`@JsonTypeInfo` 相关 gadget chain | 与 fastjson 类似 |
| xstream 反序列化 | XML 入参含 `<dynamic-proxy>`、`<map>`、`<entry>` + java.lang 类引用 | 需要业务有 xstream 反序列化点 |
| Yaml/SnakeYAML | `!!javax.script.ScriptEngineManager`、`!!java.net.URLClassLoader`、`!!org.springframework.context.support.FileSystemXmlApplicationContext` | 业务接收 yaml 输入要警惕 |
| SpEL | `T(java.lang.Runtime).getRuntime().exec(`、`#{T(...)...}`、`new ProcessBuilder` | Spring 应用中 |
| OGNL（Struts2） | `(#_memberAccess)`、`new java.lang.ProcessBuilder`、`@java.lang.Runtime@getRuntime()`、Struts2 历史 CVE 序列号 | Struts2 系列 CVE |
| Velocity / Freemarker SSTI | `<#assign value="freemarker.template.utility.Execute">`、`#set($x="...")`、`runtime.exec`、`Runtime.getRuntime` | 出现在模板渲染参数中 |
| Jinja2 SSTI | `{{config.__class__`、`{{''.__class__.__mro__`、`__globals__`、`__import__` | Python 模板 |
| 纯命令注入 | `;`、`\|`、`\|\|`、`&&`、`$()`、`` ` ` ``、`;cat /etc/passwd`、`;id`、`;whoami` | 拼接特征 |
| Weblogic T3 / IIOP | T3 协议特征（非 HTTP 层，需要流量识别）、`weblogic.utils.unsyncio.ObjectInputStream` | CVE 系列 |
| Shiro 反序列化 | `rememberMe=` cookie + base64 长串、PKCS5Padding 特征 | CVE-2016-4437 |

通用关键字（任何位置出现都要查）：
- `Runtime.getRuntime()`
- `ProcessBuilder`
- `cmd.exe /c`
- `/bin/sh -c`
- `${IFS}` / `$@` / `$*`（命令行参数变量绕过空格）
- `base64 -d` + `bash`（base64 编码后管道执行）
- `curl ... | bash` / `wget ... | sh`
- `python -c` / `perl -e` / `ruby -e`

### 2.2 行为特征（请求节奏与位置）

- **payload 位置异常**：
  - User-Agent 中出现 `${jndi:` → 几乎肯定攻击（log4j 系列）
  - X-Forwarded-For 中出现 SQL/JNDI payload → 攻击者试探日志组件
  - Referer / Cookie 中出现命令注入特征
  - URL 参数包含 base64 长字符串（解码后是命令）
- **请求节奏**：
  - 短时间内对多个接口尝试相同 payload（典型扫描器）
  - 单接口反复尝试微调的 payload（手工利用）
- **请求 + 主机出网联动**：HTTP 请求收到后，主机立即对外发起异常 DNS / TCP 连接

### 2.3 上下文特征 / 主机侧

- **出站行为异常**：
  - DNS 查询到陌生域名（log4j 攻击常用 `*.dnslog.cn` / `*.ceye.io` / `*.interactsh.com`）
  - 向 1389 / 1099 / 1090 / 389 / 8888 / 4444 / 9999 等非业务端口发起 TCP 连接
  - 异常下载行为：`curl xxx -o /tmp/x`、`wget` 到 `/tmp/`、`/dev/shm/` 等可写目录
- **进程层异常**（最强信号）：
  - **`java` / `php-fpm` / `python` / `node` 进程拉起 `bash` / `sh` / `cmd` / `powershell`**
  - 父进程是 web 应用，子进程是 `whoami` / `id` / `uname -a` / `ifconfig` / `ipconfig` / `cat /etc/passwd`
  - web 进程的子进程链中出现 `curl` / `wget` / `python -c` / `perl -e` / `nc` / `bash -i`
  - 出现 `/tmp/`、`/var/tmp/`、`/dev/shm/`、`/.config/` 目录下的新可执行文件
- **环境变量异常**：`LD_PRELOAD` 出现非业务路径（提权 / 反检测）
- **文件系统异常**：`/tmp/.X11-lock`、`/tmp/.ICE-unix/`、`/var/tmp/.systemd-private-*` 等隐藏路径出现新文件

### 2.4 各子类的独有指纹

#### log4j2 JNDI

- 请求中任意位置出现 `${jndi:`、`${jndi:ldap`、`${jndi:rmi`、`${jndi:dns`、`${jndi:iiop`
- 混淆变体：`${${::-j}${::-n}${::-d}${::-i}:`、`${${lower:j}${lower:n}${lower:d}i:}`
- 主机侧：java 进程发起到外部 LDAP/RMI 端口（1389/1099/389/1090）的连接
- DNS 侧：查询陌生子域名（`*.dnslog.cn` / `*.burpcollaborator.net` / 攻击者自建 dnslog）

#### fastjson 反序列化

- json 入参含 `"@type":"..."` 字段
- 经典 gadget 类名（识别用）：
  - `com.sun.rowset.JdbcRowSetImpl`（JDBC 连接执行）
  - `org.apache.commons.collections.functors.*`
  - `org.springframework.context.support.FileSystemXmlApplicationContext`
  - `com.alibaba.fastjson.JSONObject` 自调用
- 响应行为：业务接口收到含 `@type` 的 JSON 时，可能在内部触发外联

#### SpEL / OGNL

- payload 含 `T(...)` 或 `(#_memberAccess)` 类元编程关键字
- Struts2 系列 CVE 的固定 prefix（如 `%{` 包裹 OGNL）
- Spring Boot Actuator 暴露 `/env` 等端点配合 SpEL 攻击

#### SSTI

- 响应中出现「模板表达式被执行后的结果」（如算术表达式回显结果：`{{7*7}}` → `49`）
- 主机侧：模板渲染进程的子进程链出现 shell

## 3. 日志查询模式（按日志类型）

### 3.1 nginx / apache access.log

```bash
# log4j2 JNDI 通用
grep -iE '\$\{jndi:|\$\{lower:|\$\{upper:|\$\{::-' access.log

# fastjson @type 关键字（注意可能在 POST body 中，需要解析 body）
grep -iE '"@type":|"@class":' access.log

# SpEL / OGNL
grep -iE 'T\(java\.lang|Runtime\.getRuntime|ProcessBuilder|new\s+java\.lang\.ProcessBuilder|@java\.lang\.Runtime' access.log

# 命令注入特征（注意有大量误报，需要 url-decode 后再过）
awk -F'"' '{print $2}' access.log \
  | python3 -c "import sys,urllib.parse; [print(urllib.parse.unquote(l.strip())) for l in sys.stdin]" \
  | grep -iE ';\s*(id|whoami|uname|cat\s+/etc/|ls\s+/|wget\s+|curl\s+)'

# 异常 UA / Header 字段（攻击者常把 payload 塞在 UA / Referer / X-Forwarded-For）
awk -F'"' '/jndi|@type|Runtime/ {print}' access.log
```

### 3.2 auth.log / secure（关联）

```bash
# 短时间内出现的非常规命令执行（webshell/RCE 落地后的横向准备）
grep -E 'sudo:.*COMMAND=' /var/log/auth.log | grep -vE 'TTY=(pts|tty)'

# 新用户 / 新 SSH key 添加
grep -E 'new user|new group|useradd' /var/log/auth.log
```

### 3.3 audit / 进程审计日志（如启用 auditd）

```bash
# 关键：父进程是 java/php-fpm/w3wp，子进程是 bash/sh/cmd
ausearch -k cmd_exec | grep -E 'comm="(bash|sh|cmd|powershell|curl|wget|nc|python|perl)"'

# 进程树关联（找 java 拉起的非业务进程）
ps -ef --forest | grep -A 5 -E 'java|php-fpm|tomcat|w3wp'
```

### 3.4 Windows EventID

- `4688` —— 进程创建，**重点关注 w3wp.exe / java.exe / php-cgi.exe 拉起 cmd.exe / powershell.exe / certutil.exe / bitsadmin.exe**
- `4104` —— PowerShell ScriptBlock 日志，关注混淆 base64 命令
- `5156` —— Windows Filtering Platform 允许的连接，关注 java/w3wp 进程对外网 1389/389 等异常端口的连接
- `1102` —— 安全日志清空

### 3.5 WAF / FW 告警关键字

- `RCE`, `Remote Code Execution`, `Command Injection`, `OS Command Injection`
- `Log4j`, `Log4Shell`, `CVE-2021-44228`, `JNDI Injection`
- `Fastjson`, `Jackson`, `Deserialization`
- `SSTI`, `Template Injection`, `Freemarker`, `Velocity`, `Jinja2`
- `Struts2`, `OGNL Injection`, `SpEL Injection`
- `Shiro`, `Weblogic`

### 3.6 出站连接监控（最关键）

```bash
# 关注 web 服务进程对外联建立的 TCP 连接（特别是非业务端口）
ss -tnp | grep -E 'java|tomcat|nginx|php-fpm|w3wp' | grep -vE ':(80|443|3306|6379|11211)\s'

# DNS 查询日志（如有）—— 关注 dnslog / oast 类外发
grep -iE 'dnslog|interactsh|burpcollaborator|ceye\.io|oast\.online' /var/log/named/*.log
```

## 4. 误报排查清单

| # | 误报特征 | 如何排除 |
|---|---|---|
| 1 | 业务接口本身就传递 JSON（含 `@type` 字段作为业务字段名，非反序列化关键字） | 看 `@type` 后跟的是不是 java 类全限定名（含点号的 ClassName）。业务字段名通常不带点 |
| 2 | 模板教学 / 文档站含 `${jndi:` / `{{7*7}}` 类示例文本（GET 请求获取文档） | 看请求是 GET 文档路径而非 POST 业务接口；上下文是博客 / 教程而非应用入参 |
| 3 | 业务用 freemarker / velocity 模板渲染，参数中合法含 `${...}` 占位符 | 看占位符内的内容是否是合法字段名而非可执行表达式 |
| 4 | 老业务自身就在 logs 中打印 `Runtime.exec` 字符串作为业务日志 | 看是不是 access.log 还是应用日志；access.log 中出现属于异常 |
| 5 | 探测扫描器（绿盟、启明、漏扫）的内部资产扫描 | 与扫描日程对账；扫描器 IP 白名单 |
| 6 | 业务允许的「调试模式」接口（如 `/admin/eval` 给运维用） | 看接口是不是 `/admin/`/`/internal/` 路径；调用方是不是已认证的运维账户；执行时段是不是合理 |
| 7 | CI/CD 调用业务的 health check 接口，URL 中带特殊字符 | 看 UA + 源 IP（CI 节点固定） |
| 8 | 业务用 SpEL 做条件评估（如 Spring Boot 配置中 `@Value("#{...}")`），日志中含 SpEL 表达式 | 看是日志框架自身的输出还是请求层；请求层不应该出现 SpEL |

**误报判定原则**：
- 命令执行类告警**误报率应该极低**（只要规则做得好），所以**宁误标 P1 也不要轻易标 P3**。
- 必须结合主机侧观察：如果**主机没有任何异常子进程 / 异常外联**，且 WAF 拦截了，标 P3 可接受；任何主机侧异常都立即升 P0。

## 5. 关联升级规则

### 5.1 严重性升级

**命令执行类告警基线就是 P1+，不存在 P2/P3。** 因为：
- 一次成功的 RCE 等于主机失陷
- 误报代价远低于漏报代价

- **P1 → P0**（任意一条命中即升）：
  - 主机侧确认存在异常子进程（web 进程拉起 bash/sh/cmd 等）
  - 主机侧确认存在异常外联（DNS / 非业务端口连接）
  - WAF 拦截但有放行（疑似绕过成功）
  - 同一攻击 payload 多次出现且涉及主机有持久化痕迹
  - 落地物（webshell / 木马 / 工具）已确认

### 5.2 模式升级

- **monitor → audit**：任何 RCE 类告警都应该 audit 模式深挖：回看 24h / 72h 该接口和该主机的所有访问
- **audit → ir**：
  - 主机侧确认有异常进程 / 异常文件 / 异常外联 → 立即 ir
  - 即使主机侧暂未发现，但攻击 payload 命中率高、WAF 未完全拦截 → 进 ir 做主动取证

## 6. 止血动作（containment）

### 6.1 网络层（最优先）

| 动作 | 操作要点 | 副作用 | 回退路径 |
|---|---|---|---|
| **阻断主机出网** | 防火墙限制目标主机只能与业务必要的下游通信（DB/缓存/中间件），禁止主动出公网 | 业务功能受影响（如调用外部 API） | 加白名单允许业务必需的出网域名 |
| WAF 加规则 ban payload 特征 | 对 `${jndi:`、`@type:` 等特征加 WAF 规则 | 误伤合法请求（罕见） | 按业务接口加例外 |
| WAF ban 源 IP | 同源 IP 全部 ban | NAT 出口共享时误伤 | 标准流程 |

### 6.2 主机层

| 动作 | 操作要点 | 副作用 | 回退路径 |
|---|---|---|---|
| 隔离主机 | 切到管理 VLAN / 摘负载 | 业务流量切到备机 | 根除完成后回切 |
| **kill 异常进程** | 找到攻击者拉起的子进程及关联 shell，kill 之前先 `cat /proc/<pid>/cmdline`、`ls -la /proc/<pid>/cwd`、`lsof -p <pid>` 取证 | 如果是父进程出问题杀错可能影响业务 | 业务进程异常优先重启 |
| 备份主机当前状态 | 内存 dump / 磁盘快照 + 关键日志快照 | 占用磁盘 | 证据保留 30 天 |
| jstack/jmap dump JVM | 内存马取证必备 | 暂时影响 JVM 性能（短暂） | dump 完即恢复 |

### 6.3 应用层

| 动作 | 操作要点 | 副作用 | 回退路径 |
|---|---|---|---|
| 升级 / 替换易受影响组件 | log4j → 2.17.x+、fastjson → 1.2.83+、Struts2 升到补丁版本 | 需要回归测试 | 灰度发布 |
| 临时禁用易受影响功能 | log4j：设置 `log4j2.formatMsgNoLookups=true` / 删除 `JndiLookup` class；fastjson：禁用 autoType；Struts：禁用 OGNL 危险方法 | 业务可能受影响 | 升级后撤销临时配置 |
| 漏洞接口下线 | 直接关掉受影响接口 | 业务功能不可用 | 修补后回滚 |
| 应用层加 RASP | 部署 RASP 阻断常见 RCE | 性能影响、可能误拦 | 阻断模式 → 监控模式 |

### 6.4 账号层

| 动作 | 操作要点 | 副作用 | 回退路径 |
|---|---|---|---|
| 重置主机所有可登录账户 | 包括应用 service 账户 | 应用配置可能需要更新 | 标准流程 |
| 检查 / 清理 authorized_keys | root + 应用账户 | 误删合法 key 影响运维 | 比对基线 |
| 检查 / 清理 sudoers | `sudo -l -U <user>` 检查所有用户的 sudo 权限 | 误删影响合法 sudo | 比对基线 |
| 检查新增账户 | `cat /etc/passwd` + `lastlog` + 基线比对 | 误删影响 | 比对基线 |

## 7. 根除与恢复（eradication & recovery）

### 7.1 根除步骤

1. **取证为先，再清理**：
   - 内存 dump（重启前必做）
   - 关键日志快照（access / auth / app / db）
   - 磁盘快照
2. **清理落地物**：
   - webshell 文件（参考 webshell.md）
   - `/tmp/`、`/var/tmp/`、`/dev/shm/` 下的可疑文件
   - 容器场景下的容器逃逸痕迹（`/proc/1/cgroup`、宿主机挂载点）
3. **清理持久化**（必须全部走一遍）：
   - crontab（root + 各业务用户）`crontab -l -u <user>`
   - `/etc/cron.d/`、`/etc/cron.*/`、`/var/spool/cron/`
   - `/etc/systemd/system/`、`/usr/lib/systemd/system/` 新增单元
   - `.bashrc`、`.bash_profile`、`/etc/profile.d/*`
   - `authorized_keys`（所有用户）
   - `/etc/ld.so.preload`（LD_PRELOAD 持久化）
   - 启动项：`/etc/rc.local`、`init.d/`、`/etc/inittab`
   - SSH key、登录脚本、shell 别名
4. **修补漏洞**：升级组件 / 配置加固 / WAF 规则三者至少做两个
5. **轮换凭据**：受影响主机上的数据库密码、API key、SSH key、应用 secrets 全部轮换

### 7.2 恢复步骤

- 落地物清晰 + 根除完整 → 加固后回切
- 持久化复杂或不确定彻底清理 → 推荐重装系统 + 还原业务数据（数据需扫描）
- 涉及域控 / 关键业务系统 → 整域 / 整业务系统重建（极端情况）

### 7.3 验证点

1. **进程层验证**：web 进程的子进程树 24h 干净（无 bash/sh/cmd/curl/wget 等）
2. **网络层验证**：主机出网连接列表只剩业务必需，无可疑外联
3. **文件层验证**：基线对比，无未授权新增 / 修改文件
4. **配置层验证**：易受影响组件已升级或加固配置已生效（如 `formatMsgNoLookups=true` 在配置中）
5. **WAF 验证**：原 payload 复发率 0，主动用同类 payload 自测被拦截
6. **持久化验证**：crontab / systemd / authorized_keys / .bashrc 等全部与基线一致

## 8. IOC 提取模板

```json
[
  {
    "type": "ip",
    "value": "192.168.1.xxx",
    "confidence": "high",
    "first_seen": "2026-06-30T14:11:33+08:00",
    "source": "nginx-access.log:line-30421",
    "tag": "rce,attacker-ip,log4j",
    "description": "在 UA 中嵌入 ${jndi:ldap://} 触发 log4j 利用"
  },
  {
    "type": "domain",
    "value": "<attacker>.dnslog.cn",
    "confidence": "high",
    "first_seen": "2026-06-30T14:11:35+08:00",
    "source": "dns-query.log:line-1102",
    "tag": "rce,c2,oast"
  },
  {
    "type": "ip",
    "value": "<external-ldap-server-ip>",
    "confidence": "high",
    "first_seen": "2026-06-30T14:11:35+08:00",
    "source": "conntrack:line-552",
    "tag": "rce,c2,ldap-callback"
  },
  {
    "type": "path",
    "value": "/tmp/.<random>",
    "confidence": "high",
    "first_seen": "2026-06-30T14:11:40+08:00",
    "source": "host:find / -mtime -1",
    "tag": "rce,dropped-binary"
  },
  {
    "type": "hash:sha256",
    "value": "<binary-sha256>",
    "confidence": "high",
    "first_seen": "2026-06-30T14:11:40+08:00",
    "source": "host:/tmp/.<random>",
    "tag": "rce,payload-binary"
  },
  {
    "type": "tool",
    "value": "log4shell-poc",
    "confidence": "high",
    "first_seen": "2026-06-30T14:11:33+08:00",
    "source": "rule:PLB-CE-001",
    "tag": "exploit-tool"
  }
]
```

提取重点：
- 攻击源 IP（HTTP 来源 IP）
- C2 域名 / IP（DNS 回连、LDAP 回连、二阶 payload 下载）
- 落地物路径 + hash
- 利用工具指纹（log4shell PoC、yso、ysoserial、marshalsec）
- 关键 payload 关键字（如 `${jndi:...}` 中的 LDAP server 地址）
- 受影响主机 IP / 域名

---

## rule_id 命名约定

- 前缀：`PLB-CE-NNN`（PlayBook-CommandExecution）

### 已建议规则一览

| rule_id | 规则名 | 触发条件 |
|---|---|---|
| PLB-CE-001 | log4j2 JNDI 注入 | URL/header/body 含 `${jndi:` 或其混淆变体 |
| PLB-CE-002 | fastjson @type 反序列化 | JSON body 含 `"@type":"..."` 且为 java 类名 |
| PLB-CE-003 | jackson @class 反序列化 | JSON body 含 `"@class":"..."` 类型字段 |
| PLB-CE-004 | xstream 反序列化 | XML body 含 `<dynamic-proxy>`/`<map>` + java 类引用 |
| PLB-CE-005 | SnakeYAML 反序列化 | YAML body 含 `!!javax.script`/`!!java.net.URLClassLoader` |
| PLB-CE-006 | SpEL 表达式注入 | URL/body 含 `T(java.lang.Runtime)`/`new ProcessBuilder` |
| PLB-CE-007 | OGNL 注入（Struts2） | URL/body 含 `(#_memberAccess)`/`@java.lang.Runtime@` |
| PLB-CE-008 | SSTI（Freemarker/Velocity） | URL/body 含 `freemarker.template.utility.Execute`/`#set($x="...runtime")` |
| PLB-CE-009 | SSTI（Jinja2） | URL/body 含 `{{config.__class__`/`__globals__`/`__import__` |
| PLB-CE-010 | Shiro 反序列化 | Cookie 含 `rememberMe=` 长 base64 + PKCS5 padding 特征 |
| PLB-CE-011 | 纯命令注入 | URL/body 含 `;\s*(id\|whoami\|uname\|cat\s+/etc)`、`\$\(`、反引号 |
| PLB-CE-012 | web 进程异常子进程 | java/php-fpm/w3wp 拉起 bash/sh/cmd/powershell |
| PLB-CE-013 | web 进程出网异常端口 | java/php 进程连接外网 1389/389/1099/1090/4444/8888 |
| PLB-CE-014 | DNS 回连 OAST | DNS 查询 `*.dnslog.cn`/`*.interactsh.com`/`*.ceye.io`/`*.burpcollaborator.net` |
| PLB-CE-015 | 落地物执行（curl/wget pipe） | 进程审计：`curl\s+\S+\s*\|\s*(bash\|sh)` / `wget\s+\S+\s*\|\s*sh` |
| PLB-CE-016 | base64 命令执行 | 进程命令行含 `base64\s+-d\|.*\|.*bash`/`echo\s+\S{50,}\s*\|\s*base64\s+-d\s*\|\s*bash` |
| PLB-CE-017 | 反弹 shell 特征 | 进程命令行含 `bash\s+-i`、`>&\s*/dev/tcp/`、`nc\s+.*\s+-e`、Python `socket.fromfd` |
