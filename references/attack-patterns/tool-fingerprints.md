# 攻击工具指纹库（扫描器 / DAST / 内网扫描）

> 主流红队工具默认 UA、默认请求路径、默认 payload 特征速查。
> **何时使用**：audit 模式跑 web 日志、monitor 模式分诊扫描类告警时。

只用于识别工具来源，不构成可复现 exploit。

---

## 一、扫描器 UA 指纹表

| rule_id | 工具 | UA 关键字 / 完整 UA 片段 |
|---|---|---|
| SIG-TF-001 | sqlmap | `sqlmap/` / `sqlmap/1.x` |
| SIG-TF-002 | nuclei | `Nuclei -` / `Mozilla/5.0 (compatible; Nuclei` |
| SIG-TF-003 | xray | `xray` / 部分版本无固定 UA，靠 payload 识别 |
| SIG-TF-004 | acunetix / awvs | `acunetix` / `wvs_` / `Acunetix-Aspect` |
| SIG-TF-005 | nessus | `Nessus` / `Tenable.io Scanner` |
| SIG-TF-006 | nikto | `Mozilla/5.00 (Nikto/` |
| SIG-TF-007 | dirsearch | `dirsearch` / 含 `directorysearch` |
| SIG-TF-008 | feroxbuster | `feroxbuster/` |
| SIG-TF-009 | gobuster | `gobuster/` / `Mozilla/5.0 (compatible; Gobuster` |
| SIG-TF-010 | ffuf | `Fuzz Faster U Fool v` / `ffuf/` |
| SIG-TF-011 | wfuzz | `Wfuzz/` |
| SIG-TF-012 | wapiti | `Wapiti/3.x` |
| SIG-TF-013 | appscan | `AppScan` / `HCL_AppScan` |
| SIG-TF-014 | burp suite | `Burp Collaborator` / 默认无固定 UA，靠 payload 识别 |
| SIG-TF-015 | masscan | masscan 默认无 UA（直接 TCP SYN） |
| SIG-TF-016 | zmap | zmap 同 masscan（裸 SYN） |
| SIG-TF-017 | nmap | `Mozilla/5.0 (compatible; Nmap Scripting Engine; ...)` |
| SIG-TF-018 | fscan | fscan 不发 UA（直接 TCP），靠端口扫描行为识别 |
| SIG-TF-019 | wpscan | `WPScan v` |
| SIG-TF-020 | jsky / netsparker | `netsparker` / `JSky` |
| SIG-TF-021 | arachni | `Arachni/v` |
| SIG-TF-022 | zap / OWASP ZAP | `OWASP ZAP` / `ZAP/` |
| SIG-TF-023 | hydra | `hydra/` (https 模块) |
| SIG-TF-024 | crackmapexec / nxc | UA `python-requests/x.x` + 行为特征 |
| SIG-TF-025 | impacket | python-requests + SMB 行为 |
| SIG-TF-026 | pocsuite | `pocsuite3/` |
| SIG-TF-027 | afrog | `afrog/` |
| SIG-TF-028 | go-poc | `go-poc/` |
| SIG-TF-029 | sn1per | `sn1per` |
| SIG-TF-030 | metasploit auxiliary | `Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)` 老 IE UA + 行为 |
| SIG-TF-031 | crawlergo | `crawlergo` |
| SIG-TF-032 | rad | `rad/v` |
| SIG-TF-033 | httpx | `Mozilla/5.0 (compatible; httpx)` |
| SIG-TF-034 | katana | `Mozilla/5.0 (compatible; Katana ...)` |

---

## 二、工具默认请求路径

通常蓝队看到下面这些路径密集出现 → 高置信扫描行为。

| rule_id | 路径 | 触发工具 / 用途 |
|---|---|---|
| SIG-TF-101 | `/.git/HEAD` `/.git/config` `/.git/index` | 代码泄露探测 |
| SIG-TF-102 | `/.env` `/.env.bak` `/.env.local` | 配置泄露 |
| SIG-TF-103 | `/.svn/entries` `/.svn/wc.db` | SVN 泄露 |
| SIG-TF-104 | `/.DS_Store` `/.idea/workspace.xml` | IDE 泄露 |
| SIG-TF-105 | `/wp-admin/admin-ajax.php` `/wp-login.php` `/wp-content/` | WP 探测 |
| SIG-TF-106 | `/actuator` `/actuator/env` `/actuator/heapdump` `/actuator/health` | Spring Boot 暴露 |
| SIG-TF-107 | `/manager/html` `/host-manager/html` | Tomcat 管理后台 |
| SIG-TF-108 | `/console` `/jolokia/list` | jboss / weblogic / spring console |
| SIG-TF-109 | `/druid/index.html` `/druid/login.html` | Druid 监控页 |
| SIG-TF-110 | `/swagger-ui.html` `/swagger-resources` `/v2/api-docs` | API doc 暴露 |
| SIG-TF-111 | `/phpmyadmin/` `/pma/` `/_phpmyadmin/` | PMA |
| SIG-TF-112 | `/jenkins/script` `/jenkins/computer/` | Jenkins 控制 |
| SIG-TF-113 | `/server-status` `/server-info` | apache mod_status |
| SIG-TF-114 | `/nacos/` `/nacos/v1/auth/users` | Nacos 默认账户 |
| SIG-TF-115 | `/solr/admin/cores` | Solr 暴露 |
| SIG-TF-116 | `/api/v1/namespaces/` `/api/v1/pods` | k8s API 探测 |
| SIG-TF-117 | `/aliyun_assist_service` / 云内元数据探测路径 | SSRF 元数据探测 |
| SIG-TF-118 | `/_search?q=*` `/_cluster/health` | ES 暴露 |
| SIG-TF-119 | `/HNAP1/` | 路由器 / IoT 探测 |
| SIG-TF-120 | `/cgi-bin/luci` | OpenWRT 路由 |
| SIG-TF-121 | `/login.action` `/struts/` | Struts2 探测 |
| SIG-TF-122 | `/seeyon/htmlofficeservlet` `/seeyon/webmail.do` | 致远 OA |
| SIG-TF-123 | `/yyoa/common/js/menu/test.jsp` | 致远 OA |
| SIG-TF-124 | `/api/lvyou/yzm.jsp` `/weaver/` `/wcs/` | 泛微 OA |
| SIG-TF-125 | `/system/ui/loginbg.jsp` | 蓝凌 OA |
| SIG-TF-126 | `/oa_html/` `/htmlportal/` | 用友 OA / NC |
| SIG-TF-127 | `/dwr/` `/dwr/exec` | DWR 接口暴露 |

---

## 三、工具默认 payload pattern

### 3.1 xray 测试字符串
| rule_id | 特征 |
|---|---|
| SIG-TF-201 | header `X-Forwarded-For: xray` / `X-Client-IP: xray` |
| SIG-TF-202 | xray DNSLog 域名段 `*.dnslog.cn` / xray 自带 reverse dns service |
| SIG-TF-203 | xray RCE PoC 含字符串 `xray-shellcode-` / `xshell ` |
| SIG-TF-204 | xray SSRF PoC 含 `http://xx.xx.xx.xx:port/xray-ssrf` |

### 3.2 nuclei DAST 字符串
| rule_id | 特征 |
|---|---|
| SIG-TF-211 | nuclei oast 域：`*.oast.pro` / `*.oast.site` / `*.oast.fun` / `*.interactsh.com` |
| SIG-TF-212 | header `Nuclei-Test` |
| SIG-TF-213 | nuclei 探测路径含 `/nuclei-test-{random}` |

### 3.3 sqlmap 特殊语法
| rule_id | 特征 |
|---|---|
| SIG-TF-221 | `AND (SELECT * FROM (SELECT(SLEEP(5)))xxxx)` 嵌套子查询模式 |
| SIG-TF-222 | `') WAITFOR DELAY '0:0:5'--` MSSQL 延时 |
| SIG-TF-223 | 注释组合 `/*!50000UNION*/` MySQL hint |
| SIG-TF-224 | URL 参数后追加 `qIqMr` / `gFhYZ` 等 sqlmap boundary 字符串 |
| SIG-TF-225 | `(case when (xxx) then 1 else 0 end)` 盲注 |

### 3.4 通用 RCE / SSRF 探测
| rule_id | 特征 |
|---|---|
| SIG-TF-231 | `${jndi:ldap://`、`${jndi:rmi://`（log4j） |
| SIG-TF-232 | OGNL `%{` `#context` `@java.lang.Runtime@getRuntime` |
| SIG-TF-233 | SpEL `T(java.lang.Runtime).getRuntime().exec(` |
| SIG-TF-234 | SSRF target：`169.254.169.254` / `100.100.100.200`（阿里云元数据） / `metadata.google.internal` |
| SIG-TF-235 | gopher / dict / file scheme：`gopher://` `dict://` `file:///etc/passwd` |
| SIG-TF-236 | path traversal：`../../../../etc/passwd` / 编码 `%2e%2e%2f` / `..\\..\\..\\windows\\win.ini` |

### 3.5 反序列化探测
| rule_id | 特征 |
|---|---|
| SIG-TF-241 | fastjson：`{"@type":"com.sun.rowset.JdbcRowSetImpl"`、`"@type":"org.apache.tomcat.dbcp.dbcp2.BasicDataSource"` |
| SIG-TF-242 | jackson polymorphic：`"@class":"`  |
| SIG-TF-243 | Java 原生 serialize 起始字节 `ac ed 00 05` 出现在 body |
| SIG-TF-244 | Shiro rememberMe cookie 长度异常（>= 256 字符 base64） |

---

## 四、国内常见扫描器附加特征

| rule_id | 工具 | 特征 |
|---|---|---|
| SIG-TF-301 | pocsuite3 | UA `pocsuite3/` + 默认 path 含 `/pocsuite3` |
| SIG-TF-302 | afrog | `User-Agent: afrog/v` + reverse domain `.afrog.io` |
| SIG-TF-303 | TideFinger | path 含 `/tidefinger/` 探测 |
| SIG-TF-304 | EHole | UA 中含 `EHole/` |
| SIG-TF-305 | Goby | UA `goby/` + 高频指纹路径 `/favicon.ico` 哈希探测 |
| SIG-TF-306 | yakit | 默认 UA `yaklang.io/yakit` |
| SIG-TF-307 | wih | UA `wih/v` |
| SIG-TF-308 | observer_ward | UA `observer_ward/` |

---

## 五、内网扫描工具行为特征（非 UA，靠流量）

| rule_id | 工具 | 行为 |
|---|---|---|
| SIG-TF-401 | fscan | 短时间内对 /16 / /24 段大量 22 / 445 / 3306 / 6379 / 80 / 443 / 1433 端口探测 |
| SIG-TF-402 | nmap -sS / -sV | SYN scan 行为，TTL 异常，部分版本 UA `Nmap Scripting Engine` |
| SIG-TF-403 | masscan | 极快 SYN 扫描，srcport 随机化，TTL=64/128 等 |
| SIG-TF-404 | rustscan | 类似 masscan，先 SYN 后调 nmap |
| SIG-TF-405 | ladon / kscan / gosint / yasso | 国内常见内网工具，含 webshell / brute / 漏洞利用模块；流量上类似 fscan |
| SIG-TF-406 | impacket-smbexec / wmiexec / psexec | SMB 49152+ 高端口 + 服务安装 EID 7045 + 命名管道 |
| SIG-TF-407 | hydra / medusa | 短时间对单服务高频认证失败 |

---

## 六、误报场景

- 内部安全部门日常扫描（dirsearch / nuclei）使用相同 UA — 需对比源 IP 白名单
- CI/CD pipeline 中的 OWASP ZAP 自动安全测试，源 IP 固定
- 业务 SDK 同名 `python-requests/x.x` UA — 需结合行为分量识别
- 自动化巡检系统访问 `/actuator/health`、`/server-status` 是合法的健康检查
- 安全代理 (Cloudflare / WAF) 反向探测自己保护的资产，UA 字段固定
- 旧版业务系统真实使用 UA = `Mozilla/4.0 (compatible; MSIE 6.0; ...)` —— 不要因 UA 老旧就判定 MSF

---

## 七、与统一输出契约对接

- `category` = `scanner`（命中扫描器 UA / 路径） 或 `recon`（端口扫描 / 资产探测）或 `cve_exploit`（命中具体漏洞）
- `severity` 默认 P3，命中 sensitive path + 200 状态码 → 升 P1
- `iocs.ua` / `iocs.path` / `iocs.tool` 必填
- `rule_id` 引用上表 SIG-TF-xxx

---

## 八、规则总览

总计定义 rule_id：
- SIG-TF-001 ~ SIG-TF-034（扫描器 UA，34 条）
- SIG-TF-101 ~ SIG-TF-127（默认路径，27 条）
- SIG-TF-201 ~ SIG-TF-244（payload pattern，22 条 = 4+3+5+6+4）
- SIG-TF-301 ~ SIG-TF-308（国内扫描器，8 条）
- SIG-TF-401 ~ SIG-TF-407（内网扫描行为，7 条）

合计 **98 条**。
