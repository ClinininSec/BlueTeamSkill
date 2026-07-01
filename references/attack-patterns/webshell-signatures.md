# WebShell 特征库

> 多语言 webshell 静态特征、流量特征、行为特征速查。
> **何时使用**：audit 模式跑 `webshell_scan.py` 前后核对、ir 模式人工核验可疑文件时。

所有规则只用于"识别"，特征碎片化呈现，不构成可复现 PoC。

---

## 一、PHP WebShell 特征

### 1.1 静态特征（落盘文件）

| rule_id | 特征 | 触发位置 | FP note |
|---|---|---|---|
| SIG-WS-001 | `eval(` + 用户可控参数（`$_GET / $_POST / $_REQUEST / $_COOKIE`） | 文件正文 | 极少合法用途，命中即可疑 |
| SIG-WS-002 | `assert(` + 用户可控参数 | 文件正文 | PHP 7+ 已弃用为关键字，遗留代码偶见 |
| SIG-WS-003 | `preg_replace(.., '/e')` 修饰符 | 文件正文 | PHP 7+ 已禁用，旧站点偶见 |
| SIG-WS-004 | `system / exec / passthru / shell_exec / popen / proc_open` + 用户输入 | 文件正文 | 部分管理工具合法用途 |
| SIG-WS-005 | `${_GET[xxx]}` / `${_POST[xxx]}` 变量变量动态调用 | 文件正文 | 极少正常用途 |
| SIG-WS-006 | 一句话短型：`<?php eval($_POST['x']);?>` 长度 ≤ 60 字节 | 单文件 | 命中即可疑 |
| SIG-WS-007 | base64_decode + eval / create_function 组合 | 文件正文 | 加密 webshell 常用 |
| SIG-WS-008 | gzinflate / gzuncompress / str_rot13 / hex2bin 嵌套包裹 | 文件正文 | 解码套娃多层 → 高度可疑 |
| SIG-WS-009 | `chr(116).chr(105)...` 字符拼接 + eval | 文件正文 | obfuscation 常见 |
| SIG-WS-010 | `@` 抑错前缀 + 危险函数（`@eval` / `@system`） | 文件正文 | 合法代码使用 `@` 抑错较少 |
| SIG-WS-011 | 文件名异常：`shell.php` / `cmd.php` / `1.php` / `0.php` / `phpinfo.php` 出现在 upload / image / static 目录 | 路径 | 误传可能 |
| SIG-WS-012 | 文件扩展异常：`.php.jpg` / `.php5` / `.phtml` / `.phps` / `.pht` 出现在 upload 目录 | 路径 | 部分 CMS 配置 |
| SIG-WS-013 | 双扩展 + 短内容（`xxx.php.jpg` < 1 KB） | 路径 + size | 命中即高危 |
| SIG-WS-014 | 哥斯拉默认 key payload 静态特征：固定 base64 头部 + AES/XOR 加密块 | 文件正文 | 命中即可疑 |
| SIG-WS-015 | 冰蝎默认 key 静态特征：classloader 写入 / `Cipher.getInstance("AES")` 模式 | 文件正文 | 主要看流量层 |

### 1.2 行为特征

| rule_id | 特征 | 来源 |
|---|---|---|
| SIG-WS-101 | `nginx/apache/php-fpm` 进程 fork 出 `bash/sh/python` 子进程 | auditd / Sysmon |
| SIG-WS-102 | web 进程写入 `.php / .jsp / .aspx` 文件到 webroot | inotify / auditd |
| SIG-WS-103 | web 进程发起对外网（非 RPM repo / 业务 API）TCP 连接 | netflow |
| SIG-WS-104 | webroot 下短时间内新增同名 + 后缀变种文件 | filesystem 监控 |

---

## 二、JSP / Java WebShell 特征

### 2.1 静态特征

| rule_id | 特征 | 触发位置 |
|---|---|---|
| SIG-WS-201 | `Runtime.getRuntime().exec(` + request 参数 | jsp / class |
| SIG-WS-202 | `ProcessBuilder(` 含用户输入参数 | jsp / class |
| SIG-WS-203 | `Class.forName(` + 反射调用 + base64 解密 | jsp / jar |
| SIG-WS-204 | `sun.misc.BASE64Decoder` / `Base64.getDecoder()` + `defineClass` | jsp / jar |
| SIG-WS-205 | `java.lang.reflect` + `setAccessible(true)` + 隐藏方法调用 | jsp / class |
| SIG-WS-206 | `Cipher.getInstance("AES")` + `doFinal` + `request.getInputStream` | jsp 文件 |
| SIG-WS-207 | 哥斯拉 JSP 加密 payload：`pass=key&xc=...` 参数特征 + AES base64 块 | 流量 |
| SIG-WS-208 | 冰蝎 JSP：`classloader.loadClass(...)`，`xc / pass` 参数 | 流量 |
| SIG-WS-209 | 内存马 - Filter 注入痕迹：`org.apache.catalina.core.StandardContext.filterMap` 异常 entry | JVM dump / 反射查询 |
| SIG-WS-210 | 内存马 - Listener 注入：异常 `ServletRequestListener` 实现类 | JVM 探针 |
| SIG-WS-211 | 内存马 - Interceptor 注入（Spring）：异常 `HandlerInterceptor` 实现 | JVM 探针 |
| SIG-WS-212 | 内存马 - Servlet 注入：动态 register Servlet，未在 web.xml 声明 | runtime |

### 2.2 行为特征

| rule_id | 特征 |
|---|---|
| SIG-WS-251 | tomcat / jboss / weblogic 进程拉起 bash / sh | 
| SIG-WS-252 | JVM 加载的类含异常包名（如 `com.metasploit.*`、`org.apache.coyote.tomcat.A` 这类伪装包） |
| SIG-WS-253 | 同一接口 `Content-Type: application/octet-stream` 高频 POST 但响应也是 octet-stream（typical 哥斯拉） |

---

## 三、ASPX / .NET WebShell 特征

### 3.1 静态特征

| rule_id | 特征 | 触发位置 |
|---|---|---|
| SIG-WS-301 | `Server.CreateObject("WScript.Shell")` | aspx 文件 |
| SIG-WS-302 | `Eval(Request[` / `Eval(Request.Form[` | aspx |
| SIG-WS-303 | `cmd.Process` / `System.Diagnostics.Process.Start` + 用户输入 | aspx / cs |
| SIG-WS-304 | `<%@ Page Language="JScript" %>` 罕见混用 | aspx |
| SIG-WS-305 | base64 解码后 `Assembly.Load` 动态加载 | aspx / cs |
| SIG-WS-306 | 一句话型：`<%@Page Language="C#"%><% System.Diagnostics.Process.Start(Request["c"]); %>` | aspx |

### 3.2 行为特征

| rule_id | 特征 |
|---|---|
| SIG-WS-351 | `w3wp.exe` 拉起 `cmd.exe / powershell.exe`（Sysmon EventID 1） |
| SIG-WS-352 | IIS 工作进程写入 `.aspx / .ashx / .asmx` 到 wwwroot |

---

## 四、流量层特征

| rule_id | 特征 | 协议层 |
|---|---|---|
| SIG-WS-401 | 哥斯拉默认 key MD5 前 16 字节常量串：`3c6e0b8a9c15224a` 等已知默认 key 派生值 | HTTP body |
| SIG-WS-402 | 哥斯拉 PHP：固定起始 base64 段 + 加密块尾 | HTTP body |
| SIG-WS-403 | 冰蝎 2.x 默认 key `rebeyond`，3.x 默认 `e45e329feb5d925b` 派生 | HTTP body |
| SIG-WS-404 | 蚁剑 default UA：`antSword/v` / 含 `antSword` | HTTP header |
| SIG-WS-405 | 蚁剑请求体特征：`Form data` 含大量 base64 + 关键字 `@ini_set` / `@set_time_limit` 反射 | HTTP body |
| SIG-WS-406 | 异常 `Content-Type: application/octet-stream` 用于 POST 请求 + 大 body | HTTP header |
| SIG-WS-407 | 同一 URI 短时间高频 POST，每次响应 size 差异大（命令交互特征） | 行为 |
| SIG-WS-408 | POST 请求 body 长度 ≥ 1024 但 URI 是单 jsp/php 文件（非常规 API） | 流量 |
| SIG-WS-409 | Cookie 或 Header 中夹带超长 base64（夹带 payload） | HTTP header |
| SIG-WS-410 | 响应体 base64 解码后含 `id\\nuid=`、`whoami` 输出 pattern | HTTP body |

---

## 五、行为特征（主机 + 网络）

| rule_id | 特征 | 数据源 |
|---|---|---|
| SIG-WS-501 | web 进程作为父进程拉起 shell / curl / wget / nc / python -c | auditd / Sysmon |
| SIG-WS-502 | web 进程在 `/tmp /var/tmp /dev/shm` 写入可执行文件 | auditd / fim |
| SIG-WS-503 | web 进程出网到非业务相关公网 IP（剔除已知 CDN / repo） | netflow |
| SIG-WS-504 | web 进程 `connect()` 到 4444 / 1337 / 8888 / 6666 等反弹常用端口 | netflow / strace |
| SIG-WS-505 | webroot 出现近 1h 内新写入文件 + 用户 = web 进程账户 | filesystem |
| SIG-WS-506 | `.htaccess` 被修改新增 PHP handler 或 RewriteRule | filesystem |

---

## 六、误报场景

- **CMS 模板引擎**：phpcms / dedecms 等模板渲染含 eval 是合法的，需结合调用上下文（是否被外部 GET 触发）。
- **管理工具**：phpmyadmin / adminer 等数据库管理工具含 `system` 调用是设计如此，看路径和权限。
- **dev 调试代码遗留**：开发者写 `<?php echo phpinfo(); ?>` 临时测试，文件名 `info.php / phpinfo.php`。
- **自动化部署脚本**：部分发布脚本通过 web 写文件到 webroot，但来源 IP 固定 + 行为重复 → 白名单。
- **业务正常 octet-stream 上传**：文件上传服务、API 二进制接口。
- **JSP 内存马 false positive**：APM / 监控类 agent（Pinpoint、SkyWalking）也通过反射注入 Interceptor —— 需对比已知白名单 agent 包名。

---

## 七、与统一输出契约对接

每条检测到的 webshell 候选生成 1 条 schema 条目：
- `category` = `webshell`
- `severity` 静态匹配（SIG-WS-0xx / SIG-WS-2xx / SIG-WS-3xx）→ P1，加上行为/流量证据后升 P0
- `evidence` = 关键字命中行（脱敏） + 文件路径 + 行号
- `rule_id` = 上表 SIG-WS-xxx
- `iocs` = `tool:webshell:godzilla` / `tool:webshell:behinder` / `tool:webshell:antsword` 等 tag

---

## 八、规则总览

总计定义 rule_id：
- SIG-WS-001 ~ SIG-WS-015（PHP 静态，15 条）
- SIG-WS-101 ~ SIG-WS-104（PHP 行为，4 条）
- SIG-WS-201 ~ SIG-WS-212（JSP 静态/内存马，12 条）
- SIG-WS-251 ~ SIG-WS-253（JSP 行为，3 条）
- SIG-WS-301 ~ SIG-WS-306（ASPX 静态，6 条）
- SIG-WS-351 ~ SIG-WS-352（ASPX 行为，2 条）
- SIG-WS-401 ~ SIG-WS-410（流量，10 条）
- SIG-WS-501 ~ SIG-WS-506（主机行为，6 条）

合计 **58 条**。
