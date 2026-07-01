# Web Access Log 字段速查（nginx / apache / IIS）

> 蓝队 audit / monitor 模式下查 nginx access.log、apache access.log、IIS W3C log 时随手翻。
> **何时使用**：拿到一份 web 访问日志，需要快速定位关键字段、写 grep/awk 抽取异常行时。

---

## 一、字段速查表（厂商无关化）

| 标准字段 | nginx default (`$var`) | apache combined (`%var`) | IIS W3C (`#Fields`) |
|---|---|---|---|
| 客户端 IP | `$remote_addr` | `%h` / `%a` | `c-ip` |
| 远程用户 | `$remote_user` | `%u` | `cs-username` |
| 时间戳 | `$time_local` / `$time_iso8601` | `%t` | `date time` |
| 请求方法 | `$request_method` | `%m` | `cs-method` |
| 请求 URI | `$request_uri` / `$uri` | `%U%q` | `cs-uri-stem cs-uri-query` |
| 请求行 | `$request` | `%r` | (合成) |
| HTTP 版本 | `$server_protocol` | `%H` | `cs-version` |
| 状态码 | `$status` | `%>s` | `sc-status` |
| 响应字节 | `$body_bytes_sent` | `%b` / `%B` | `sc-bytes` |
| Referer | `$http_referer` | `%{Referer}i` | `cs(Referer)` |
| User-Agent | `$http_user_agent` | `%{User-Agent}i` | `cs(User-Agent)` |
| XFF | `$http_x_forwarded_for` | `%{X-Forwarded-For}i` | `cs(X-Forwarded-For)` |
| 请求耗时 | `$request_time` | `%D`（μs） | `time-taken`（ms） |
| upstream 耗时 | `$upstream_response_time` | — | — |
| Server Name | `$server_name` / `$host` | `%v` | `cs-host` |
| 端口 | `$server_port` | `%p` | `s-port` |
| 子状态 | — | — | `sc-substatus` |
| Win32 错误 | — | — | `sc-win32-status` |

---

## 二、常见日志格式变体

### 2.1 nginx 默认 `combined`

```
log_format combined '$remote_addr - $remote_user [$time_local] '
                    '"$request" $status $body_bytes_sent '
                    '"$http_referer" "$http_user_agent"';
```
样例：`192.168.1.10 - - [30/Jun/2026:10:15:23 +0800] "GET /api/user HTTP/1.1" 200 1532 "-" "Mozilla/5.0"`

### 2.2 apache combined

```
LogFormat "%h %l %u %t \"%r\" %>s %b \"%{Referer}i\" \"%{User-Agent}i\"" combined
```

### 2.3 nginx JSON log（云原生常见）

```
log_format json escape=json '{"ts":"$time_iso8601","ip":"$remote_addr","method":"$request_method",'
  '"uri":"$request_uri","status":$status,"size":$body_bytes_sent,'
  '"ua":"$http_user_agent","xff":"$http_x_forwarded_for","rt":$request_time}';
```

### 2.4 IIS W3C（默认字段顺序）

```
#Fields: date time s-ip cs-method cs-uri-stem cs-uri-query s-port cs-username c-ip cs(User-Agent) cs(Referer) sc-status sc-substatus sc-win32-status time-taken
```

---

## 三、常用 awk / grep 模板

约定：`ACCESS=/var/log/nginx/access.log`，nginx combined 格式；apache/IIS 列号需要按各自字段顺序调整。

### 3.1 按状态码筛选（4xx / 5xx 突增）
```bash
awk '$9 ~ /^[45]/ {print $0}' $ACCESS | head
awk '$9 ~ /^[45]/ {print $9}' $ACCESS | sort | uniq -c | sort -rn
```

### 3.2 UA 黑名单过滤（扫描器特征 UA）
```bash
grep -EiI 'sqlmap|nuclei|nikto|acunetix|nessus|dirsearch|gobuster|ffuf|wfuzz|fscan|xray|awvs|wpscan|masscan' $ACCESS
```

### 3.3 提取 4xx 突增的 Top IP（多为扫描）
```bash
awk '$9 ~ /^4/ {print $1}' $ACCESS | sort | uniq -c | sort -rn | head -20
```

### 3.4 访问敏感路径的客户端
```bash
grep -EiI ' (GET|POST) [^ ]*(\\.git|\\.env|\\.svn|\\.DS_Store|wp-admin|phpmyadmin|actuator|console|manager/html|druid|swagger|/\\.\\./|//+)' $ACCESS
```

### 3.5 长 URL（≥ 500 字节，疑似 payload 注入）
```bash
awk 'length($7) >= 500 {print NR": "$1" "$7}' $ACCESS | head
```

### 3.6 同 IP 高频访问（阈值法，>200 次/天）
```bash
awk '{print $1}' $ACCESS | sort | uniq -c | awk '$1 >= 200 {print}' | sort -rn
```

### 3.7 异常 HTTP method（PUT / PATCH / CONNECT / TRACE / DELETE / OPTIONS 滥用）
```bash
awk '$6 ~ /"(PUT|PATCH|CONNECT|TRACE|DELETE|OPTIONS|PROPFIND|MKCOL)/ {print}' $ACCESS
```

### 3.8 大响应（>10MB，疑似数据外传）
```bash
awk '$10+0 > 10485760 {print $1, $7, $10}' $ACCESS | sort -k3 -rn | head
```

### 3.9 同 IP × 多 URI（路径爆破特征：1 个 IP 撞 ≥50 个不同 URI）
```bash
awk '{print $1, $7}' $ACCESS | sort -u | awk '{print $1}' | sort | uniq -c | awk '$1 >= 50' | sort -rn
```

### 3.10 按时间窗口切片（取 10:00-12:00 段）
```bash
awk '$4 >= "[30/Jun/2026:10:00:00" && $4 <= "[30/Jun/2026:12:00:00"' $ACCESS
```

### 3.11 提取 POST 大 body（潜在 webshell 上传 / 反序列化）
```bash
awk '$6 ~ /"POST/ && $10+0 > 4096 {print $1, $7, $10}' $ACCESS
```

### 3.12 同 IP 命中多种规则（关联升级）
```bash
grep -E "192\\.168\\.1\\.xxx" $ACCESS | awk '{print $7}' | sort -u | wc -l
```

### 3.13 提取 referer 为空且 UA 异常（脚本特征）
```bash
awk '$11 == "\"-\"" && length($12) < 20 {print}' $ACCESS | head
```

### 3.14 JSON log 字段提取（jq）
```bash
jq -r 'select(.status >= 400) | "\(.ip) \(.status) \(.uri)"' access.json.log | sort | uniq -c | sort -rn
```

---

## 四、字段使用陷阱

1. **XFF 可伪造**：`X-Forwarded-For` 字段对外暴露时不可信，需结合接入层 IP 一同保存。
2. **time_local 与 time_iso8601**：跨时区核查时优先用 iso8601；time_local 含时区偏移但解析较麻烦。
3. **$request 拆解**：`$request` = method + uri + protocol 三段空格分隔，含特殊字符（如未编码空格）时 awk 列号会错位 —— 推荐用 `$request_method` / `$request_uri` 替代。
4. **body_bytes_sent vs bytes_sent**：前者不含 header；统计数据外传量请用 `$bytes_sent` 或 `%O`（apache）。
5. **upstream_response_time** 是反代/网关日志独有，0 或 `-` 表示未走 upstream。
6. **IIS sc-substatus**：状态码细化，例如 401.2（认证模式不匹配）；`sc-win32-status` 是 OS 错误号，定位文件权限问题用得到。

---

## 五、与异常清单关联

抽到的字段建议落到统一 schema（参考 SKILL.md 第 4 节）：
- `evidence` ← 完整一行日志（脱敏后）
- `source` ← 文件路径 + 行号
- `iocs.ip` ← `$remote_addr`（私网保留尾段）
- `iocs.ua` ← `$http_user_agent`
- `iocs.path` ← `$request_uri`
- `rule_id` ← 命中的 nginx_anomaly 规则号
