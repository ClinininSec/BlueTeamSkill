# Playbook: SQL 注入处置剧本

> 适用模式：monitor / audit / ir
> 难度：★★★☆☆
> 平均处置时间：30-90 分钟

## 1. 攻击概述

- **攻击者目的**：通过在 Web 应用的输入位置拼接 SQL 语义，破坏原查询逻辑，实现：（1）数据库内容读取/导出；（2）写文件落地 webshell（堆叠查询 + INTO OUTFILE）；（3）数据库提权（UDF / 命令执行）；（4）拖库 / 数据外传。
- **典型攻击链位置**：
  - MITRE ATT&CK 战术映射：`Initial Access (T1190 Exploit Public-Facing Application)` → `Credential Access (T1212)` → `Collection (T1213 Data from Information Repositories)` → `Exfiltration (T1041)`
  - 多数 SQL 注入在初始接入阶段被利用，但也常用于「拖库」这种数据动作。
- **护网期间出现频次**：高。SQL 注入告警噪音极大（绝大部分是扫描器探测），真实命中比例不高但**影响极大**——一次成功的拖库就是整场护网的失分点。
- **常见入口**：
  - 老 OA / CMS 系统（很多 jsp / asp 系统至今未参数化）
  - 业务自研接口（特别是搜索 / 报表 / 多条件查询）
  - 管理后台（任意场景）
  - API 接口（GraphQL / RESTful 的过滤参数）

## 2. 识别特征

> 只描述识别特征，不输出完整可复现 payload。

### 2.1 静态特征（payload 形态，仅识别用）

注入分类与「特征关键字」（注意：实际 payload 会大量混入空白、注释、编码混淆）：

| 类型 | 关键识别词（部分） | 简述 |
|---|---|---|
| Union-based | `UNION SELECT`、`UNION ALL SELECT`、列数对齐特征如 `1,2,3,...,NULL,NULL` | 直接读回内容 |
| Boolean-based | `AND 1=1` / `AND 1=2`、`AND ASCII(...)>` 类逐字符判断 | 盲注，看响应差异 |
| Time-based | `SLEEP(N)`、`BENCHMARK(`、`pg_sleep(`、`WAITFOR DELAY` | 盲注，看响应延迟 |
| Error-based | `extractvalue(`、`updatexml(`、`floor(rand`、`exp(~`、`geometrycollection(` | 利用报错回显内容 |
| Stacked queries | `;DROP`、`;INSERT`、`;UPDATE`、`;SHUTDOWN`、`; EXEC` | 多语句堆叠 |
| OOB（带外） | `LOAD_FILE('//x.x.x.x/`、`xp_dirtree`、`UNC path`、DNS 注入域名 | 通过外发请求回传 |
| 系统命令 | `xp_cmdshell`、`sys_exec`、`sys_eval`、UDF lib_mysqludf_sys | 数据库执行系统命令 |

通用关键字（请求中含以下任一即应进入候选）：
- `select`、`union`、`from`、`where`、`order by`（在非搜索类参数中出现 SQL 关键字）
- `information_schema`、`mysql.user`、`pg_user`、`sysobjects`、`sys.tables`
- `concat(`、`group_concat(`、`hex(`、`unhex(`
- 经典探测尾巴：`'`、`"`、`)`、`--`、`#`、`/*`、`*/`、`;%00`

### 2.2 工具指纹

- **sqlmap**：
  - 默认 UA：`sqlmap/1.x.x.x#stable (https://sqlmap.org)`（新版可改）
  - 默认 Cookie 注入测试位置带 `sqlmap` 标记
  - 探测序列特征：先 1=1/1=2、再 ORDER BY 1/ORDER BY 100、再 UNION 列数枚举
  - payload 中常出现 `qwerty` / `RkZsa` / `RkZsa` 等固定 marker（用于判断回显）
- **xray / nuclei / w13scan / pocsuite**：
  - UA 含工具名（多数默认带）
  - 同 URI 短时间内大量变体 payload（典型扫描器签名）
- **manual exploit**：
  - 节奏不规律，单点反复尝试同一 payload 微调
  - 来源 IP 与 WAF/IDS 告警源一致

### 2.3 WAF 绕过特征（识别用）

注意以下特征本身就是「攻击者在绕 WAF」的强信号：
- **大小写混淆**：`SeLeCt`、`UnIoN`、`SeLeCt FROM`
- **注释混淆**：`SE/**/LECT`、`UNI/*xxx*/ON`、`/*!50000SELECT*/`（MySQL 内联注释）
- **空白替换**：`SELECT/**/FROM`、`%09`（TAB）、`%0a`（换行）、`%0c`
- **编码套娃**：双 url-encode（`%2527` = `%27` = `'`）、unicode 编码（`'`）、HTML 实体（`&#39;`）
- **关键字拆分**：`UNI`+`ON`、`SEL`+`ECT`，配合参数污染或 ASCII 拼接
- **协议绕过**：HPP (HTTP Parameter Pollution，同一参数多次出现)、JSON 编码绕过、multipart/form-data 绕过

### 2.4 响应特征（业务侧反向印证）

- **响应包含敏感关键字**：
  - 数据库错误信息：`SQL syntax`、`mysql_fetch`、`ORA-`、`PostgreSQL.*ERROR`、`MSSQL`
  - 表名 / 字段名：`information_schema`、`users`、`admin`、`password`、`token`
  - 大段疑似拖库内容（很多行 + 大量逗号分隔，看起来像 CSV）
- **响应大小异常**：同一接口某次响应 body 比常态大 10 倍以上
- **响应时间异常**：单次请求耗时显著超过 baseline（time-based 注入命中典型特征）
- **响应状态码反复变化**：同 URI 反复 200/500 交替（盲注的差异化探测）

### 2.5 数据库侧识别

- 慢查询日志（slow.log）：异常 SQL（含 `information_schema.columns`、超长 `OR`/`AND` 链、`SLEEP(N)`）
- 错误日志（error.log）：高频 syntax error
- 审计日志（如启用）：非业务用户的 SELECT FROM `information_schema.*`、`mysql.user`
- `general_log`：业务接口对应 SQL 中出现明显的拼接痕迹（参数位有 SQL 关键字）

## 3. 日志查询模式（按日志类型）

### 3.1 nginx / apache access.log

```bash
# 通用 SQL 关键字过滤（注意会有误报，需要后续 URL-decode + 业务白名单）
grep -iE 'union[+%20\s/\*]+(all[+%20\s/\*]+)?select|information_schema|order[+%20\s/\*]+by[+%20\s/\*]+[0-9]{2,}|sleep\(|benchmark\(' access.log

# url-decoded 后再次匹配（很多 payload 是 % 编码的）
awk -F'"' '{print $2}' access.log | while read line; do
  python3.11 -c "import urllib.parse,sys; print(urllib.parse.unquote(sys.argv[1]))" "$line"
done | grep -iE 'union\s+select|sleep\(|extractvalue\('
# 实际用 scripts/nginx_anomaly.py 跑

# sqlmap UA 指纹
grep -iE 'sqlmap|nuclei|xray|w13scan' access.log

# 同 IP 短时间内大量变体 payload
awk '{print $1, $7}' access.log | sort | uniq -c | awk '$1 > 50 {print $0}'

# error-based 注入命中的响应特征：response 中含 SQL 关键字往往在更大的 status code 序列里
awk '$9 == 500' access.log | head -50
```

字段过滤逻辑：
- 同 IP / 同 URI / 短时间大量含 SQL 关键字的请求 → P1 候选
- 单次请求即返回大量数据（response body > 1MB 且接口正常 response 是 < 10KB） → P0 候选（疑似拖库）

### 3.2 WAF 告警

直接看 WAF 输出的攻击日志：
- 关键字：`SQL Injection`、`SQLi`、`Union Select`、`Boolean SQLi`、`Time-based SQLi`、`Stacked Queries`
- 状态字段：注意「拦截」vs「告警放行」的差异，重点看「放行」的——可能存在绕过
- 同源 IP 跨多个 URI 触发 SQLi 规则 → 高置信扫描

### 3.3 数据库侧

```bash
# MySQL slow log（启用了 long_query_time 后）
grep -iE 'information_schema|sleep|benchmark|extractvalue|updatexml' /var/lib/mysql/*-slow.log

# MySQL general log（生产很少开，但开了就是金矿）
grep -iE 'union.*select|information_schema|sleep\(' /var/lib/mysql/*-general.log

# error log
grep -iE 'syntax error|denied|error.*select' /var/lib/mysql/*.err
```

### 3.4 应用日志（业务 stack trace）

- 业务报错堆栈中出现 `SQLSyntaxErrorException`、`PSQLException`、`SQLException` + 用户输入参数
- 频繁报 `MySQLSyntaxErrorException` → 攻击者在试探或盲注误命中
- ORM 框架（mybatis、hibernate）报错含 `### SQL: SELECT ...` 完整 SQL，关注非业务 SQL

## 4. 误报排查清单

| # | 误报特征 | 如何排除 |
|---|---|---|
| 1 | 业务搜索接口（`/search?q=...`）的合法关键字「select」「from」等出现在用户输入中 | 看是否是搜索 / 报表类接口；搜索接口里的 `select` 多数是查询关键字而非 SQL；正常请求不会带 `union select` 这类完整 SQL 片段 |
| 2 | 业务自身报表 / SQL 工作台（如 metabase / superset / 内部 SQL 平台）由合法用户提交查询 | 看请求 source IP 是不是内部分析师固定 IP；账户是不是 BI 账户；接口路径是 `/superset/sql` 之类而非业务接口 |
| 3 | 安全扫描器内部资产扫描产生的 SQLi payload | 与扫描日程对账；源 IP 在扫描白名单；扫描时段已报备 |
| 4 | 前端 JS 框架的请求中带 `order by`/`group by` 等关键字作为 URL 参数（如 `?orderBy=id&direction=DESC`） | 看实际 payload 是否是「参数 = 字段名」而非「参数 = 完整 SQL 片段」；前端框架的固定 pattern 可建立白名单 |
| 5 | CDN / 缓存层 health check 探测路径带特殊字符 | 看请求节奏（固定时间间隔）+ UA（CDN UA）+ 路径（健康检查路径） |
| 6 | 学习类博客或文档站存在含 SQL 教学文本的合法访问 | 看 URI 是 `/blog/`、`/docs/`、`/learn/` 等内容路径，且是 GET 请求；不会在参数里出现 |
| 7 | 老旧业务接口本身就是用 SQL 关键字命名参数（如 `?fields=id,name&where=status=1`） | 与开发对账接口契约；建立接口级白名单 |
| 8 | 攻击者扫但 WAF 拦掉的（攻击未成功） | WAF 拦截记录中状态为 `block` 且无对应业务侧异常 → 标 P3（保留 IOC 但不升级） |

**误报判定原则**：能与「业务正常查询语义」对账的标 `false_positive_prob >= 0.7`；WAF 拦截的（block 状态）标 P3 即可，但要把源 IP 加入观察列表。

## 5. 关联升级规则

### 5.1 严重性升级（P2 → P1 → P0）

- **P2 → P1**：
  - 同 IP 在 1h 内对同一 URI 大量变体 payload（典型 sqlmap）→ P1
  - WAF 拦截了 N 条但有 1-2 条放行（疑似绕过）→ P1
  - 响应中出现 SQL error 关键字（攻击者已能稳定触发报错）→ P1
- **P1 → P0**：
  - 响应 body 含明确的表名 / 字段名（特别是 `password`、`token`）→ P0
  - 响应 body 异常大且形如数据导出（大量行）→ P0（疑似拖库）
  - 数据库审计日志显示非业务用户访问了 `information_schema` / `mysql.user` → P0
  - 数据库错误日志显示成功的 stacked query / xp_cmdshell 调用 → P0
  - SQL 注入后短时间内同 IP 访问到新 webshell 文件 → P0（SQLi 写文件成功）

### 5.2 模式升级

- **monitor → audit**：单 URI 出现高置信 SQLi 告警 → audit 模式回溯该接口最近 7 天访问，查是否早就在打
- **audit → ir**：
  - 确认拖库 / 数据外传 / 数据库提权 / webshell 落地 → ir
  - 数据库层面发现可疑账户、UDF、jobs/triggers → ir

## 6. 止血动作（containment）

### 6.1 网络层

| 动作 | 操作要点 | 副作用 | 回退路径 |
|---|---|---|---|
| WAF 加规则 ban 源 IP | 优先 /32，慢慢扩 | NAT 出口下误伤 | 标准流程 |
| WAF 加 URI 级规则 | 对漏洞 URI 加严格 SQLi 检测规则 | 误伤合法请求 | 调整规则阈值 |
| 临时下线漏洞接口 | nginx location 返回 403 | 业务功能受影响 | 修复后回滚 |

### 6.2 主机层

| 动作 | 操作要点 | 副作用 | 回退路径 |
|---|---|---|---|
| 隔离数据库主机出网 | 防火墙限制数据库主机只能与业务后端通信，不能直接出公网 | 数据库无法主动外联（很少有合法需求） | 紧急情况临时开放 |
| 备份数据库当前状态 | 全量备份留作证据，含日志 | 备份占用磁盘 | 证据保存 30 天后清理 |
| 检查并清理可疑 UDF / 触发器 / 存储过程 | DBA 配合，先查后清 | 误删业务 SP 影响功能 | 备份对账 |

### 6.3 应用层

| 动作 | 操作要点 | 副作用 | 回退路径 |
|---|---|---|---|
| 应用层参数化 | 用预编译 / 绑定变量替换字符串拼接 | 代码变更，需要测试 | 标准开发流程 |
| 临时下线漏洞接口 | feature flag 关闭功能 | 功能不可用 | 修复后开启 |
| 输入校验加严 | 接口入参类型 / 长度 / 字符集校验 | 可能拒绝部分合法但格式不严的输入 | 调整校验规则 |
| 异常信息脱敏 | 不在响应中回显 SQL error stack trace | 调试时不便 | 调试时临时开 |

### 6.4 账号层

| 动作 | 操作要点 | 副作用 | 回退路径 |
|---|---|---|---|
| 应用对应的数据库账户最小权限化 | 业务账户只给 DML 不给 DDL，只给当前业务库，不给 `FILE` / `SUPER` 等高权 | 部分管理操作需要切高权账户 | 加专用管理账户 |
| 重置数据库 root 口令 | DBA 配合，确认没有应用硬编码 root | 应用配置需要同步更新 | 标准流程 |
| 清理可疑数据库账户 | 比对基线，删除非授权账户 | 误删合法应用账户影响业务 | 备份对账 |

## 7. 根除与恢复（eradication & recovery）

### 7.1 根除步骤

1. **修复代码漏洞**：所有相关接口改为参数化查询；对存量 SQL 拼接做全量审计
2. **数据库层加固**：
   - 关闭 `FILE` 权限（应用账户）
   - 禁用 `xp_cmdshell` / `sys_exec` 等危险函数
   - 关闭 `secure_file_priv` 写文件目录（或限制为空）
   - 检查并清理可疑 UDF（特别是 `lib_mysqludf_sys`）
3. **写文件落地物清理**：
   - SQL 注入常用 `INTO OUTFILE` 写 webshell → 全面扫 web 目录最近修改文件
   - SQL 注入提权常用 UDF dll/so → 检查 mysql 数据目录是否有可疑文件
4. **数据库账户重置**：业务账户口令轮换
5. **审计数据外传**：通过 access.log / 数据库流量 / DLP 检查数据是否已外泄

### 7.2 恢复步骤

- 漏洞已修补 + 数据库已加固 + 无落地物 → 可继续运行
- 数据已外泄 → 走数据外泄应急流程，按合规要求通知 / 报告
- 数据库提权成功 → 假设整个数据库实例已不可信，按 ir 流程全量重装

### 7.3 验证点

1. **代码验证**：相关接口已改为参数化，单元测试覆盖；用 sqlmap 类工具自检确认无注入点
2. **数据库验证**：
   - 应用账户权限符合最小权限原则（`SHOW GRANTS FOR ...`）
   - `secure_file_priv` 已限制
   - 危险函数已禁用（mysql：`xp_*` 不适用；MSSQL：`sp_configure 'xp_cmdshell',0`）
3. **日志验证**：加固后 24h 内同 IP 的 SQLi 告警归零 / WAF block 状态稳定
4. **响应验证**：异常响应不再回显数据库错误堆栈
5. **数据外传验证**：DB → 公网的连接日志干净，无可疑大流量

## 8. IOC 提取模板

```json
[
  {
    "type": "ip",
    "value": "192.168.1.xxx",
    "confidence": "high",
    "first_seen": "2026-06-30T10:21:33+08:00",
    "source": "nginx-access.log:line-21183",
    "tag": "sqli,attacker-ip,tool:sqlmap"
  },
  {
    "type": "url",
    "value": "https://customer.example.com/api/report?id=...",
    "confidence": "high",
    "first_seen": "2026-06-30T10:21:33+08:00",
    "source": "nginx-access.log:line-21183",
    "tag": "sqli:injection-point,vulnerable-endpoint"
  },
  {
    "type": "ua",
    "value": "sqlmap/1.x.x.x#stable",
    "confidence": "high",
    "first_seen": "2026-06-30T10:21:33+08:00",
    "source": "nginx-access.log:line-21183",
    "tag": "tool:sqlmap"
  },
  {
    "type": "tool",
    "value": "sqlmap",
    "confidence": "high",
    "first_seen": "2026-06-30T10:21:33+08:00",
    "source": "rule:PLB-SQ-005",
    "tag": "sqli-tool"
  }
]
```

提取重点：
- 攻击源 IP
- 漏洞 URL（injection-point）
- 攻击工具 UA / 工具名
- 被读取 / 被影响的表名（如果能从响应或 db log 中识别）
- 写入的落地物 hash（如有 INTO OUTFILE 写 webshell）
- 数据外传目标 IP / 域名（如有 OOB）

---

## rule_id 命名约定

- 前缀：`PLB-SQ-NNN`（PlayBook-SQli）

### 已建议规则一览

| rule_id | 规则名 | 触发条件 |
|---|---|---|
| PLB-SQ-001 | Union-based 关键字 | URL/body 含 `union\s+(all\s+)?select` |
| PLB-SQ-002 | Boolean-based 模式 | URL/body 含 `and\s+1=1` / `and\s+1=2` 类配对 |
| PLB-SQ-003 | Time-based 关键字 | URL/body 含 `sleep\(`/`benchmark\(`/`pg_sleep`/`waitfor\s+delay` |
| PLB-SQ-004 | Error-based 关键字 | URL/body 含 `extractvalue\(`/`updatexml\(`/`floor\(rand`/`exp\(~` |
| PLB-SQ-005 | sqlmap 工具指纹 | UA 含 `sqlmap` 或 Cookie 中含 sqlmap marker |
| PLB-SQ-006 | xray/nuclei/w13scan 指纹 | UA 命中扫描器名 + 短时间内大量变体 payload |
| PLB-SQ-007 | information_schema 探测 | URL 含 `information_schema` / `mysql.user` / `sys.tables` |
| PLB-SQ-008 | Stacked query 模式 | URL/body 含 `;\s*(insert\|update\|drop\|exec\|shutdown)` |
| PLB-SQ-009 | OOB 注入 | URL 含 `load_file\(`/`xp_dirtree` 或对外部 IP/DNS 的回连 |
| PLB-SQ-010 | WAF 绕过：注释混淆 | URL 含 `/*!`、`/**/`、URL 编码的注释 |
| PLB-SQ-011 | WAF 绕过：编码套娃 | 双 url-encode（`%25xx`）+ SQL 关键字 |
| PLB-SQ-012 | 响应回显 SQL 报错 | 响应 body 含 `SQL syntax`/`ORA-`/`MSSQL`/`PSQLException` |
| PLB-SQ-013 | 大响应（疑似拖库） | 同接口响应 body > 10x baseline 且 SQL 注入告警同源 |
| PLB-SQ-014 | DB 日志 information_schema 访问 | 非业务账户访问 `information_schema.*` 或 `mysql.user` |
| PLB-SQ-015 | INTO OUTFILE 落地 webshell | DB general log/slow log 含 `into\s+outfile`/`dumpfile` |
