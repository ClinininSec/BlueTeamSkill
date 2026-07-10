# WAF / Firewall 告警字段最大公约数

> WAF / NGFW / IDS 告警 JSON/CSV 的字段映射、规则分类、误报模式速查。
> **何时使用**：monitor 模式下分诊批量 WAF/FW 告警；不点名厂商，用 vendor A/B/C 占位。

---

## 一、通用字段速查表

| 标准字段 | 含义 | 典型取值 |
|---|---|---|
| `ts` / `timestamp` | 告警时间（建议 ISO8601） | `2026-06-30T10:15:23+08:00` |
| `src_ip` | 攻击源 IP | `192.168.1.xxx` |
| `src_port` | 源端口 | `53412` |
| `dst_ip` | 目标 IP | `10.10.10.xxx` |
| `dst_port` | 目标端口 | `443` |
| `proto` | 协议 | `tcp/udp/icmp/http/https` |
| `action` | 处置动作 | `allow / deny / alert / drop / reset / block / monitor` |
| `rule_id` | 规则编号 | `WAF-1001` / vendor 私有 ID |
| `rule_name` | 规则名 | `SQL Injection - Union Select` |
| `category` | 攻击类别 | 见下方分类表 |
| `severity` | 严重等级 | `critical / high / medium / low / info` |
| `payload` | 原始 payload 片段 | URL / body 片段（往往截断） |
| `signature` | 命中签名 | 厂商签名 ID |
| `host` / `domain` | 受攻击主机 | `customer.example.com` |
| `uri` | 受攻击 URI | `/api/login` |
| `method` | HTTP 方法 | `POST` |
| `ua` | User-Agent | `sqlmap/1.7-stable` |
| `xff` | X-Forwarded-For | 上游链 IP |
| `referer` | Referer | 来源页 |
| `status` | 后端响应码 | `200/403/500` |
| `bytes_in / bytes_out` | 进出字节数 | 流量统计 |
| `country` / `geoip` | 源 IP 地理位置 | （不依赖在线 GeoIP） |
| `asset_tag` | 资产标签 | 内部 CMDB 匹配 |
| `attack_chain_id` | 关联攻击链 ID | 跨告警关联 |

---

## 二、不同厂商字段名映射示意

| 标准字段 | vendor A | vendor B | vendor C |
|---|---|---|---|
| `src_ip` | `attack_ip` | `client.ip` | `source_address` |
| `dst_ip` | `victim_ip` | `server.ip` | `dest_address` |
| `rule_id` | `policy_id` | `signature_id` | `rule_uuid` |
| `category` | `attack_type` | `event.category` | `threat_type` |
| `severity` | `risk_level` | `event.severity` | `alarm_level` |
| `payload` | `match_content` | `payload_data` | `request_body` |
| `action` | `disposal` | `event.outcome` | `action_taken` |
| `ts` | `timestamp_ms` | `@timestamp` | `event_time` |

> 实操：拿到任意厂商导出后，先写一份 mapping 表落到本地 `scripts/log_parser.py` 的 `parse_waf_alert()`，统一规范化为以上"标准字段"再喂给分诊。

---

## 三、告警规则分类（统一 category 取值）

| category 取值 | 子类 / 关键词 | 优先级倾向 |
|---|---|---|
| `sqli` | union select / sleep() / benchmark / order by / waitfor / and 1=1 | P1+（依赖响应） |
| `xss` | `<script>` / `javascript:` / `onerror=` / svg payload | P2 居多 |
| `rce` | fastjson / log4j / `${jndi:ldap` / Runtime.exec / shellcommand / OGNL | P0 |
| `ssrf` | `127.0.0.1` / `localhost` / 内网地址 / gopher:// / dict:// | P1 |
| `xxe` | `<!ENTITY` / `SYSTEM "file://` | P1 |
| `info_disclosure` | `.git/` / `.env` / `WEB-INF/web.xml` / `swagger-ui` / `actuator` | P2，命中且 200 升 P1 |
| `brute_force` | 同 IP 高频 401/403 / `auth_failed` 标记 | P2 |
| `scanner` | UA = sqlmap / nuclei / nikto / nessus / awvs | P3（除非命中） |
| `unauthorized_access` | 401/403 突增 + 异常 URI | P2 |
| `webshell` | 上传特征 / 一句话 payload / 哥斯拉 / 冰蝎特征 | P0 |
| `malware_c2` | C2 域名 / IP / known bad hash | P0 |
| `dos` | flood / syn / udp 反射 | P1 |
| `data_exfil` | 大响应 + 异常出网 / dnstunnel | P0 |
| `cve_exploit` | 命中 CVE 签名 | 视命中确认度 P0/P1 |

---

## 四、常见 False Positive Pattern

蓝队首次过批量告警时优先识别这几类高误报场景：

1. **SQLi 命中表单字段含合法 SQL 关键字** —— 例如博客内容含 `select` / `union` 字符；要看 `status` 与后端响应 size。
2. **XSS 命中富文本编辑器内容** —— CKEditor / TinyMCE 提交本身含 `<script>`，需看 dst URI 是否为编辑器保存路径。
3. **RCE 命中扫描器探测但未命中** —— payload 含 `${jndi:` 但响应 404 / 不触发 dns 回连。
4. **扫描器 UA 但定向资产仅是登录页** —— 内部安全部门日常扫描。
5. **`.git/` 探测但仓库不存在** —— 持续被扫但无泄露。
6. **业务正常长 URL** —— 报表导出 / 复杂搜索参数。
7. **WAF 重复告警** —— 同 src/dst/rule 短时间内 N 倍重复（多为 WAF 自身去重未配）。
8. **CDN / 接入层 IP 误判** —— `src_ip` 是 CDN 节点而非真实攻击者，需读 `xff`。

---

## 五、与 SIEM 关联升级的字段

monitor 模式下需把单条告警升级为攻击链时，按以下字段做关联：

| 关联维度 | 字段组合 | 升级逻辑 |
|---|---|---|
| 同 IP 多类攻击 | `src_ip` × distinct(`category`) | ≥ 3 类 → 高置信扫描者，升 P1 |
| 同 IP 命中后 success | `src_ip` + `status=200/302` | 升 P0（疑似真实命中） |
| 多 IP 同 payload | hash(`payload`) | 大盘扫描 / 蠕虫，降 P3 |
| 同 IP 跨资产 | `src_ip` × distinct(`dst_ip`) | ≥ 5 资产 → P1 横向探测 |
| 命中 + 出网 | dst 端 srv 出现新外联 | 升 P0 真实落地 |

---

## 六、日志接入与归一化建议

- 各厂商 SDK 推送的 JSON 直接喂 `scripts/log_parser.py` 的 `parse_waf_alert()`，输出标准字段。
- 同一字段含多值（如 XFF 链）时，保留为数组而非拼接字符串。
- `payload` 字段往往被厂商截断到 256/512 字节，需要在 audit 阶段回到原始 WAF/access 日志做证据补全。
- 时间戳统一转 ISO8601 + UTC，便于多源拼时间线。
