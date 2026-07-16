# IOC 标准输出格式

> 本模板定义 `hvv-defender` skill 在任意模式下输出 IOC（Indicator of Compromise）时遵循的统一 schema。
>
> 所有脚本（`ioc_match.py` / `nginx_anomaly.py` / `auth_log_audit.py` / `webshell_scan.py` / `traffic_anomaly.py`）与子 agent（`alert-triage` / `log-analyzer` / `traffic-analyst` / `ir-investigator`）输出 IOC 时必须严格遵循。
>
> 该格式与主流 SIEM（Splunk / ELK / QRadar 国内常见替代）的 lookup 表兼容，可直接 import。

---

## 1. 顶层结构

```json
{
  "version": "0.1",
  "generated_at": "2026-06-30T18:00:00+08:00",
  "case_id": "MON-2026-06-30 | AUD-2026-06-30 | TRAF-2026-06-30 | IR-2026-06-30-<host_hash> | REM-2026-06-30",
  "mode": "monitor | audit | traffic | ir | remote",
  "customer": "<customer>",
  "skill_version": "hvv-defender@0.1",
  "desensitized": true,
  "total": 27,
  "iocs": [ ... ]
}
```

### 字段说明

| 字段 | 必填 | 取值 | 说明 |
|---|---|---|---|
| `version` | ✅ | string | IOC schema 版本，本 skill 当前 "0.1" |
| `generated_at` | ✅ | ISO 8601 | 生成时间，含时区 |
| `case_id` | ✅ | string | 与告警 / 异常 / 事件主体关联的案件号 |
| `mode` | ✅ | enum | 来源模式 |
| `customer` | ✅ | string | 客户标识（脱敏后） |
| `skill_version` | ✅ | string | 用于回溯规则版本 |
| `desensitized` | ✅ | bool | 是否已通过 `desensitize.py` 过滤 |
| `total` | ✅ | int | iocs 数组长度 |
| `iocs` | ✅ | array | 详见下节 |

---

## 2. 单条 IOC schema（6 必填字段 + 可选 description）

```json
{
  "type": "ip",
  "value": "192.168.1.xxx",
  "confidence": "high",
  "first_seen": "2026-06-30T08:31:47+08:00",
  "source": "nginx-access.log:14523 | rule_id=PLB-CE-006",
  "tag": "c2:suspect",
  "description": "fastjson 利用尝试源 IP，连续 3 类规则命中"
}
```

### 字段定义

| 字段 | 必填 | 取值 | 说明 |
|---|---|---|---|
| `type` | ✅ | enum | 见下"type 取值清单" |
| `value` | ✅ | string | IOC 实际值，必须脱敏后存储 |
| `confidence` | ✅ | `high` / `medium` / `low` | 置信度 |
| `first_seen` | ✅ | ISO 8601 | 在日志/证据中首次出现的时间戳 |
| `source` | ✅ | string | 提取来源：日志文件:行号 / 规则 ID / 采集文件 |
| `tag` | ✅ | string | 标签，格式 `category:subtype`（详见"tag 命名约定"） |
| `description` | ⛔ | string | 可选，一句话上下文 |
| `last_seen` | ⛔ | ISO 8601 | 可选，末次出现时间（如多次） |
| `count` | ⛔ | int | 可选，出现次数 |

### type 取值清单

| type | 示例 | 备注 |
|---|---|---|
| `ip` | `192.168.1.xxx` | 支持单 IP，CIDR 段单独 |
| `cidr` | `192.168.1.0/24` | |
| `domain` | `customer.example.com` 或 `<external>` | 通配 `*.foo.com` |
| `url` | `http://example.com/x.sh` | 完整 URL |
| `hash:md5` | `<md5>` | MD5 不脱敏（已不可逆） |
| `hash:sha1` | `<sha1>` | |
| `hash:sha256` | `<sha256>` | 优先 |
| `ua` | `Apache-HttpClient` | User-Agent 字符串 |
| `path` | `/uploads/a.jsp` | 文件或 URL path |
| `email` | `a***@<domain>` | 已脱敏 |
| `tool` | `fscan` / `sqlmap` | 工具名（识别后的） |
| `port` | `4444` | 端口（数字） |
| `process` | `tomcat → bash → curl` | 进程链 |
| `file` | `/etc/cron.d/.update` | 完整文件路径 |
| `pubkey_fingerprint` | `SHA256:<base64>` | SSH 公钥指纹 |
| `tactic` | `T1190` | MITRE ATT&CK 技术 ID（ir 模式专用） |

### confidence 评定标准

| 级别 | 判定规则 | 示例 |
|---|---|---|
| `high` | 命中多条规则 / 已确认入侵 / 公开恶意样本 | fastjson 命中 + tomcat 起子进程 + 出站 C2 |
| `medium` | 命中单条规则 / 疑似但无横向印证 | sqlmap UA + 4xx 突增 |
| `low` | 单点匹配 / 误报概率 ≥ 0.5 | UA 含 "Mozilla" 但 url 含特征字符串 |

### tag 命名约定

格式：`category:subtype[/extra]`，全小写连字符。

| category | subtype 示例 |
|---|---|
| `tool` | `tool:sqlmap` `tool:nuclei` `tool:fscan` `tool:cs-beacon` |
| `c2` | `c2:confirmed` `c2:suspect` `c2:cobaltstrike` |
| `persistence` | `persistence:cron` `persistence:authorized_keys` `persistence:pam` |
| `webshell` | `webshell:php` `webshell:jsp` `webshell:godzilla` |
| `tactic` | `tactic:t1190` `tactic:t1059.004` |
| `scanner` | `scanner:tool` `scanner:internal-whitelist` |
| `fp` | `fp:health-check` `fp:internal-monitor` `fp:test-traffic` |
| `severity` | `severity:p0` `severity:p1` |

可多 tag，用空格分隔：`"tag": "tool:fscan severity:p1"`。

---

## 3. 脱敏要求（强制）

所有 `value` 字段进入文件前必须满足：

| type | 脱敏规则 | 脱敏后示例 |
|---|---|---|
| ip | 私网保留 /24+xxx；公网整体替换 `<public-ip>` 或保留（如客户授权） | `192.168.1.xxx` |
| domain | 内部域名替换 `<internal>`；客户域名替换 `<customer>` | `<internal>` |
| email | `a***@<domain>` | `z***@<internal>` |
| path | `/home/<user>/...` 自动脱用户名 | `/home/<user>/.ssh/id_rsa` |
| hash | 不脱（已不可逆） | `<sha256>` 仅占位例示 |

`desensitize.py` 必须默认在 IOC 输出前过一遍；未脱敏的 IOC 文件禁止流出客户授权范围。

---

## 4. 文件存储约定

| 模式 | 文件命名 | 位置 |
|---|---|---|
| monitor | `iocs-monitor-<date>.json` | 客户值守目录 |
| audit | `iocs-audit-<date>-<system>.json` | 审计案件目录 |
| traffic | `iocs-TRAF-<date>-<pcap>.json` | 流量案件目录 |
| ir | `iocs-<case_id>.json` | incident 案件目录 |
| remote | `iocs-REM-<date>-<host>.json` | remote 案件目录 |

文件后缀必须为 `.json`，UTF-8 无 BOM，`indent=2`。

---

## 5. SIEM 导入兼容性

- **Splunk**：每条 IOC 转为 `lookup` 表行，字段名一对一
- **ELK**：作为 `_source` 直接索引（type / value / tag / first_seen 字段无需重命名）
- **QRadar / Sumo / 国内常见替代**：导出为 CSV `type,value,confidence,first_seen,source,tag`

`hvv-defender` 不提供自动导入脚本（属于"厂商对接"）。值守班用户可手工转换或写自有桥接脚本。

---

## 6. 校验清单（写入前自查）

- [ ] `version` `generated_at` `case_id` `mode` `customer` `total` 顶层字段齐全
- [ ] `desensitized` 字段为 `true`，且确实跑过 `desensitize.py`
- [ ] 每条 IOC 含必填 6 字段（type/value/confidence/first_seen/source/tag）
- [ ] `type` 取值在清单内
- [ ] `confidence` 仅 high/medium/low 三档
- [ ] `tag` 符合 `category:subtype` 命名
- [ ] `first_seen` 为 ISO 8601 带时区
- [ ] `value` 无未脱敏的私网 IP / 内部域名 / 用户名 / 客户名

---

## 7. 示例（完整 mini 文件）

```json
{
  "version": "0.1",
  "generated_at": "2026-06-30T18:00:00+08:00",
  "case_id": "MON-2026-06-30",
  "mode": "monitor",
  "customer": "<customer>",
  "skill_version": "hvv-defender@0.1",
  "desensitized": true,
  "total": 3,
  "iocs": [
    {
      "type": "ip",
      "value": "192.168.1.xxx",
      "confidence": "high",
      "first_seen": "2026-06-30T08:31:47+08:00",
      "source": "nginx-access.log:14523",
      "tag": "c2:suspect tactic:t1190",
      "description": "fastjson 反序列化尝试源 IP，多规则命中"
    },
    {
      "type": "ua",
      "value": "Apache-HttpClient",
      "confidence": "medium",
      "first_seen": "2026-06-30T08:23:11+08:00",
      "source": "rule_id=SIG-TF-018",
      "tag": "tool:suspect"
    },
    {
      "type": "path",
      "value": "/uploads/a.jsp",
      "confidence": "high",
      "first_seen": "2026-06-30T08:31:47+08:00",
      "source": "rule_id=PLB-WS-001 nginx-access.log:14523",
      "tag": "webshell:jsp severity:p0",
      "description": "短文件名 jsp，访问立即返回 200"
    }
  ]
}
```
