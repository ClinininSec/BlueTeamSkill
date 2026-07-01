---
vendor_name: changting-safeline
display_name: 长亭雷池 SafeLine WAF
alert_export_formats: [json, csv]
field_map:
  ts: [event_time, log_time, "@timestamp", timestamp, create_time, ts]
  src_ip: [src_ip, client_ip, remote_addr, source_ip, attacker_ip]
  dst_ip: [dst_ip, upstream_addr, server_ip, host_ip, target_ip]
  dst_port: [dst_port, server_port, upstream_port, dest_port, port]
  proto: [proto, protocol, scheme, l7_proto]
  rule_name: [rule_name, module, attack_type, event_name, threat_type]
  severity: [severity, risk_level, level, action_type, block_reason_level]
  payload: [payload, request, req_body, raw_request, body, matched_content]
  user_agent: [user_agent, ua, http_user_agent, agent]
  username: [user, username, account]
  hostname: [host, hostname, server_name, domain, dst_host]
  action: [action, block_action, disposal, verdict, decision]
severity_map:
  高风险: P0
  高危: P0
  高: P1
  中风险: P2
  中危: P2
  中: P2
  低风险: P3
  低危: P3
  低: P3
  提示: P3
  信息: P3
  high: P1
  medium: P2
  low: P3
  critical: P0
  block: P1
  monitor: P3
category_map:
  SQL注入: sqli
  SQL盲注: sqli
  基于时间的盲注: sqli
  基于布尔的盲注: sqli
  命令注入: rce
  命令执行: rce
  Java反序列化: rce
  反序列化: rce
  Fastjson反序列化: rce
  Log4j2利用: rce
  Spring命令执行: rce
  Shiro反序列化: rce
  WebShell上传: webshell
  WebShell访问: webshell
  WebShell通信: webshell
  一句话木马: webshell
  暴力破解: brute-force
  账号爆破: brute-force
  密码爆破: brute-force
  扫描器识别: recon
  漏洞扫描: recon
  Web漏洞扫描: recon
  信息泄露探测: recon
  XSS跨站: 其他
  存储型XSS: 其他
  反射型XSS: 其他
  文件包含: rce
  文件上传绕过: webshell
  目录穿越: 其他
  服务端请求伪造: 其他
  SSRF: 其他
  XXE: 其他
  越权访问: 其他
  敏感信息泄露: data-exfil
---

# 长亭雷池 SafeLine WAF 告警字段抽屉

## 一、告警数据格式概览

- **平台版本兼容说明**：本抽屉参考长亭雷池 SafeLine WAF 开源版 3.x/4.x/5.x 以及商业版 (Chaitin Web Application Firewall)。雷池 SafeLine 从 2024 年开源以来经历了几次字段命名调整：2024 年 3.x 走 `client_ip / upstream_addr` 命名（贴 nginx 传统命名），2025 年 5.x 引入 `src_ip / dst_ip` 统一命名（兼顾 SIEM 消费）。本抽屉两套命名同时兼容。
- **常见导出方式**：
  - Web 页面攻击事件 → 导出（JSON / CSV）；雷池默认单批最多 10k 条
  - SafeLine Console 内置 API：`GET /api/open/records/attack` 拉取
  - Docker 部署下直接读容器日志卷：`/data/safeline/resources/log/attack.log`（NDJSON 格式）
  - Syslog Forward 到 SIEM，格式为标准 JSON over UDP
- **常见文件扩展名**：
  - `.json`：单文件顶层数组，每条为一个事件
  - `.ndjson` / `.log`：容器日志卷直读，每行一条 JSON
  - `.csv`：Web 页面导出的报表，表头中英混合（例如 "时间 event_time"）
- **雷池的双命名兼容策略**：因 SafeLine 走开源迭代节奏，字段命名不稳定，vendor_field_mapper.py 需要在遇到未识别字段时打印 debug 提示，而不是直接跳过。

## 二、字段对照表（详版）

| skill 标准字段 | 厂商字段名（JSON） | 备注 |
|---|---|---|
| ts | event_time / log_time / create_time | 3.x 用秒级 epoch，5.x 用 ISO8601 |
| src_ip | client_ip / src_ip | 3.x 用 `client_ip`（贴 nginx `remote_addr`），5.x 引入 `src_ip` 别名 |
| dst_ip | upstream_addr / dst_ip / server_ip | 3.x 用 `upstream_addr`，5.x 用 `dst_ip` |
| dst_port | server_port / dst_port | 数值 |
| proto | scheme / proto | http / https（雷池是 Web 层设备，L4 协议基本固定） |
| rule_name | attack_type / event_name / module | 雷池的 `module` 是检测模块（如 sqli/xss），`attack_type` 是具体子类 |
| severity | risk_level / severity | 中文三级 高风险/中风险/低风险 或英文 high/medium/low |
| payload | raw_request / req_body / body | 雷池默认保留完整请求体（比 QAX/SIP 好），最大 8KB |
| user_agent | user_agent / http_user_agent | 从 request headers 抽取 |
| username | user / account | 认证类事件才有 |
| hostname | host / server_name / domain | 从 HTTP Host header 抽取 |
| action | action / block_action | 雷池 action 枚举：block/monitor/passed/challenge |

## 三、severity 映射说明

- 雷池 SafeLine 主用三级：高风险 / 中风险 / 低风险；商业版部分场景引入五级（高 / 中 / 低 / 提示 / 信息）。
- **保守分级建议**：
  - 雷池 "高风险" → skill `P0`。雷池是专用 WAF，其"高风险"判定通常已经过语义引擎二次判定（雷池的语义分析引擎是其核心卖点），误报率相对国产友商 WAF 低。
  - 雷池 "中风险" → `P2`。
  - 雷池 "低风险 / 提示 / 信息" → `P3`。
- **边界注意**：
  - 雷池 5.x 部分版本会把 `action=block` 直接映射为 P1（"块了就是高风险"逻辑），但驻场值守时应关注"块 + 高频重试"组合，即使被阻断也应升级。
  - 雷池 `action=monitor`（仅监控模式）建议全部降为 P3 或 P2，因为监控模式不阻断，误报率相对未加人工调优的 WAF 高。

## 四、category 映射说明

- 雷池的 `attack_type` 字段中文命名细致（例如区分"基于时间的盲注 / 基于布尔的盲注"），本抽屉尽量按细分类别映射。
- **常见坑**：
  - "文件上传绕过" 归入 `webshell` 而非 `其他`，因为雷池对此类事件的 severity 判定较高，通常是文件上传功能 + 特殊后缀 + 双扩展名绕过组合，本质是 webshell 落地前置行为。
  - "存储型 XSS / 反射型 XSS" 均归入 `其他`，因 skill 标准 category 无 xss 分类。
  - "SSRF / XXE / 越权访问" 均归入 `其他`。
  - "服务端请求伪造 / SSRF" 是同一事件的两种中英命名，两个都要在 category_map 里。
- **不可归类**：落到 `其他`，vendor_field_mapper.py 打印未映射统计。

## 五、常见误报模式（vendor-specific）

雷池 SafeLine 在驻场值守中常见误报 pattern：

1. **富文本 / 编辑器保存触发 XSS**：客户 CMS / 博客 / 工单系统的富文本编辑器保存内容含 `<script>` / `on*=` 属性时会命中 XSS 规则。识别特征：dst 是编辑器保存路径（如 `/api/article/save`）+ src 是内部用户段 + status 200。雷池 5.x 引入"上下文感知"部分缓解此类误报，但仍需关注。
2. **API 参数 order_by / sort_by 触发 SQL 注入**：业务 REST API 参数如 `orderBy=create_time DESC` 会命中 SQL 注入规则。识别特征：payload 只含 SQL 关键字但无实际注入 payload + status 200。
3. **CDN 回源 IP 被判为攻击者**：客户在雷池前面还有 CDN 或反向代理时，`client_ip` 是 CDN 节点 IP，会导致所有攻击来源都是 CDN。识别特征：`client_ip` 属于已知 CDN 段（Cloudflare / 阿里云 CDN / 腾讯云 CDN 段）。**必须读 X-Forwarded-For 抽真实 src**。
4. **压测 / 探活工具触发扫描器识别**：客户业务压测 / API 探活工具（wrk / ab / prometheus-blackbox）会命中"扫描器识别"规则。识别特征：源 IP 在客户内部监控段 + 请求路径固定 + 时段规律。
5. **雷池语义引擎对 base64 body 误判 RCE**：雷池的语义引擎对含 base64 编码的 body 敏感，客户业务如有 base64 传参（如富文本图片、加密业务参数）会命中 RCE 规则。识别特征：payload 含 base64 编码 + dst 是业务 API。

## 六、驻场对接实操建议（3-5 条）

1. **首选容器日志直读**：雷池 SafeLine 部署为 Docker 容器时，`/data/safeline/resources/log/attack.log` 是 NDJSON 格式，比 Web 页面导出的 JSON 更完整（含 `raw_request` 完整请求体）。vendor_field_mapper.py 应支持 ndjson 输入。
2. **X-Forwarded-For 处理**：雷池默认从 `X-Forwarded-For` header 抽最左侧 IP 作 `client_ip`，但客户前置 CDN 时 XFF 可能是"CDN_IP, REAL_IP"。驻场首日必须与客户确认 XFF 抽取策略（雷池 Console → 网站配置 → 客户端 IP 来源）。
3. **规则库快速迭代**：雷池开源版规则库更新频繁（每两周一次），rule_name 变化较大。驻场时应固定使用一个版本（推荐 5.0 LTS），vendor_field_mapper.py 的 category_map 与该版本对齐。
4. **`raw_request` 隐私风险**：雷池默认保存完整请求体，含用户业务数据（表单、cookie、token）。驻场脱敏阶段必须优先脱 `raw_request` 中的敏感字段（token、session、身份证号），desensitize.py 应对雷池数据特别处理。
5. **`action=monitor` 优先级**：雷池仅监控模式下的告警建议驻场首周不纳入 monitor 分诊主流程，因为客户往往在"新上线业务观察期"设置监控模式导致告警爆炸；纳入 audit 抽样即可。

## 七、已知不确定的字段（驻场时校准）

- `semantic_score`：雷池 5.x 的语义引擎会输出置信度分（0-100），字段名可能是 `score / confidence / risk_score`，本抽屉未映射，驻场时可作为 false_positive_prob 的辅助信号。
- `rule_id` / `signature_id`：雷池的 rule_id 格式在 4.x 到 5.x 之间变过（数字 vs 字符串），本抽屉走 rule_name 优先策略避开该问题。
- `request_headers` 详细字段：雷池 5.x 会保留完整请求头，字段名 `headers` 或 `request_headers`，本抽屉未映射到标准 8 字段，audit 阶段回补时可作为额外证据。

## 八、字段抽屉小结

- field_map 共 12 个 skill 标准字段，每字段列 3-5 个别名（雷池双命名兼容策略）。
- severity_map 覆盖中文三级 + action 状态 + 英文，共 17 条。
- category_map 覆盖 32 条常见攻击类型（细分 SQL 注入子类、包含 XSS/SSRF/XXE 归入"其他"）。
- 雷池 SafeLine 的关键校准点是 X-Forwarded-For 真实 IP 抽取和语义引擎置信度字段，驻场首日必须与客户对齐。
