---
vendor_name: dbappsec-mingyu
display_name: 安恒明御 WAF
alert_export_formats: [json, csv]
field_map:
  ts: [attack_time, event_time, alarm_time, log_time, occur_time, timestamp, "@timestamp"]
  src_ip: [src_ip, attack_source_ip, source_ip, client_ip, attacker]
  dst_ip: [dst_ip, target_ip, victim_ip, dest_ip, protected_ip]
  dst_port: [dst_port, target_port, server_port, dest_port]
  proto: [protocol, proto, l7_protocol, app_protocol]
  rule_name: [rule_name, attack_type_name, event_name, threat_name, signature_name]
  severity: [severity, threat_level, risk_level, alarm_level, level, risk_grade]
  payload: [payload, attack_content, match_content, request_content, body, matched_data]
  user_agent: [user_agent, http_user_agent, ua, agent_string]
  username: [username, user, account, login_id]
  hostname: [hostname, protected_host, target_domain, server_name, host]
  action: [action, disposal, response_action, block_action, handle_result]
severity_map:
  致命: P0
  紧急: P0
  高: P0
  高危: P0
  中: P2
  中危: P2
  中等: P2
  低: P3
  低危: P3
  提示: P3
  信息: P3
  4: P0
  3: P1
  2: P2
  1: P3
  critical: P0
  high: P0
  medium: P2
  low: P3
category_map:
  WebShell上传: webshell
  WebShell访问: webshell
  WebShell后门: webshell
  一句话木马: webshell
  Webshell管理: webshell
  SQL注入攻击: sqli
  SQL注入: sqli
  SQL盲注攻击: sqli
  联合查询注入: sqli
  命令注入攻击: rce
  命令执行: rce
  远程命令执行: rce
  代码执行: rce
  反序列化攻击: rce
  Java反序列化: rce
  Fastjson漏洞利用: rce
  Log4j2漏洞利用: rce
  Struts2漏洞利用: rce
  Spring漏洞利用: rce
  Weblogic漏洞利用: rce
  暴力破解攻击: brute-force
  账号暴力破解: brute-force
  弱口令尝试: brute-force
  Web扫描: recon
  漏洞扫描: recon
  目录扫描: recon
  端口扫描: recon
  敏感文件扫描: recon
  信息收集: recon
  横向移动: lateral
  数据外发: data-exfil
  敏感数据泄露: data-exfil
  异常数据传输: data-exfil
  跨站脚本攻击: 其他
  XSS攻击: 其他
  文件包含攻击: rce
  目录遍历攻击: 其他
  CSRF攻击: 其他
---

# 安恒明御 WAF 告警字段抽屉

## 一、告警数据格式概览

- **平台版本兼容说明**：本抽屉参考安恒明御 Web 应用防火墙 (DAS-WAF) 从 5.x 到 7.x 的告警字段格式，兼顾明御云 WAF (Cloud WAF)。安恒明御 WAF 是国内驻场护网中出现频率较高的国产 WAF 之一，字段命名在 6.x 版本引入统一，早期 5.x 版本存在 `attack_source_ip / attacker` 这类稍冗长的命名。
- **常见导出方式**：
  - Web 页面攻击日志 → 导出（JSON / CSV / Excel）
  - 明御 WAF OpenAPI（`/api/v6/attackLog/query`）拉取
  - Syslog Forward，格式为明御私有 KV 或 CEF
  - 明御周报邮件附件（.xlsx，需转 CSV）
- **常见文件扩展名**：
  - `.json`：明御导出的 JSON 结构类似 SIP，顶层 `{"result": [...], "total": N}`，需要取 `.result`
  - `.csv`：表头中文，字段与 JSON 命名接近但需要中英映射
  - `.xlsx`：明御周报格式，需转 CSV
- **明御的 `result` 包裹层**：与 SIP 的 `data` 类似的包裹结构，vendor_field_mapper.py 需要检测并展开。

## 二、字段对照表（详版）

| skill 标准字段 | 厂商字段名（JSON） | CSV 表头（中文） | 备注 |
|---|---|---|---|
| ts | attack_time / event_time / occur_time | 攻击时间 / 事件时间 | 明御默认 `YYYY-MM-DD HH:mm:ss` 本地时间，5.x 部分版本用秒级 epoch |
| src_ip | src_ip / attack_source_ip / attacker | 攻击源IP / 攻击者 | 5.x 冗长命名，6.x 之后统一 `src_ip` |
| dst_ip | dst_ip / target_ip / protected_ip | 目标IP / 被保护资产IP | 明御强调"被保护资产"概念，字段名带 `protected_` |
| dst_port | dst_port / target_port / server_port | 目标端口 | 数值 |
| proto | protocol / l7_protocol | 协议 | http / https（明御是 WAF，L4 固定） |
| rule_name | attack_type_name / rule_name / event_name | 攻击类型 / 规则名称 | 明御规则名多为中文，例如"SQL 注入攻击" |
| severity | threat_level / severity | 威胁等级 / 风险等级 | 明御用中文四级：致命/高/中/低 或数值 4/3/2/1 |
| payload | attack_content / match_content | 攻击内容 / 命中内容 | 明御默认截断 512 字节，5.x 部分版本 256 字节 |
| user_agent | user_agent / http_user_agent | User-Agent | 明御从请求头抽取 |
| username | user / login_id | 账号 / 登录ID | 认证类事件才有 |
| hostname | protected_host / target_domain | 被保护主机 / 目标域名 | 明御的资产管理是核心卖点，通常已挂业务命名 |
| action | disposal / block_action | 处置动作 / 阻断动作 | 明御 action 中文枚举：拦截 / 告警 / 放行；编码：block/alert/pass |

## 三、severity 映射说明

- 明御 WAF 使用中文四级：致命 / 高 / 中 / 低 (部分版本用"紧急/高危/中危/低危" 或 "高/中/低" 三级)。
- 部分 API 返回数值 4/3/2/1。
- **保守分级建议**：
  - 明御 "致命 / 紧急" → skill `P0`。
  - 明御 "高 / 高危" → **`P0` 而非 P1**！这是明御的特殊之处：明御 WAF 的"高"级别通常已经是"确认命中且拦截失败"的场景，不同于 QAX/SIP 的"疑似高危"。驻场首日应与客户确认此语义，如客户明御规则库未特殊调优，可能需要下调到 P1。本抽屉默认按明御标准语义映射到 P0。
  - 明御 "中 / 中危" → `P2`。
  - 明御 "低 / 低危 / 提示 / 信息" → `P3`。
- **边界注意**：明御 "高" 到 P0 的映射比 QAX 更激进，驻场首日必须与客户确认该映射。如果客户明御规则库有大量"高"级别但历史误报率高，本抽屉可临时降级到 P1。
- 数值 3 映射到 P1（做保守中间档），是为 CSV 里的数值型 severity 场景提供缓冲。

## 四、category 映射说明

- 明御的攻击类型枚举细致且中英夹杂（例如"Struts2 漏洞利用 / Log4j2 漏洞利用"直接点名 CVE 类目），本抽屉尽量按具体漏洞类目映射。
- **常见坑**：
  - 明御把"Weblogic 漏洞利用 / Struts2 漏洞利用 / Spring 漏洞利用"作为独立 category，本抽屉全部归入 `rce`。
  - "Webshell 管理" 归入 `webshell`（管理 = 已落地 webshell 的 C2 通信）。
  - "CSRF 攻击" 归入 `其他`。
  - "文件包含攻击" 归入 `rce`（同 QAX/SIP 处理）。
- **不可归类**：落到 `其他`。

## 五、常见误报模式（vendor-specific）

明御 WAF 在驻场值守中常见误报 pattern：

1. **明御规则库"过拟合"业务参数**：明御规则库以"细"著称（规则数量国内 WAF 中较多），部分规则对合法业务参数敏感。例如"命令注入攻击"规则会命中含 `;` 或 `|` 的合法业务参数（如 CSV 导出接口 `format=csv;utf8`）。识别特征：payload 只含少量特殊符号 + status 200 + dst 是业务 API。
2. **API 网关健康检查触发扫描器识别**：客户 K8s / 微服务架构下的健康检查探针（如 `/actuator/health / /healthz / /liveness`）会被明御判为"敏感文件扫描"。识别特征：请求路径固定 + 高频（>1/秒）+ src 是内部段。
3. **明御自身探测流量误报**：明御 WAF 内置自检探针会向后端发送测试流量，部分场景下自检流量被记为攻击日志（"内部自检 / 探测请求"）。识别特征：src_ip 是明御设备管理段 + rule_name 含"探测 / 自检"。
4. **业务动态生成 JS 命中"XSS 存储"**：客户业务动态生成 JS 代码（例如动态路由、模板引擎输出）会命中 XSS 存储型规则。识别特征：dst 是业务动态 JS 端点 + payload 是合法 JS 代码。
5. **报表导出接口触发"敏感数据泄露"**：明御的"敏感数据泄露"规则监控响应体大小和敏感关键字（手机号、身份证号），业务报表导出场景会大量命中。识别特征：dst 是报表接口 + response size 大 + src 是内部用户段。

## 六、驻场对接实操建议（3-5 条）

1. **明御"高"映射校准**：明御"高"级别在不同客户规则库下语义差异大，驻场首日必须抓一份最近 24h 的"高"级别告警样本，人工分诊 50 条计算 TP/FP 比例；若 FP > 30%，则临时把明御"高"映射到 P1 而非 P0。
2. **导出粒度**：明御建议单批 ≤ 8h（明御告警密度高，24h 单批容易超过 20 万条）；驻场时按"致命 + 高"筛选，中低批量归档。
3. **规则库版本对齐**：明御规则库更新频率月度，rule_name 变化较大。驻场首日必须导出一份明御规则库快照（Web 页面 → 规则库 → 导出），与 category_map 对齐。
4. **payload 截断补全**：明御 payload 默认截断 512 字节（部分老版本 256），驻场时应申请客户在明御后端开启"完整报文留存"（明御 6.x 起支持存 8KB）；如无法开启，audit 阶段依赖 access.log 或 pcap 补全。
5. **多站点场景**：明御大客户常见"多域名多站点"部署，`protected_host / target_domain` 字段是站点标识；vendor_field_mapper.py 保留 target_domain 作为 hostname，同时主会话应按 domain 分组关联，避免跨站点告警混淆。

## 七、已知不确定的字段（驻场时校准）

- `attack_stage` / `attack_chain_id`：明御 6.x 部分版本引入攻击链关联字段，但字段名和取值枚举各客户实施差异较大，本抽屉未映射。
- `false_positive_marked`：客户历史标注的误报字段（明御支持二次标注），本抽屉未映射，可作为 skill false_positive_prob 的先验证据。
- `response_body_leaked`：明御 6.x "数据泄露"事件会输出响应体片段字段，字段名各版本不一（`leaked_data / response_snippet / body_leak`），驻场时校准。
- `attack_chain_stage`：明御 7.x 试点版本引入 ATT&CK-based 攻击阶段标签，本抽屉未映射，属于加分项。

## 八、字段抽屉小结

- field_map 共 12 个 skill 标准字段，每字段列 4-6 个别名（兼顾明御 5.x/6.x/7.x 命名差异）。
- severity_map 覆盖中文四级 + 数值 + 英文，共 17 条，注意"高"映射到 P0 的激进策略。
- category_map 覆盖 37 条常见攻击类型（明御按具体 CVE 类目细分，本抽屉逐条映射到 rce 大类）。
- 明御 WAF 的关键校准点是"高"级别的严重度语义（驻场首日必须评估 TP/FP 比）和多站点场景下的 target_domain 归组。
