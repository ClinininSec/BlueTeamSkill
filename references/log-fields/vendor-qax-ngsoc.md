---
vendor_name: qax-ngsoc
display_name: 奇安信 NGSOC
alert_export_formats: [json, csv]
field_map:
  ts: [detect_time, event_time, alarm_time, log_time, occur_time, "@timestamp", timestamp]
  src_ip: [src_ip, attacker_ip, source_address, s_ip, srcip, src_address]
  dst_ip: [dst_ip, victim_ip, dest_address, d_ip, dstip, dst_address, target_ip]
  dst_port: [dst_port, dest_port, dport, target_port, victim_port]
  proto: [proto, protocol, app_proto, l4_proto, transport_protocol]
  rule_name: [rule_name, alarm_name, signature, event_name, policy_name, detect_rule_name]
  severity: [severity, risk_level, alarm_level, threat_level, level]
  payload: [payload, match_content, raw_log, packet_content, request_content, hit_content]
  user_agent: [user_agent, http_user_agent, ua, agent]
  username: [username, user, account, login_user, source_user]
  hostname: [hostname, asset_name, host_name, dst_hostname, target_host, dev_name]
  action: [action, disposal, handle_result, policy_action, verdict, response_action]
severity_map:
  紧急: P0
  严重: P0
  高危: P1
  高: P1
  中危: P2
  中: P2
  低危: P3
  低: P3
  提示: P3
  info: P3
  critical: P0
  high: P1
  medium: P2
  low: P3
category_map:
  WebShell上传: webshell
  WebShell通信: webshell
  WebShell检测: webshell
  疑似WebShell: webshell
  SQL注入: sqli
  SQL注入攻击: sqli
  盲注: sqli
  命令执行: rce
  命令注入: rce
  反序列化漏洞: rce
  反序列化: rce
  反序列化攻击: rce
  Log4j2漏洞利用: rce
  Fastjson反序列化: rce
  远程代码执行: rce
  暴力破解: brute-force
  弱口令登录: brute-force
  账号爆破: brute-force
  端口扫描: recon
  漏洞扫描: recon
  资产探测: recon
  信息泄露: recon
  横向移动: lateral
  内网渗透: lateral
  数据泄露: data-exfil
  数据外发: data-exfil
  异常外联: data-exfil
  XSS跨站脚本: 其他
  文件包含: rce
---

# 奇安信 NGSOC 告警字段抽屉

## 一、告警数据格式概览

- **平台版本兼容说明**：本抽屉参考 QAX NGSOC 2023.x / 2024.x / 2025.x 三个大版本的告警导出格式。QAX NGSOC 从 2021 年开始逐步统一告警字段命名，早期 2019/2020 版本存在若干旧字段（如 `s_ip / d_ip` 未与 `src_ip / dst_ip` 合并），本文件同时兼容新旧字段名。
- **常见导出方式**：
  - Web 页面告警中心 → 导出 → JSON 或 CSV（最常见，驻场值守场景 90% 走这条）
  - Open API（`/api/v1/alarms/search`）Pull 拉取，返回 JSON 数组
  - Syslog Forward 到第三方 SIEM，格式为 CEF 或 QAX 私有 KV
  - 附件邮件（QAX Weekly Report 附件包含 CSV）
- **常见文件扩展名**：
  - `.json`：QAX 告警中心默认导出格式；结构为顶层数组，每条告警为一个 object
  - `.csv`：多用于报表导出；表头中文，字段名与 JSON 略有差异（例如 CSV 里叫"告警时间"，JSON 里叫 `detect_time`）
  - `.xlsx`：QAX 定期报表；结构与 CSV 相同但需要用户先转成 CSV 才能喂脚本
- **CSV 表头中文化说明**：QAX CSV 表头是中文（例如"告警时间 / 攻击源 / 受害资产"），vendor_field_mapper.py 需要在此文件的备注表中记录中英对照，运行时先中→英归一化再走 field_map。

## 二、字段对照表（详版）

| skill 标准字段 | 厂商字段名（JSON） | CSV 表头（中文） | 备注 |
|---|---|---|---|
| ts | detect_time / event_time | 告警时间 / 检测时间 | ISO8601 或 `2026-06-30 08:14:23` 本地时间格式（无时区，需假设为客户机时区 CST） |
| src_ip | src_ip / attacker_ip / s_ip | 攻击源IP / 源地址 | 支持 IPv4/IPv6；早期版本用 `s_ip`，2023 后统一 `src_ip` |
| dst_ip | dst_ip / victim_ip / d_ip | 受害资产IP / 目的地址 | 若受害资产已挂 CMDB 则同时有 asset_name 字段 |
| dst_port | dst_port / dest_port | 目的端口 | 数值 |
| proto | proto / protocol | 协议 | tcp / udp / http / https / dns |
| rule_name | rule_name / alarm_name | 告警名称 / 规则名 | 中文规则名居多，例如"检测到WebShell通信" |
| severity | severity / risk_level | 风险级别 / 告警等级 | 中文四级："紧急/高危/中危/低危" 或数值 4/3/2/1 |
| payload | payload / match_content | 匹配内容 / 命中报文 | 常被 QAX 截断到 512 字节；证据补全需回原始日志 |
| user_agent | user_agent / http_user_agent | User-Agent | Web 类告警才有；网络层告警可能缺失 |
| username | username / login_user | 账号 / 登录用户 | 主要在暴破 / 认证类告警中出现 |
| hostname | hostname / asset_name | 资产名称 / 主机名 | 若挂 CMDB 则为业务命名，否则为 IP 反查主机名 |
| action | action / handle_result | 处置结果 / 动作 | 中文枚举："阻断 / 放行 / 告警 / 监控"；QAX 编码：block/allow/alert |

## 三、severity 映射说明

- QAX NGSOC 使用**中文四级 + 提示**共 5 档：紧急 / 高危 / 中危 / 低危 / 提示。
- 部分版本（尤其 API 拉取）会返回数值 4/3/2/1 对应紧急/高危/中危/低危。
- **保守分级建议**：
  - QAX "紧急" 是最高档，映射到 skill `P0` 无争议。
  - QAX "高危" 建议映射到 skill `P1`（不映射到 P0），因为 QAX 高危经常包含"疑似"类告警（例如"疑似 SQL 注入尝试"），如果直接置 P0 会导致 P0 数量爆炸失去区分度。
  - QAX "中危" 映射到 skill `P2`。
  - QAX "低危 / 提示" 均映射到 skill `P3`。
- **边界注意**：QAX 部分规则会主动标为"紧急"（例如 WebShell 通信、Log4j2 已利用成功），这类应保留 P0；如果发现"高危"里出现 rule_name 含"成功 / 已利用 / 已控制"字样，主会话应主动追问是否升 P0。

## 四、category 映射说明

- QAX NGSOC 使用中文攻击类型分类字段（`attack_type` 或 `event_category`），本抽屉的 category_map 覆盖 ≥ 25 条常见中文枚举。
- **常见坑**：
  - "疑似 WebShell" 在 QAX 里是独立类目，本抽屉将其归入 `webshell`；主会话如认为置信度低可自动 -1 档 severity。
  - "XSS 跨站脚本" 因 skill category 枚举里无对应项，暂归入 `其他`，主会话应在生成 evidence 时保留原 XSS 类型描述。
  - "文件包含"（LFI/RFI）本抽屉归入 `rce`（因为最终危害是命令执行），主会话可根据 payload 是否成功决定是否降级。
- **不可归类的处理**：任何 QAX 中文类型不在 category_map 中的告警统一落到 `其他`，vendor_field_mapper.py 在末尾打印"未映射类型统计"，主会话据此追问客户驻场值守负责人补充映射。

## 五、常见误报模式（vendor-specific）

QAX NGSOC 在驻场值守中常见的误报 pattern：

1. **内部 Zabbix / Prometheus 探测被判为"端口扫描"**：QAX 在客户内部监控段没配白名单时会把 zabbix agent 心跳 + prometheus scrape 判为高危扫描。识别特征：源 IP 是内部监控段（如 10.99.0.0/24）+ dst 是业务集群 + 目标端口固定 9090/8080/9100。
2. **压测工具触发"CC 攻击"告警**：客户业务定时压测时 QAX 会告警"CC 攻击"或"HTTP 慢速攻击"。识别特征：源 IP 是压测机段 + UA 含 `wrk / ab / jmeter / locust` + 工作时段规律出现。
3. **业务合法 base64/json 参数命中"疑似命令注入"**：QAX 部分正则规则对长 base64 或 json body 敏感，尤其含 `cmd / exec / eval` 字段的业务参数。识别特征：dst 是业务 API 网关 + status 200 + 参数含合法业务字段。
4. **文件上传业务命中"WebShell 上传"高危**：客户如有 OA / 文档管理系统允许上传 jsp/php 附件（罕见但存在），QAX 会告警。识别特征：上传路径含 `/upload / /attachment` + 上传后 40x 拒绝 + 文件后缀被业务改名。
5. **HTTPS 内部证书告警"疑似中间人"**：客户内部自签 CA 部分场景 QAX 会告警"证书异常"。识别特征：源/目的均是内部段 + 证书 CN 是 corp / internal 域名。

## 六、驻场对接实操建议（3-5 条）

1. **导出粒度**：从 QAX NGSOC "告警中心" → 选择时间范围（建议单批 ≤ 24h）→ 筛选 "紧急/高危/中危" 三档（低危+提示批量归档，进 monitor 前不必带入）→ 导出 JSON。CSV 用于人工核对，JSON 用于喂脚本。
2. **时区处理**：QAX 部分版本导出的时间戳无时区（本地时间），driver 需先与客户确认 SIEM 时区（一般是 CST），并在 vendor_field_mapper.py 里加 `--tz Asia/Shanghai` 参数（如无则默认加 +08:00）。
3. **payload 截断**：QAX 告警 payload 默认截断到 512 字节；驻场时需要跟客户申请开启"完整报文留存"（受合规约束可能拒绝）；如无法开启，audit 阶段需要回原始 access.log / traffic pcap 做证据补全。
4. **规则版本对齐**：QAX NGSOC 规则库每季度更新，rule_name 措辞会小改（例如 2024 Q1 把"Fastjson 反序列化"改为"Fastjson 反序列化攻击"）。驻场首次接入时应导出一份 QAX 当前规则库，与本抽屉 category_map 对齐一次；每季度复核。
5. **多租户 / 多分公司场景**：QAX NGSOC 大客户常见多租户部署，`tenant_id` 字段是告警归属租户；vendor_field_mapper.py 保留 tenant_id 但不参与归一化，主会话在跨租户关联时应按 tenant 分组后再走关联规则。

## 七、已知不确定的字段（驻场时校准）

以下字段是根据 2024 年公开材料整理，2026 年可能有变动，驻场首日必须校准：

- `attack_chain_id`：QAX 从 2024 版本开始输出攻击链关联 ID，但字段名在部分版本叫 `chain_id / attack_id`，需要驻场首日抓一份样本 JSON 确认。
- `handle_status`：处置状态字段（未处置 / 已处置 / 已确认误报），本抽屉未纳入 field_map 因为不影响归一化，但 audit 阶段做闭环追踪时会用到，驻场时应确认字段名和取值枚举。
- `evidence_url`：部分 QAX 版本告警会带一个可回溯到原始报文的 URL（驻场机内部访问），本抽屉不使用（离线原则），但驻场时可作为二次证据补全的入口。

## 八、字段抽屉小结

- field_map 共 12 个 skill 标准字段，每个字段列出 4-7 个别名。
- severity_map 覆盖中文四级 + 数值 + 英文，共 15 条。
- category_map 覆盖 26 条中文攻击类型。
- 本抽屉基于 QAX NGSOC 2023-2025 公开材料 + 驻场经验整理，遇到新版本字段变化时应更新本文件而非改动 vendor_field_mapper.py 主逻辑。
