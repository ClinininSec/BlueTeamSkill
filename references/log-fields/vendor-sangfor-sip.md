---
vendor_name: sangfor-sip
display_name: 深信服 SIP
alert_export_formats: [json, csv]
field_map:
  ts: [alarm_time, event_time, detect_time, log_time, first_time, last_time, "@timestamp"]
  src_ip: [src_ip, attacker_ip, source_ip, atk_src_ip, s_ip, srcip, src_addr]
  dst_ip: [dst_ip, victim_ip, target_ip, atk_dst_ip, d_ip, dstip, dst_addr]
  dst_port: [dst_port, target_port, dest_port, victim_port, dport]
  proto: [protocol, proto, l4_proto, app_protocol]
  rule_name: [rule_name, event_name, alarm_name, threat_name, signature, sig_name]
  severity: [severity, threat_level, risk_level, alarm_level, level]
  payload: [payload, packet_content, request_content, match_content, evidence, raw_content]
  user_agent: [user_agent, http_user_agent, ua]
  username: [username, user, account, login_name]
  hostname: [hostname, asset_name, dst_host, target_host, endpoint_name]
  action: [action, disposal, response_action, block_status, handle_action]
severity_map:
  高危: P0
  高: P1
  中危: P2
  中: P2
  低危: P3
  低: P3
  信息: P3
  提示: P3
  4: P0
  3: P1
  2: P2
  1: P3
  critical: P0
  high: P1
  medium: P2
  low: P3
  info: P3
category_map:
  Web攻击-WebShell: webshell
  WebShell检测: webshell
  WebShell上传: webshell
  WebShell通信: webshell
  Web攻击-SQL注入: sqli
  SQL注入攻击: sqli
  SQL盲注: sqli
  Web攻击-命令注入: rce
  命令执行: rce
  命令执行漏洞: rce
  远程代码执行: rce
  反序列化攻击: rce
  Log4j2利用: rce
  Fastjson利用: rce
  Struts2利用: rce
  Shiro反序列化: rce
  暴力破解攻击: brute-force
  弱口令: brute-force
  账号爆破: brute-force
  端口扫描: recon
  漏洞扫描: recon
  Web漏洞扫描: recon
  信息探测: recon
  横向移动: lateral
  内网横向: lateral
  数据泄露: data-exfil
  敏感信息外传: data-exfil
  异常外联: data-exfil
  XSS攻击: 其他
  文件包含: rce
  目录遍历: 其他
---

# 深信服 SIP 告警字段抽屉

## 一、告警数据格式概览

- **平台版本兼容说明**：本抽屉参考 Sangfor SIP（安全感知平台）从 3.x 到 5.x 的告警字段格式。SIP 3.x（2021 前）和 SIP 5.x（2023+）字段命名有较大差异，例如早期字段前缀 `atk_` 在新版本中被去掉；本抽屉同时兼容两种命名。
- **常见导出方式**：
  - Web 页面告警中心 → 事件详情 → 导出（JSON / CSV / Excel）
  - SIP OpenAPI（`/api/v3/event/query`）拉取，返回 JSON
  - Sangfor 云端联动模式：SIP 会把告警推到深信服云端，客户可申请下发到本地（离线场景不用）
  - Syslog Forward，格式为 LEEF 或 Sangfor 私有格式
- **常见文件扩展名**：
  - `.json`：SIP 告警中心默认导出；顶层为 `{"data": [...], "total": N}` 结构，需要先取 `.data` 数组
  - `.csv`：SIP 报表导出，表头中文，字段与 JSON 略有出入
  - `.xlsx`：SIP 周报 / 月报附件，需转 CSV 使用
- **SIP 的 `data` 包裹层**：与 QAX 顶层数组不同，SIP JSON 是包裹层结构，vendor_field_mapper.py 需要在解析时检测 `data` 键并展开。

## 二、字段对照表（详版）

| skill 标准字段 | 厂商字段名（JSON） | CSV 表头（中文） | 备注 |
|---|---|---|---|
| ts | alarm_time / event_time / first_time | 告警时间 / 首次发生时间 | SIP 采用 epoch 毫秒或 `YYYY-MM-DD HH:mm:ss`；epoch 需要转 ISO8601 |
| src_ip | src_ip / atk_src_ip | 攻击源IP / 源IP | SIP 3.x 前缀 `atk_`，5.x 去除 |
| dst_ip | dst_ip / atk_dst_ip | 受害IP / 目的IP | 同上 |
| dst_port | dst_port / target_port | 目的端口 | 数值 |
| proto | protocol / app_protocol | 协议 | tcp / udp / http / https / dns / ssh |
| rule_name | event_name / threat_name / sig_name | 威胁名称 / 事件名称 | SIP 规则名多为中文，例如"检测到 SQL 注入攻击" |
| severity | threat_level / severity | 威胁等级 / 风险等级 | SIP 用中文三级"高危/中危/低危" 或数值 3/2/1（5.x 部分版本引入"信息 / 提示"共 5 档） |
| payload | packet_content / match_content | 报文内容 / 命中特征 | SIP 默认截断 1024 字节，比 QAX 略长 |
| user_agent | http_user_agent / user_agent | User-Agent | Web 类告警才有 |
| username | user / login_name | 账号 / 登录名 | 认证 / 暴破类告警才有 |
| hostname | asset_name / dst_host | 资产名称 / 目标主机 | SIP 有内置 CMDB，命中则填业务命名 |
| action | disposal / block_status | 处置状态 / 阻断状态 | SIP 编码：blocked/notblocked/monitor/allow；CSV 里中文"已阻断/未阻断/仅监控" |

## 三、severity 映射说明

- SIP 主用三级：高危 / 中危 / 低危；SIP 5.x 部分版本引入五级：高危 / 中危 / 低危 / 信息 / 提示。
- 部分 API 返回数值 3/2/1（对应高/中/低）或 4/3/2/1（五级）。
- **保守分级建议**：
  - SIP "高危" 是最高档（没有"紧急"档），映射到 skill `P0`。SIP 高危规则通常已经过 SIP 内部关联引擎升级，误报率相对低于 QAX 高危。
  - SIP "中危" → `P2`。
  - SIP "低危 / 信息 / 提示" → `P3`。
  - 缺少 P1 中间档：驻场值守时若发现"高危"数量过多，可结合 `false_positive_prob` 或 SIP 内部 `confidence` 字段（3.x 无，5.x 引入）自动降级到 P1。
- **边界注意**：SIP "高危" 不等同 QAX "紧急"。SIP 高危里包含较多"疑似"类事件，但已经过 SIP 内部关联判定，直接映射 P0 是合理保守策略。

## 四、category 映射说明

- SIP 使用中文攻击类型分类字段 `event_type / threat_type`，本抽屉覆盖 ≥ 30 条常见枚举。
- **常见坑**：
  - SIP 分类字段常带"Web 攻击-"前缀（例如"Web 攻击-SQL 注入 / Web 攻击-WebShell"），vendor_field_mapper.py 需要做前缀去除或前缀 + 正文双向匹配。
  - "文件包含"归入 `rce`（同 QAX 处理）。
  - "目录遍历" 归入 `其他`（因 skill category 无 path-traversal 独立分类），主会话生成 evidence 时应保留"目录遍历"原描述。
  - "XSS 攻击" 归入 `其他`（同 QAX）。
- **不可归类**：落到 `其他`，vendor_field_mapper.py 在末尾打印未映射统计。

## 五、常见误报模式（vendor-specific）

SIP 在驻场值守中常见误报 pattern：

1. **"新型攻击" AI 引擎误报**：SIP 5.x 内置 "深度学习检测引擎"，会输出 `新型未知攻击` 类目。识别特征：event_name 含"AI 检测 / 深度学习 / 未知威胁" + confidence < 0.7 + 无具体 rule_id。这类事件在驻场首次接入时建议全量降级为 P3 观察 72 小时再评估。
2. **业务 API 长参数触发"SQL 注入"**：SIP 部分 SQL 注入规则对含 `select / union / order` 字符的业务参数（例如 REST API 里的 `orderBy=create_time`）敏感。识别特征：dst 是业务 API 网关 + status 200 + 参数是明确业务字段名。
3. **反向代理链路触发"异常访问"**：SIP 部分版本对经过多层反向代理的请求（源 IP 是 CDN / Nginx 前置）判为"异常访问"或"非法来源"。识别特征：src_ip 是 CDN / 反代节点段 + 目标是业务 Web。
4. **DNS 缓存投毒误报**：SIP DNS 检测规则对客户内部 DNS 转发场景敏感（内部 DNS 返回外部 DNS 解析结果被判"缓存投毒"）。识别特征：dst_ip 是内部 DNS 服务器 + 源是客户端段 + 域名是白名单业务域名。
5. **合规扫描期"漏洞利用尝试"批量告警**：SIP 对内部合规扫描器（如客户自建 Nessus / 绿盟 RSAS）无白名单时会批量告警。识别特征：源 IP 固定 + 目标扫描面广 + 时段规律（每周固定时间）。

## 六、驻场对接实操建议（3-5 条）

1. **导出粒度**：SIP 建议单批 ≤ 12h（因 SIP 告警密度高于 QAX，24h 单批容易超过 10 万条），并在导出时按"高危 + 中危"筛选，低危批量归档。SIP 的 JSON 是包裹 `.data` 结构，脚本需检测并展开。
2. **时间戳格式**：SIP 5.x 大量使用 epoch 毫秒，vendor_field_mapper.py 需检测数值型时间戳并自动转 ISO8601。SIP 3.x 使用本地时间字符串，需要额外指定时区。
3. **payload 完整度**：SIP 1024 字节截断比 QAX 略好，但仍不够 audit；驻场应申请开启 SIP 的"原始报文留存"（受磁盘容量限制，客户常不开），否则 audit 阶段依赖 pcap 补全。
4. **规则库版本差异**：SIP 规则库更新频率高于 QAX（月度），rule_name 变化较大。驻场首日必须与客户驻场安全工程师对齐当前规则库版本，导出一份规则清单存档。
5. **AI 检测引擎去噪**：SIP 5.x 的 AI 引擎在没做企业化调优前误报率高。驻场首周建议在 vendor_field_mapper.py 输出后追加过滤：`event_name` 含 "AI / 深度学习 / 未知威胁" 的告警自动降级到 P3，随后 72 小时评估是否重新纳入正式分诊。

## 七、已知不确定的字段（驻场时校准）

- `confidence` 字段：SIP 5.x 引入 AI 检测置信度（0.0-1.0），本抽屉未纳入 field_map 因为标准 8 字段 schema 无对应字段；audit / monitor 阶段可作为附加权重，驻场首日确认字段名。
- `kill_chain_stage` / `attack_stage`：SIP 5.x 输出攻击链阶段（侦察 / 立足 / 提权 / 横向 / 持久化 / 目的达成），字段名各版本略有差异，本抽屉暂不映射，驻场时可作为 tag 补充。
- `related_events` / `event_group_id`：SIP 内部关联的相关事件 ID 列表；本抽屉未使用（skill 有自己的关联引擎），但驻场时可作为 SIP 已判定的攻击链证据参考。

## 八、字段抽屉小结

- field_map 共 12 个 skill 标准字段，每个字段列出 4-7 个别名（兼容 SIP 3.x / 5.x）。
- severity_map 覆盖中文三级 + 五级 + 数值 + 英文，共 17 条。
- category_map 覆盖 30 条常见事件类型（包含 "Web 攻击-" 前缀变体）。
- SIP 特有的 AI 检测引擎和 kill_chain_stage 字段是本抽屉的重点校准点，驻场首日必须与客户对齐。
