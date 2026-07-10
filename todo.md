# hvv-defender 路线图 / TODO

> 规则源扩充 + 能力增强的后续规划。本期已完成项标 ✅，待办按优先级分档。

## ✅ 已完成（v0.4-M2 进行中）

### 阶段 0：激活死规则（让 JSON 规则真正告警）
- ✅ `evtx_hunt.py` sysmon 规则激活 emit → 新增 `R-WIN-023`（sysmon 补充规则命中告警）
- ✅ `evtx_hunt.py` persistence 规则新增消费 → 新增 `R-WIN-024`（持久化位置命中告警）
- ✅ `traffic_anomaly.py` tls 分发补 `ja3`/`ja3s`/`cipher` case → `SIG-TRAF-087+` JA3 签名生效
- ✅ `pcap_parser.py` view_tls 补 `tls.handshake.ja3`/`ja3s` 输出 → JA3 数据流打通

### 阶段 1：国外通用规则源接入
- ✅ `scripts/feeds/sync_owasp_crs.py` — OWASP CRS 通用 Web 攻击正则 → `traffic-signatures.json`
  - 解析 SecRule `@rx`，提取 SQLi/RCE/XSS/LFI/RFI 通用正则，转 http view 条目
  - 状态机解析器（正确处理转义双引号 + 续行），Python re 兼容性校验

## 🟡 高优先级（近期）

### 规则源扩充
- [ ] `sync_yara.py` — YARA 通用 webshell 规则（bartblaze/Neo23x0）→ `webshell-patterns.json`
  - 解析 YARA `strings:` 提取正则/字符串，转 Python re（注意 webshell_scan 用 `MULTILINE|DOTALL`，大小写敏感需自带 `(?i)`）
- [ ] `sync_webshell_traffic.py` — 国内 webshell 管理工具流量特征 → `traffic-signatures.json`
  - 源：xiecat/wsm、minhangxiaohui/DecodeSomeJSPWebshell、xiaopan233/AntSword-Cryption-WebShell
  - 提取 Behinder/Godzilla/AntSword/Knife 通信特征（UA/URI/参数名/编码模式）
- [ ] `sync_kunpeng.py` — 国内漏洞 POC（opensec-cn/kunpeng）→ `tool-signatures.json` payload 段
  - 解析 Go POC，提取 FastJSON/Shiro/Struts2/Spring/WebLogic/泛微/通达/用友 检测特征
- [ ] `sync_cn_tools.py` — 国内红队/穿透工具流量 → `traffic-signatures.json`
  - 补充 frp/nps/chisel/stowaway/suo5/reGeorg/gost/fscan/goby/xray/nuclei/yakit/viper 特征
- [ ] `sync_sigma.py` — Sigma 通用 Windows 检测规则 → `sysmon-detection-rules.json`
  - 解析 Sigma detection 语法（`|contains`/`|endswith`/`|re`）转 Python 正则；按 level high + ATT&CK tag 策展
- [ ] `sync_et_open.py` — ET Open 通用流量规则 → `traffic-signatures.json`
  - 解析 Suricata `pcre:`/`content:`，按 msg 分类

### 消费端补强
- [ ] `traffic_anomaly.py` flow 分发补 `payload_first_bytes` case
  - 激活 frp/nps 等工具的握手字节检测（当前 flow view 只认 `dst_port`，握手字节是死字段）
- [ ] `evtx_hunt.py` persistence `detection_type` 42 枚举全分支消费
  - 当前 R-WIN-024 只按 `location` contains 匹配，未按 `detection_type` 分流

## 🟢 中优先级（中期）

### 国产设备扩充
- [ ] vendor_field_mapper 扩充第 5-6 家厂商抽屉
  - 候选：绿盟 NIDS、天融信 NGTPS、启明星辰 IDS、华为乾坤、新华三 H3C
  - 每家需 `references/log-fields/vendor-<name>.md` frontmatter（field_map/severity_map/category_map）

### 国内威胁情报
- [ ] 国内威胁情报源离线打包
  - 候选：微步在线 / 奇安信威胁情报中心 / 360 威胁情报 / 安恒威胁情报 / 绿盟 NTI
  - 多数需注册 API key，与"离线优先"有张力——改为构建期拉取公开 IOC dump 落 `ioc-builtin.json`
- [ ] JA3 国内 C2 指纹扩充
  - CobaltStrike 中文社区 malleable profile + 各红队工具默认 ja3 → `traffic-signatures.json` (field=ja3)
- [ ] `webshell-patterns.json` 补国内 webshell 家族
  - b374k/c99/r57 中文变种 + 内存马特征（Tomcat/WebLogic filter 型）

### 数据治理
- [ ] 扫描器 UA 四处重复归一
  - sqlmap/nuclei/xray/nessus 等在 `ioc-builtin.json`+`traffic-signatures.json`+`tool-signatures.json`+`tool-fingerprints.md` 重复，归一到单源
- [ ] 规则 ID 命名空间文档同步
  - `rule-id-namespaces.md` 的 R-TRAF 条数（写"68 类"实际已到 098+999）需更新

## 🔵 长期（v0.5+）

- [ ] 规则映射 MITRE ATT&CK Technique ID
  - Sigma tags 已含 ATT&CK ID，透传到 finding；YARA/CRS 补 ATT&CK 映射
- [ ] feeds 定时同步 + 离线 bundle 完整性校验
  - CI 定期跑同步器，校验产物 JSON schema + 体积 + 离线可跑
- [ ] MCP 工具化 / 情报 API 接入
  - 规则查询、IOC 查询、pcap 分析 MCP 化
- [ ] AI 辅助规则挖掘 / 告警根因分析 / 多主机集群模式

## 红线（贯穿所有规则源）

- ❌ 不输出可复现的攻击 PoC payload — 同步器只提取检测特征（触发字段+关键词+正则模式）
- ❌ 不做破坏性操作 — 同步器只读上游、只写本地 `data/`
- ❌ 运行时不联网 — 同步器产物落 `data/`，检测脚本只读本地

## 版本节奏

- v0.4-M2（当前）：阶段 0 激活死规则 + OWASP CRS + 计划中的 6 个规则源同步器
- v0.4-M3：国产设备扩充 + 国内威胁情报离线包
- v0.5：MITRE ATT&CK 映射 + MCP 工具化
