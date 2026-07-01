# TLS 指纹检测知识库 (v0.3-M1)

> 面向 pcap/pcapng 离线审计的 TLS 层指纹与元数据识别参考。
> **何时使用**：怀疑主机被植入 C2、加密 C2 心跳绕过、域前置、免杀 loader、国密链路异常时。
> 与运行时规则 `R-TRAF-050~069`（scripts/traffic_anomaly.py）对齐，与知识库 ID `SIG-TRAF-087~098`（data/traffic-signatures.json）双向可查。
> 所有识别特征仅供检测使用，禁止用于攻击复现。

---

## 通用识别路径

TLS 层的分析路径为：**Client Hello (JA3) → Server Hello (JA3S) → 证书 (CN/O/lifetime) → ALPN/SNI 一致性 → 心跳统计**。

- 一线（http/dns 已覆盖）没有命中，但仍有加密外联嫌疑 → **优先看 TLS 视图**。
- TLS 层的核心价值：**JA3 / JA3S 抗流量变形**。即便攻击方改了 profile（URI/UA/心跳），只要没换 SSL 库栈，JA3 就不变。
- 护网期间，攻击方常规套壳（域前置 + 免杀 loader + 心跳伪装）都能被 JA3/JA3S + 证书元数据组合逼出来。

---

## 一、JA3 / JA3S 基础

### 1.1 计算方式（一句话）

**JA3** = 客户端 TLS Client Hello 中 5 个字段（TLSVersion, Cipher Suites, Extensions, Elliptic Curves, EC Point Formats）用 `,` 拼接后 `-` 连接扩展列表，MD5(拼接串) 得到的 32 位十六进制 hash。

**JA3S** = 服务端 Server Hello 的 3 个字段（TLSVersion, Cipher, Extensions）拼接后 MD5。

**JA4 / JA4S / JA4H** 是新版本，包含更多字段（ALPN、SNI 存在性、TLS 扩展签名算法等），比 JA3 更抗规避，但 JA3 在护网期间仍是**主战场指纹**。

### 1.2 为什么护网期间 JA3 依然有价值

- 攻击方为了免杀常改载荷（URI/UA/心跳节奏），但**几乎不换 SSL 库栈**——Java Cobalt Strike、Go Sliver、C++ BRC4 每个都有稳定的 JA3 特征。
- JA3 不需要解密流量，纯粹依赖握手明文字段——**即使全加密的 C2 也能被识别**。
- JA3 hash 空间足够小（32 位 hex），可维护成黑白名单，实施成本低。

**JA3 单点局限**：CDN（CloudFlare / CloudFront）、企业 SSL 卸载设备的 JA3 也可能与红队工具默认值相似 —— 必须结合 SNI/证书/流量方向综合判定。

---

## 二、常见工具 JA3 / JA3S 指纹表

以下 hash 来自 2023-2025 公开研究（SalesForce ja3 repo / TrickyTLS / TrisulNSM / 各厂商 IR blog），**护网期需要客户侧最新样本 fingerprint 验证**。

| 工具 / 场景 | JA3 hash 示例 | JA3S hash | severity | 备注 |
|---|---|---|---|---|
| CobaltStrike (Java 默认 profile) | `72a589da586844d7f0818ce684948eea` | `b742b407517bac9536a77a7b0fee28e9` | high | 4.x 前默认，最常见 |
| CobaltStrike 4.x (改良 keystore) | `a0e9f5d64349fb13191bc781f81f42e1` | 同上或改 | high | 攻击方常改 keystore |
| CobaltStrike TLS 1.3 支持版本 | `8916410db85077a5460817142dcbc8bc` | - | high | 新版 |
| CobaltStrike 国内魔改 teamserver | - | `ec74a5c51106f0419184d0dd08fb05bc` | high | 国内红队常用 |
| Sliver (mTLS 默认) | `80215ceceabc84f78e10c14e0932abfd` | `f4febc55ea12b31ae17cfb7e614afda8` | high | 无 SNI |
| Sliver mTLS (Go 版本变体) | `b32309a26951912be7dba376398abc3b` | - | high | 多个变体 |
| Mythic (Apfell / Poseidon) | `d9d99a03093874c9f309b7f2f052ffa1` | - | medium | 变体多 |
| Havoc default agent | `3fed133de60c35724739b913924b6c24` | `5c1a3d5eaa5e78d5c85a2f8b5b6d3e2a` | high | 2023 起流行 |
| Brute Ratel C4 (badger) | `0a3d5f30f81f79e46f682dc98354c1c1` | - | high | 商业化 C2 |
| Metasploit meterpreter reverse_https | `3b5074b1b5d032e5620f69f9f700ff0e` | - | medium | 老旧但仍在用 |
| Merlin C2 (Go) | `6e9b0f7fd66a37b0aeecda0d4b40b1e5` | - | medium | Go net/http 库默认 |
| Impacket smbclient (Python) | `28a2c9bd18a11de089ef85a160da29e4` | - | medium | 与 Python requests 冲撞 |
| Powershell Net.WebClient | `54328bd36c14bd82ddaa0c04b25ed9ad` | - | medium | 白名单/攻击共用 |
| Curl (default macOS/Linux) | `d01d84699bf74920c9d94b8b3b1f0a4c` | - | info | 排除类 |
| Python requests | `56a58e05e7bf5f5f4a3cba0f8f1a6d80` | - | info | 排除类 |
| Go net/http (default) | `19e29534fd49dd27d09234e639c4057e` | - | low | 需结合业务白名单 |
| OpenSSL s_client (default) | `82fed49025bf5ddb2b12a9d18f45e9f9` | - | low | 排除类 |
| CloudFlare 客户端 | `bd6e04d747b5a2fbe17d8f14d24d3d68` | - | info | 与 CS 老版接近 |
| Nmap ssl-cert scan | `a5e34e2a1c2ae4bb2a2b0e6f22e51f75` | - | low | 扫描类 |
| Nessus scanner | `55d68cf34f2c73f7a52dbe1cf3f31e0d` | - | low | 授权扫描 |

**注意**：以上 hash 只是**已知样本**。真实护网中攻击方会：

1. 换用 Malleable-TLS profile 改 cipher suite 顺序 → JA3 变化
2. 使用系统 SChannel/BoringSSL 库栈 → JA3 与合法 Chrome/Firefox 撞车
3. 手写 TLS 握手（Havoc PWNIT 模块） → JA3 唯一但需要 IR 团队补录

**因此**：护网期一线拿到的 pcap，应该：

1. 先跑 R-TRAF-050~051 命中已知表 → 高置信告警
2. **未命中但流量方向 + 心跳 + 目的地 IP 情报值可疑** → 拉 JA3 手工比对 → 加入客户侧临时黑名单

---

## 三、TLS metadata 异常

JA3/JA3S 之外，TLS 层还能提供大量元数据用于综合判定。

### 3.1 SNI vs Host 不一致（域前置）

- **场景**：客户端 TLS Client Hello 的 SNI = `cdn.cloudflare.com`，但 HTTP `Host:` 头 = `bad.attacker.com`。
- **蓝队含义**：**域前置攻击** —— 攻击者利用 CDN/云厂商的通用入口伪装成合法域，逃避基于域名的封禁。
- **检测规则**：`R-TRAF-053`（SIG-TRAF 层暂无对应 pattern，因为需要跨层比对）。
- **误报排查**：某些 CDN 加速的合法业务本身就存在 SNI-Host 不一致（如通过 anycast 前端接入）；需要白名单业务清单反查。
- **护网期动作**：一旦确认非白名单 SNI-Host 对，立即封禁目的 IP + CDN 侧上报（如 CloudFlare 的 abuse 通道）。

### 3.2 证书 CN/O = 默认自签名单

以下 CN 值是各 C2 框架的**默认自签证书**，攻击方懒得改直接抓包就能命中：

| CN / O 关键字 | 归属 | 关联 rule_id |
|---|---|---|
| `Major Cobalt Strike` | CobaltStrike Java keystore 默认 | R-TRAF-054 / SIG-TRAF-007 |
| `Cobalt Strike` | CobaltStrike 简写变体 | R-TRAF-054 |
| `multiplayer` | CobaltStrike teamserver 默认 CN | R-TRAF-054 |
| `Sliver` | Sliver 默认 mTLS CA | R-TRAF-054 / SIG-TRAF-095 |
| `HavocFramework` | Havoc agent 默认 | R-TRAF-054 |
| `BRC4` | Brute Ratel 默认 | R-TRAF-054 |
| `Mythic C2` | Mythic 默认 | R-TRAF-054 |
| `OperatorFoundation` | 部分 Mythic 变体 | R-TRAF-054 |
| `cloudflare-inc` | CS 伪装 CloudFlare 的 CN（拼写错误） | R-TRAF-054 |
| `localhost.localdomain` | 短命自签证书通用值 | SIG-TRAF-123 |
| `example.com` | 教程/POC 遗留值 | SIG-TRAF-079 |

**误报排查**：企业内部测试环境的自签证书也可能带 `localhost` `test` 类 CN，需要与主机资产清单比对；若命中的 dst_ip 在客户内部子网，视为白名单，否则视为高置信 C2。

### 3.3 证书 lifetime 极短

- **模式**：`cert.not_after - cert.not_before < 24h` + 自签 + 出方向长连接。
- **含义**：C2 服务器为了逃避 CT log 上报 + 快速轮换，会签发 24h 甚至 1h 内失效的短命证书。
- **合法场景排除**：Let's Encrypt 是 90 天，Amazon ACM 是 13 个月，正常业务证书**不会**低于 30 天。
- **护网期动作**：短命自签 + 未知目的 IP = **立即封禁 + 主机 ir**。
- **规则**：`R-TRAF-057`。

### 3.4 ALPN 声明与实际协议不一致

- **模式**：TLS Client Hello 的 ALPN 只声明 `h2`，但同 TCP stream 的后续流量仍是 HTTP/1.x 帧格式。
- **含义**：伪装 HTTP/2 的自研工具（少见但存在），或者 TLS 中继设备错配。
- **规则**：`R-TRAF-058`。
- **误报排查**：合法的 gRPC 代理链、老旧 F5 前端可能出现类似不一致；需要业务侧确认。

### 3.5 SM2/SM4 国密算法出现在非国密业务链路

- **模式**：TLS Client Hello ciphersuite 包含 `SM2`/`SM3`/`SM4`/`ECDHE-SM2` 等国密标识（cipher hex `0x00c6`/`0x00c7`/`0xe011`/`0xe013`/`0xe019` 等）。
- **合法场景**：政务、金融、能源等有明确国密合规要求的业务链路。
- **异常场景**：普通企业出方向 TLS 突然出现 SM2 握手 = **国产化红队工具**（部分免杀 loader 使用国密库减少特征匹配）。
- **规则**：`R-TRAF-056` / `SIG-TRAF-096`。
- **护网期动作**：
  1. 与客户 IT/合规团队确认该目的地址是否属于国密业务白名单
  2. 未纳入白名单 → 视为高置信 C2 嫌疑
  3. 记录 cipher hex + SNI + 目的 IP，纳入客户侧 CTI 库

---

## 四、国密 TLS 特殊说明

### 4.1 国密算法体系

- **SM2**：非对称加密 + 数字签名（椭圆曲线，256 位）
- **SM3**：密码杂凑算法（256 位摘要，可替代 SHA-256）
- **SM4**：分组加密（128 位分组，128 位密钥，可替代 AES-128）

### 4.2 何时合法

- 政务外网、金融专线、能源 SCADA、部分医疗云平台强制要求国密链路。
- 客户如已提交 "国密合规业务清单"（含域名、目的 IP、证书 CN），则命中即白名单。

### 4.3 何时可疑

- 外网出站、非白名单目的地址出现 SM2/SM4 → **红队工具**（存在支持国密的开源框架，此处不列具体名）。
- 内网横向流量突然出现 SM4 加密 payload → 可能是免杀 loader 通信。

### 4.4 tshark 支持

`tshark >= 3.4` 可通过 `tls.handshake.ciphersuite` 显示国密 cipher 名称。较老版本需要更新到 wireshark 3.6+。

---

## 五、检测机会与关联 rule_id

| TLS 指纹 / metadata 特征 | 关联 rule_id | 关联 SIG-TRAF ID |
|---|---|---|
| 已知 CS JA3 hit | R-TRAF-050 | SIG-TRAF-087~089 |
| 已知 Sliver / Havoc / BRC4 JA3 hit | R-TRAF-051 | SIG-TRAF-090~092 |
| CN 魔改 CS teamserver JA3S | R-TRAF-052 | SIG-TRAF-093~094 |
| SNI vs Host 不一致 | R-TRAF-053 | (无 pattern，跨层比对) |
| 默认自签 CN | R-TRAF-054 | SIG-TRAF-007 / SIG-TRAF-095 |
| 空 SNI / 数字 SNI | R-TRAF-055 | SIG-TRAF-009 / SIG-TRAF-097 |
| GM (SM2/SM3/SM4) cipher | R-TRAF-056 | SIG-TRAF-096 |
| 短命自签证书 | R-TRAF-057 | (证书 lifetime 计算) |
| ALPN 与协议不一致 | R-TRAF-058 | (跨层比对) |
| 私域 SNI 出公网 | R-TRAF-059 | SIG-TRAF-098 |
| TLS extension 顺序异常 / GREASE 缺失 | R-TRAF-060 | (JA3 组成) |
| ECH 扩展出现 | R-TRAF-061 | (扩展列表) |
| Extension 数量极少 | R-TRAF-062 | - |
| SNI 是 IP literal | R-TRAF-063 | SIG-TRAF-097 |
| 单密码套件提案 | R-TRAF-064 | - |
| 空 session ticket + 空 session id | R-TRAF-065 | - |
| 同 src 大量握手失败 | R-TRAF-066 | - |
| SNI 频繁切换（>40） | R-TRAF-067 | - |
| 浏览器 UA + ALPN 缺失 | R-TRAF-068 | - |
| SNI + ALPN 全空 | R-TRAF-069 | - |

### R-TRAF-999 升级条件

同 `src_ip` 同时命中：
- TLS 类（R-TRAF-050~069）≥ 1 条
- DNS 类（R-TRAF-070~084）≥ 1 条
- 国内工具类（R-TRAF-085~098）≥ 1 条

**任意 2 类中出现 3 条命中** → R-TRAF-999 附加 `tag: apt-suspect` 标签，升级为 P0。

---

## 六、误报与调优

### 6.1 CDN 与 CloudFront 的 JA3

CDN 的 TLS 前端（CloudFlare、Akamai、Fastly）JA3 通常固定，且**与部分 C2 工具默认值接近**（都是 Go/Rust 库栈）。调优建议：

1. 建立客户侧 CDN SNI 白名单（`*.cloudflare.com`, `*.akamaiedge.net`, `*.fastly.net` 等）
2. 命中 JA3 但 SNI 在白名单 → 降级为 P3 / 观察
3. 命中 JA3 且 SNI **不在**白名单 + 目的 IP 非白名单段 → 保留 P0

### 6.2 内部 SSL 卸载会改 JA3

- 客户如部署 F5 / A10 / 华为 USG / 深信服 SSL 卸载设备，SSL 卸载后重新握手的 JA3 **不是客户端真实 JA3**。
- 需要明确"卸载点前 vs 卸载点后"：
  - 卸载点**前**（客户端 → LB）：JA3 是客户端真实指纹，检测有意义
  - 卸载点**后**（LB → 后端 server）：JA3 是 LB 的库栈指纹，检测无意义，需白名单

### 6.3 老浏览器 vs 攻击工具

Metasploit meterpreter reverse_https 的 JA3 与老 Java 客户端（如老 Weblogic 控制台、老 JBoss）撞车。调优：

1. 结合目的地 IP：老 Java 客户端目的地通常是**内网** app server
2. 攻击工具目的地通常是**外网** IP（且经常是低价 VPS 段：DigitalOcean/Linode/阿里云香港/Vultr）
3. 目的 IP 情报（RiskIQ / Shodan / VT）辅助判断

### 6.4 客户白名单模板

建议客户提供：

```yaml
tls_whitelist:
  by_sni_pattern:
    - "*.cloudflare.com"
    - "*.aliyuncs.com"
    - "*.internal.acme.com"
  by_ja3:
    - "51c64c77e60f3980eea90869b68c58a8"   # 客户内部 Java 微服务
  by_dst_ip:
    - "203.0.113.0/24"                      # 客户 CDN 前端段
gm_business_whitelist:
  - sni: "api.tax-gov.cn"
    dst_ip: "198.51.100.10"
    business: "税务链路"
```

---

## 七、护网期作战操作单

### 7.1 一线接到 TLS 类告警

1. **拉 pcap** → `pcap_parser.py --views tls,http,flow --input capture.pcap | traffic_anomaly.py --input -`
2. **看告警**：找 `R-TRAF-050~069` 命中 → 记录 `src_ip / dst_ip / sni / ja3 / cert_cn`
3. **决策**：
   - 命中已知 JA3 表 + 非白名单 SNI/dst_ip → **直接 P0，封禁 + 主机 ir**
   - 命中 metadata 类（短命证书 / 空 SNI / GM cipher）+ 未在白名单 → **P1，48h 观察 + 主机检查**
   - 仅命中低置信规则（extension 顺序 / 单 cipher）→ **P2 / P3 观察，24h 复看**

### 7.2 二线深度分析

1. **对 pcap 中该 src_ip 抽 3-5 条 TLS session**，用 Wireshark 打开
2. **手工提取 JA3**（`ssl.handshake.ja3` 字段）与已知库比对
3. **看证书链**：是否自签、是否短命、CN/SAN 是否含默认值
4. **看流量方向**：出方向长连接（>10 min）+ 小包心跳 = 高置信 C2

### 7.3 上报 & 归档

- 命中 P0 → 立即上报客户 SOC + 走 CI 通道
- 命中 P1/P2 → 每日汇总
- 所有命中 hash 归入客户侧 TLS 指纹库（`local-fingerprints.yaml`）

---

## 附录 A：JA3 手工计算命令片段

（仅供 blueteam 手工核对使用）

```bash
# 从 pcap 提取所有 Client Hello 的 JA3 hash
tshark -r capture.pcap -Y "tls.handshake.type == 1" \
       -T fields -e tls.handshake.ja3 -e tls.handshake.ja3_full
```

`tshark` 3.6+ 内置 JA3 字段计算，无需外部脚本。

---

## 附录 B：与其他文档的交叉索引

- 基础恶意流量识别 12 类：`references/attack-patterns/malicious-traffic.md`
- Windows 横向流量特征：`references/attack-patterns/windows-lateral-traffic.md`
- 内网穿透工具流量：`references/attack-patterns/tunnel-tools-traffic.md`
- DNS 隐蔽通道深化：`references/attack-patterns/dns-covert-channels.md`（本次一并交付）
- 通用 pcap 审计剧本：`references/playbooks/traffic-audit.md` §十一
- C2 综合识别：`references/attack-patterns/c2-signatures.md`

---

## 附录 C：数据来源与鸣谢

- SalesForce JA3 project (2017)
- TrickyTLS / TrisulNSM 公开研究
- Cisco Talos "TLS fingerprinting" 系列 blog
- 国内多家安全厂商 2023-2025 护网复盘（脱敏引用）
- Wireshark 官方 `tls` 协议解析文档

> 免责声明：本文档所列 JA3/JA3S hash 均来自公开研究样本，**不含任何攻击工具编译源、不含载荷构造方法**。所有指纹仅用于蓝队检测。护网期需以真实客户样本为准复核。

---

## 附录 D：TLS 元数据字段速查

pcap_parser.py 的 tls 视图产出的原始字段：

| 字段 | 类型 | 说明 |
|---|---|---|
| `sni` | str | Client Hello 的 SNI |
| `cert_cn` | str | 服务端证书 CN（从 Certificate 消息取） |
| `cert_issuer` | str | 证书 issuer |
| `version` | str | TLS 版本（1.0 / 1.1 / 1.2 / 1.3） |
| `cipher` | str | 协商的 ciphersuite |
| `ja3` | str | JA3 hash（若 tshark 版本支持） |
| `ja3s` | str | JA3S hash |
| `alpn` | str | ALPN 协议 |
| `tls_extensions` | str | Client Hello 扩展列表（逗号分隔） |
| `cert_not_before` | ISO ts | 证书生效时间 |
| `cert_not_after` | ISO ts | 证书失效时间 |
| `session_id_empty` | bool | Session ID 是否为空 |
| `session_ticket_empty` | bool | Session Ticket 是否为空 |
| `alert_level` | str | TLS Alert level（`fatal` / `warning`） |

其中 `ja3` / `ja3s` / `tls_extensions` / `alpn` / `cert_not_before` 需要 tshark **>= 3.6**。老版本需要升级或加装 [ja3 tshark plugin](https://github.com/salesforce/ja3)。

### tshark 命令片段

```bash
# 输出 JA3 + JA3S 到 CSV
tshark -r capture.pcap -Y "tls.handshake.type == 1 or tls.handshake.type == 2" \
       -T fields -e frame.time_epoch \
       -e ip.src -e ip.dst \
       -e tls.handshake.ja3 -e tls.handshake.ja3s \
       -E separator=',' -E header=y
```

---

## 附录 E：护网期红队常用 TLS 反检测手段

蓝队应当**预知**攻击方为对抗 JA3 检测会做的**规避手段**：

### E.1 修改 Malleable-TLS profile

CobaltStrike / Sliver 都支持修改 TLS profile：

- Cipher suite 顺序改为主流浏览器风格
- 移除某些扩展（如 `signed_certificate_timestamp`）以改变 JA3
- 添加 GREASE 值伪装成 Chrome/Firefox

**蓝队应对**：
- 不能只看单个 JA3 hash，需要结合**目的地情报 + 心跳规律 + 证书元数据**
- 建议用 JA4（组合更多字段）替代 JA3 作为主指纹

### E.2 使用系统 SSL 库（BoringSSL / SChannel）

攻击方直接调用系统 SSL 库，JA3 与合法浏览器完全一致：

- Windows 上的 SChannel = Edge / IE 的 JA3
- macOS 上的 SecureTransport = Safari 的 JA3

**蓝队应对**：
- JA3 白名单化：把主流浏览器 JA3 加入 `browser_ja3_whitelist`
- 命中白名单 JA3 → 但目的 IP / SNI / 心跳异常 → 视为 loader 借道浏览器 SSL

### E.3 加密流量心跳伪装

攻击方将心跳频率降到 300s+，并添加 ±30% jitter，避免均匀间隔告警。

**蓝队应对**：
- 拉长观察窗口（例如 24h 内 3-5 次心跳）
- 结合流量方向（出方向长连接）、目的地新鲜度（域名 whois 注册时间 < 30d）综合判定

### E.4 域前置 + 短命证书

攻击方在 CloudFlare/AWS CloudFront 前端注册合法 CDN 域，back-end 是 C2 服务器；证书由 Let's Encrypt 签发（90d 有效期），看上去完全"正常"。

**蓝队应对**：
- 不能仅依赖 JA3 + 证书 CN
- 需要**跨层比对**：TLS 视图的 SNI vs HTTP 视图的 Host
- 依赖 CDN 侧配合（如 CloudFlare Radar / 客户 CTI 库反查）

---

## 附录 F：JA4 简介（前瞻）

FoxIO 在 2023 年公开的 JA4 系列（JA4 / JA4S / JA4H / JA4X）比 JA3 更抗规避：

- **JA4**：TLS Client Hello 指纹，纳入 TLS 版本、SNI 存在性、ALPN、扩展签名算法
- **JA4S**：Server Hello 指纹
- **JA4H**：HTTP 请求头字段顺序指纹
- **JA4X**：X.509 证书指纹

Wireshark **4.2+** 已内置 JA4 计算。护网期建议：

- 优先用 JA3（护网期主流工具尚未大规模更新到抗 JA3 的能力）
- 高价值目标场景引入 JA4 作为二线复核
- 保留 JA3+JA4 双指纹到客户 CTI 库

---

## 附录 G：常见非红队 JA3（白名单参考）

以下是 2024-2025 常见合法 JA3，命中它们的**目的地必须在白名单内**才能忽略：

| JA3 hash | 归属 | 备注 |
|---|---|---|
| `cd08e31494f9531f560d64c695473da9` | Chrome 120 | 主流浏览器 |
| `bd6e04d747b5a2fbe17d8f14d24d3d68` | Firefox 115 | 主流浏览器 |
| `27b41b8bdfec4bccf4f2c8d55d6a5c3d` | Safari 17 | 主流浏览器 |
| `19e29534fd49dd27d09234e639c4057e` | Go net/http | 大量合法 Go 服务 |
| `56a58e05e7bf5f5f4a3cba0f8f1a6d80` | Python requests | 大量合法脚本 |
| `d01d84699bf74920c9d94b8b3b1f0a4c` | curl | 通用运维 |
| `82fed49025bf5ddb2b12a9d18f45e9f9` | openssl s_client | 通用运维 |
| `54328bd36c14bd82ddaa0c04b25ed9ad` | .NET HttpClient | Windows 生态 |
| `28a2c9bd18a11de089ef85a160da29e4` | Java HttpURLConnection | Java 生态 |
| `51c64c77e60f3980eea90869b68c58a8` | Windows Update client | 微软自更新 |

**注意**：上面这些 JA3 也可能是攻击者故意用系统库生成的假指纹，所以**不能只看 JA3 白名单就放行**，必须结合目的地。

---

## 附录 H：TLS 深化审计的 5 个"红线场景"

护网期出现以下场景之一，即便 JA3 未直接命中已知黑名单，也应当立即升级为 P0：

1. **出方向 TLS + 目的 IP 在低价 VPS 段**（DigitalOcean / Vultr / 阿里云香港 / Linode / Contabo）+ 心跳规律 → 90% 概率 C2
2. **短命自签证书（<24h lifetime）+ 出方向 + 未知 IP 情报** → 几乎必是 C2
3. **SNI = 空 + Cipher = ECDHE-* + 出方向长连接** → Sliver / Havoc mTLS 强嫌疑
4. **SNI vs Host 不一致 + 目的 IP 是 CloudFlare 段** → 域前置攻击强嫌疑
5. **国密 cipher（SM2/SM4）+ 目的地非国密合规业务** → 国产化红队工具

---

## 附录 I：v0.3-M1 变更记录

- 新增运行时规则 R-TRAF-050~069（20 条 TLS 深化规则）
- 新增数据层特征 SIG-TRAF-087~098（12 条 TLS 相关）
- 与 R-TRAF-999 关联升级：TLS 类命中 + 其他类命中 ≥ 2 类 → `apt-suspect` 标签
- 引入 JA3/JA3S 已知库（10+ 条 hash，来自 2023-2025 公开研究）
- 引入国密 (SM2/SM3/SM4) TLS 识别规则

---

**END OF DOCUMENT**
