# DNS 隐蔽通道检测知识库

> 面向 pcap/pcapng 离线审计的 DNS 隧道、DGA、DoH/DoT 出站异常识别参考。
> **何时使用**：怀疑主机被植入后门用 DNS 通道回连、外发数据、探测存活时。
> 与运行时规则 `R-TRAF-070~084`（scripts/traffic_anomaly.py）对齐，与知识库 ID `SIG-TRAF-099~104`（data/traffic-signatures.json）双向可查。
> 所有识别特征仅供检测使用，禁止用于攻击复现或构造 payload。

---

## 通用识别路径

DNS 视图（`pcap_parser.py --views dns`）产出的关键字段：`qname / qtype / rcode / response_ip / payload_len / ttl`。

检测流程：**基础字符串特征 → 统计特征 → 时序特征 → 与 http/tls 视图关联**。

- 传统的 IOC 黑名单（"命中 dnscat2.xxx 就报"）在 2026 年已远远不够
- **必须做统计特征**（长度分布、熵、子域爆炸、NXDOMAIN 比例、心跳节奏）
- 蓝队优先级：`R-TRAF-078`（CS DNS beacon 前缀）> `R-TRAF-073/074`（TXT/NULL 占比） > `R-TRAF-070/071`（长 qname + 高熵） > `R-TRAF-072`（子域爆炸）> `R-TRAF-081`（时间间隔均匀性） > 其他

---

## 一、DNS 隧道原理简述

DNS 请求本身是明文（未加密的 DNS 情况下），但因为 DNS 出方向 UDP/53 在多数网络里是"允许"的，攻击方常把 payload 编码到 DNS query name / TXT record 里传输。

### 1.1 常见编码方式

| 编码 | 特征 | 常见工具 |
|---|---|---|
| base32 (小写) | 字符集 `a-z2-7`；qname 首标签长且规则 | iodine / DNScat2 (老) |
| base64url | 字符集 `A-Za-z0-9_-`；qname 中出现 `-` `_` | DNSExfiltrator / 自研 |
| 十六进制 | 字符集 `a-f0-9`；固定字长 | Sliver DNS / CobaltStrike DNS beacon |
| 简单 XOR / ROT13 | 有明文字母分布特征 | 教学级工具 |

**注意**：本文档不给出编码/解码代码，只给出**识别特征**。

### 1.2 常见 DNS 隧道工具（仅列名，不含 payload 构造）

- **iodine**：老牌 IPv4-over-DNS 隧道，qtype 常用 NULL，qname 长
- **dnscat2**：TXT 查询大量出现，qname 通常有工具前缀 `dnscat.xxx`（老版本）
- **DNSExfiltrator**：TXT / CNAME 载荷，qname 首标签 base32
- **CobaltStrike DNS beacon**：默认前缀 `api.` / `cdn.` / `www.` + hex；qtype 通常 A / AAAA
- **Sliver DNS**：hex 编码，qtype A/AAAA/CNAME 混用
- **自研 DGA + DNS 通道**：结合 DGA 算法生成子域，无固定前缀

---

## 二、静态特征

以下特征可用**单条 DNS 记录**判定，属于低成本快检。

### 2.1 qname 长度分布

- 正常 DNS qname 长度**大部分 < 30 字节**（普通域名如 `www.example.com`）
- 长 qname (> 40 字节) 通常是：
  - CDN 缓存 key（如 `cdn-key-abcdef123456.example-cdn.com`）
  - Analytics 事件上报（如 `event-id-uuid.tracking.example.com`）
  - **DNS 隧道 / DGA**

**规则**：`R-TRAF-070`（同 src 平均 qname > 40 字节 + 高频）。

### 2.2 编码字符集

- **base32**：首标签 20+ 字符，字符集全在 `a-z0-9`（尤其 `a-z2-7`）
- **base64url**：首标签 20+ 字符，字符集在 `A-Za-z0-9_-`
- **hex**：首标签 20+ 字符，字符集在 `a-f0-9`
- 正常子域**很少**这么长且完全符合单一编码字符集

**规则**：`R-TRAF-076`（首标签 base32/base64 比例 > 85%） / `SIG-TRAF-101`（base32） / `SIG-TRAF-103`（hex）。

### 2.3 查询类型偏好

| qtype | 正常占比 | 异常场景 |
|---|---|---|
| A / AAAA | 90%+ | 极低占比 = 异常 |
| TXT | 通常 < 5% | > 30% → 可能是 dnscat2 / iodine |
| NULL | 通常 < 0.1% | > 5% → 几乎必是 iodine |
| CNAME | 5-10% | 极高 + 长 qname 组合 = 可疑 |
| MX / SRV | 视业务 | 应用无关的话，异常 |

**规则**：
- `R-TRAF-073`（TXT 占比 > 30%）
- `R-TRAF-074`（NULL 占比 > 5%）
- `SIG-TRAF-102`（NULL qtype 命中直接告警）

---

## 三、统计特征（推荐用于检测）

单条 DNS 记录很难判定，但**窗口内聚合**能大幅提升置信度。

### 3.1 Shannon 熵计算简介

Shannon 熵衡量字符串的"随机程度"：

```
H(s) = -Σ p(x) * log2(p(x))
```

其中 `p(x)` 是字符 x 在字符串 s 中的频率。

- 英文单词的 Shannon 熵约 **2.5-3.5**
- 随机字符串（如 UUID）Shannon 熵约 **4.2-4.6**
- **base32 / base64 编码后的字符串** Shannon 熵约 **4.5-5.0**

**规则**：`R-TRAF-071`（首标签 Shannon 熵 > 4.0 且长度 >= 16）。

### 3.2 子域数量爆炸

- 正常业务：**同一父域** (`example.com`) 的子域数量通常 < 100（除非是大厂 CDN）
- **DGA / DNS 隧道**：短时间内产生 100+ 独立子域

**规则**：`R-TRAF-072`（同父域 5 min 内 > 100 独立子域）。

**误报排查**：
- CDN 边缘节点子域（`edge-node-abc.cdn.example.com`）可能天然多，但大厂 CDN 通常有稳定命名，可白名单
- CT log（`crt.sh` / Google CT）扫描类流量也可能触发，需要看是否是已知扫描服务

### 3.3 NXDOMAIN 比例

- 正常业务 NXDOMAIN 比例 < 5%
- **DGA 探测**：DGA 算法生成的子域大部分未注册，NXDOMAIN 比例 **> 30%**
- **注意**：有些应用 typo / autocomplete 也会产生 NXDOMAIN，需要区分

**规则**：`R-TRAF-077`（单 client 5 min 内 > 50 NXDOMAIN）。

### 3.4 时间间隔均匀性（beacon 特征）

- 正常业务的 DNS 请求间隔**方差很大**（用户点击驱动）
- **beacon 心跳**（DNS 版）会有近似**恒定间隔**（如每 60s 一次）

计算方法：
- 收集同 src → 同 parent domain 的所有 query timestamp
- 计算相邻间隔的**变异系数 CV = std / mean**
- CV < 0.15 → 高度均匀 → **beacon 嫌疑**

**规则**：`R-TRAF-081`（15 个样本内 CV < 0.15 且 mean > 5s）。

**误报排查**：
- SNMP monitor / probe 类工具也会周期性查 DNS，需要业务白名单
- Windows NCSI (Network Connectivity Status Indicator) 会周期性查 `dns.msftncsi.com`

---

## 四、DGA 分类

DGA (Domain Generation Algorithm) 是恶意软件家族用来"逃避静态 IOC 黑名单"的算法。

### 4.1 常见 DGA 家族速览

| 家族 | 特征 | 备注 |
|---|---|---|
| **Necurs** | 拼音风格 + 数字后缀（如 `xoxdvjxfjkfld.com`） | 已被 takedown |
| **Conficker** | 长度 8-11 字符，无元音 | 2008 老 malware |
| **Suppobox** | 类似英文单词的组合（`dictionaryword1word2.com`） | 混淆度高 |
| **Gozi / ISFB** | 3-4 字符 + 特定 TLD | 银行木马家族 |
| **Emotet** | 每天生成新域，长度中等 | 2021 被 takedown 但衍生仍在 |
| **Trickbot / Qakbot** | 类似 Emotet 的短域 + TLD 组合 | 银行木马 |

### 4.2 n-gram 分类简介

DGA 域名与合法域名在 n-gram（连续 n 个字符）分布上有显著差异：

- 合法域名：n-gram 分布近似人类语言（如 `-com`、`.co-`、`www` 高频）
- DGA 域名：n-gram 分布近似均匀随机

**简单 n-gram 启发式**（本 skill 采用）：
- 连续辅音（去掉元音 `aeiou` 和数字后）字符串长度 >= 7 → 可能是 DGA
- 例：`xkjqvzptl.com` 的辅音簇长度 = 9 → 命中

**规则**：`R-TRAF-080`（连续辅音簇 >= 7）。

**局限**：这是**低成本启发式**，真实生产环境应使用 ML 分类器（scikit-learn LogisticRegression / RandomForest 训练 top-1m Alexa vs 已知 DGA），但本 skill 强调**离线可复现 + 无模型依赖**，故仅提供 n-gram 版本。

### 4.3 DGA 与 DNS 隧道的区别

| 维度 | DGA | DNS 隧道 |
|---|---|---|
| **目的** | 隐藏 C2 域，抗黑名单 | 传输数据 |
| **qname 长度** | 通常 < 20 字符 | 通常 > 40 字符 |
| **NXDOMAIN 比例** | 高（大部分域未注册） | 低（域已注册，能解析） |
| **qtype** | 大多是 A/AAAA | 常有 TXT/NULL/CNAME |
| **应对方式** | 检测 + 情报订阅 | 断 DNS 出站 |

---

## 五、DoH / DoT 出站

DoH (DNS over HTTPS) 端口 443 / DoT (DNS over TLS) 端口 853。攻击方可用 DoH/DoT 逃避 DNS 层监控（因为它们看起来就是普通 HTTPS）。

### 5.1 常见公共 DoH 端点白名单

以下是主流公共 DoH 端点，通常允许出站：

- `dns.google` (Google Public DNS)
- `cloudflare-dns.com` / `one.one.one.one` (Cloudflare 1.1.1.1)
- `dns.quad9.net` (Quad9)
- `doh.opendns.com` (OpenDNS)
- `dns.adguard.com` (AdGuard)
- `dns.alidns.com` (阿里公共 DNS)
- `doh.pub` (DNSPod / Tencent)
- `doh.360.cn` (360 公共 DNS)

### 5.2 何时算异常

- 出方向到**非白名单** DoH 域名 = **攻击方自建 DoH 中继**
- 特征：TLS SNI 含 `doh` / `dns-over` / `dnstls` / `dot` 关键字，但 SNI 不在白名单
- 或者：TLS session 到 UDP/853 端口 但目的 IP 未在白名单

**规则**：`R-TRAF-079`。

### 5.3 组织级建议

护网期建议客户：

1. **禁用**主机侧浏览器的"自动 DoH"（Firefox / Chrome 默认可能启用 CloudFlare DoH）
2. **代理**所有 DoH 请求经客户内部 DNS gateway 转发（避免"绕过 DNS 监控"）
3. **只允许**白名单 DoH 端点出站（防火墙层面）

---

## 六、检测机会与关联 rule_id

| DNS 隧道 / 隐蔽通道特征 | 关联 rule_id | 关联 SIG-TRAF ID |
|---|---|---|
| 平均 qname 长度 > 40 + 高频 | R-TRAF-070 | - |
| 首标签 Shannon 熵 > 4.0 | R-TRAF-071 | - |
| 同父域 5min > 100 子域 | R-TRAF-072 | - |
| TXT 占比 > 30% | R-TRAF-073 | SIG-TRAF-062 |
| NULL 占比 > 5% (iodine) | R-TRAF-074 | SIG-TRAF-102 |
| UDP/53 payload 大小异常 | R-TRAF-075 | - |
| 首标签 base32/base64 > 85% | R-TRAF-076 | SIG-TRAF-101 |
| NXDOMAIN 风暴 (>50/5min) | R-TRAF-077 | - |
| CS DNS beacon 前缀 | R-TRAF-078 | SIG-TRAF-099 |
| DoH/DoT 非白名单出站 | R-TRAF-079 | - |
| DGA n-gram (连续辅音 >=7) | R-TRAF-080 | - |
| 时间间隔均匀性 (CV < 0.15) | R-TRAF-081 | - |
| 反向隧道（answer >> query） | R-TRAF-082 | - |
| TTL 异常 (=0 或 >7d) | R-TRAF-083 | - |
| 重复 qname burst | R-TRAF-084 | - |
| Very long qname (>= 60 chars) | R-TRAF-006  | SIG-TRAF-063 |
| dnscat2 default prefix | R-TRAF-006 | SIG-TRAF-064 / SIG-TRAF-104 |

### R-TRAF-999 升级条件

同 `src_ip` 同时命中：
- DNS 类（R-TRAF-070~084）≥ 1 条
- 且 TLS 类（R-TRAF-050~069）≥ 1 条 **或** 国内工具类（R-TRAF-085~098）≥ 1 条

→ R-TRAF-999 附加 `tag: apt-suspect`，升级为 P0。

---

## 七、误报与调优

### 7.1 大厂 CDN 与云服务的子域熵天然高

- `*.akamaihd.net` / `*.cloudfront.net` / `*.cdn.example` 常有很长的 hash 子域
- 调优：将这些 parent domain 加入 `dns_whitelist_parent`：

```yaml
dns_whitelist:
  parent_domains:
    - akamaihd.net
    - cloudfront.net
    - fastly.net
    - alicdn.com
    - qcloud.com
    - cdnjs.cloudflare.com
```

- 命中 R-TRAF-070/071/076 但父域在白名单 → 降级 P3

### 7.2 CT log / DNS-over-HTTPS 应用的正常长 qname

- CT log 扫描（如 `crt.sh`、Google CT）会产生大量长子域查询
- Cloudflare Zero Trust / CyberX 等企业 DNS 服务本身用长子域做 client identify
- 需要业务方提供白名单 client ID / 场景

### 7.3 SNMP / 探活 / 心跳类正常流量

- SNMP monitor / SolarWinds / Zabbix agent 会周期性做 DNS 查询探活
- 通常 src_ip = 客户 NMS 服务器（IP 固定）
- 白名单 src_ip 或 white-list parent domain

### 7.4 R-TRAF-081（间隔均匀）的调优

- 心跳类正常流量（Windows Update / Skype / RTC 通信）也会触发
- 建议只对**外网出方向** + **未知 dst_ip 情报值**的均匀间隔告警
- 内网 monitor 心跳一律白名单

---

## 八、护网期作战操作单

### 8.1 一线接到 DNS 类告警

1. **拉 pcap** → `pcap_parser.py --views dns --input capture.pcap | traffic_anomaly.py --input -`
2. **看告警**：找 `R-TRAF-070~084` 命中 → 记录 `src_ip / parent_domain / qname 样本 / qtype 分布`
3. **决策**：
   - 命中 `R-TRAF-074`（NULL 占比 > 5%） → **直接 P0，立即断 DNS 出站 + 主机 ir**（iodine 强特征）
   - 命中 `R-TRAF-078`（CS DNS beacon 前缀） → **P0，封禁父域 + 主机 ir**
   - 命中 `R-TRAF-073`（TXT > 30%） → **P0，dnscat2/iodine 嫌疑**
   - 命中 `R-TRAF-070+071+076` 组合 → **P1**（三特征叠加高置信）
   - 单条命中 `R-TRAF-080`（n-gram DGA） → **P2 观察**

### 8.2 二线深度分析

1. 从 pcap 中**导出该 src_ip 全部 DNS 记录**：
   ```bash
   tshark -r capture.pcap -Y "ip.src == <src_ip> and dns" \
          -T fields -e dns.qry.name -e dns.qry.type -e dns.flags.rcode
   ```
2. 手工做统计：
   - 长度分布直方图
   - qtype 分布饼图
   - parent domain top-10
3. 若 qname 疑似编码：**不要解码**（避免执行）；提交客户 IR 团队并保留原始样本
4. 找主机侧对应进程（结合 osquery / EDR）

### 8.3 阻断动作

- **临时**：DNS gateway 层封禁父域
- **永久**：加入客户 CTI 库 + 上报威胁情报中心
- **主机侧**：抓 rss 内存 + `netstat -anop` + `lsof -i` 找进程 → IR

---

## 附录 A：Wireshark 快速定位显示过滤器

```
dns and ip.src == 10.0.0.100
dns.qry.type == 16                 # TXT
dns.qry.type == 10                 # NULL
dns.flags.rcode == 3               # NXDOMAIN
dns.qry.name matches "^[a-f0-9]{20,}"   # hex 长子域
```

---

## 附录 B：与其他文档的交叉索引

- 基础恶意流量识别 12 类：`references/attack-patterns/malicious-traffic.md`
- C2 综合识别：`references/attack-patterns/c2-signatures.md`
- TLS 指纹深化：`references/attack-patterns/tls-fingerprints.md`（本次一并交付）
- 通用 pcap 审计剧本：`references/playbooks/traffic-audit.md` §十一
- Windows 横向流量特征：`references/attack-patterns/windows-lateral-traffic.md`

---

## 附录 C：数据来源与鸣谢

- 各家 threat intel blog（Cisco Talos / Palo Alto Unit 42 / SANS ISC）2022-2025 DNS 隧道复盘
- 学术论文：《Detecting DNS Tunnels using Character Frequency Analysis》
- 国内 CN-CERT 2023-2025 护网复盘（脱敏引用）
- Wireshark 官方 `dns` 协议解析文档
- iodine / dnscat2 项目公开设计文档（仅用于**识别特征**分析，不涉及使用方法）

> 免责声明：本文档仅提供 DNS 隧道 / DGA / DoH 出站的**检测特征**，不含任何攻击工具的部署、编码或 payload 构造方法。所有指纹与规则仅用于蓝队护网检测。护网期需以真实客户样本为准复核。

---

## 附录 D：DNS 视图字段速查

`pcap_parser.py --views dns` 产出的 NDJSON 字段：

| 字段 | 类型 | 说明 |
|---|---|---|
| `qname` | str | DNS 查询的完整域名 |
| `qtype` | str | 查询类型（A/AAAA/TXT/NULL/CNAME/MX/...） |
| `rcode` | int | 响应码（0=NOERROR, 3=NXDOMAIN, ...） |
| `response_ip` | str | 响应中的 IP（若 A 记录） |
| `payload_len` | int | UDP payload 大小 |
| `ttl` | int | 响应记录的 TTL |
| `answer_len` | int | 响应记录整体长度 |

若客户 pcap 用旧版 `pcap_parser.py`，只有 `qname/qtype/rcode/response_ip` 4 个字段。建议**在下次 pcap 采集时** enable `payload_len / ttl / answer_len`（需修改 `pcap_parser.py` view_dns，加入相应 tshark 字段）。

如果没有这些字段：
- R-TRAF-075（payload_len 异常）、R-TRAF-082（answer >> query）、R-TRAF-083（TTL 异常）**不会触发**
- 但 R-TRAF-070~074/076~081/084 都能触发，主要检测覆盖依然完整

---

## 附录 E：护网期红队常用 DNS 反检测手段

蓝队应当**预知**攻击方为对抗 DNS 检测会做的**规避手段**：

### E.1 拉长心跳间隔 + 混合合法查询

攻击方将 DNS beacon 心跳延长到 300-1200s，并混合合法查询（如 `www.google.com`）稀释比例。

**蓝队应对**：
- 拉长观察窗口到 24h
- 结合 http/tls 视图交叉验证（同 src 是否同时有其他可疑外联）

### E.2 使用 DoH / DoT 绕过 DNS 层监控

将 DNS 查询封装在 TLS 内，DNS 层看不到 qname。

**蓝队应对**：
- 边界防火墙禁止**非白名单 DoH** 端点（如 443 到 `mydoh.attacker.com`）
- 结合 TLS 视图，看 SNI 是否是已知 DoH 白名单

### E.3 拆分编码 payload

将大 payload 拆成多个短 qname（每个 <30 字符），逃避长度阈值。

**蓝队应对**：
- 关注**同 parent domain 的高频短查询**：即便单条不长，1 min 内 > 30 次同父域 = 隧道嫌疑
- 计算首标签的**编码字符集比例**（base32/base64）而非单纯长度

### E.4 使用 CNAME 递归查询做载荷

将 payload 编码到 CNAME 响应 chain 里，避免长 qname。

**蓝队应对**：
- 关注 CNAME 响应长度异常（answer_len >> query_len）
- 触发 R-TRAF-082

---

## 附录 F：常见误报清单

| 场景 | 触发规则 | 排查方法 | 处置 |
|---|---|---|---|
| Windows NCSI 探活 | R-TRAF-081（间隔均匀） | src_ip = Windows 终端，qname = `dns.msftncsi.com` | 白名单 qname |
| CDN 长子域 hash | R-TRAF-070/071/076 | parent domain 是 CDN 白名单 | 白名单 parent |
| CT log 扫描 | R-TRAF-072 | src_ip 是已知 CT scanner | 白名单 src |
| SolarWinds Zabbix 心跳 | R-TRAF-081 | src_ip = NMS 服务器 | 白名单 src |
| DGA-like 但合法 hash 域名 | R-TRAF-080（辅音簇） | 目的域是 `*.dropbox.com` 之类合法业务 | 白名单 parent |
| 长 TXT 查询（SPF/DKIM） | R-TRAF-073（TXT 占比） | src_ip = 邮件服务器 | 白名单 src |

调优建议：护网上线前，先跑 24h "baseline pcap"，把上述场景的 src_ip / parent domain 加入白名单，减少 P1/P2 告警噪音。

---

## 附录 G：变更记录

- 新增运行时规则 R-TRAF-070~084（15 条 DNS 深化规则）
- 新增数据层特征 SIG-TRAF-099~104（6 条 DNS 相关，其余 40 条见 tls-fingerprints.md 和 CN 工具章节）
- 与 R-TRAF-999 关联升级：DNS 类命中 + 其他类命中 ≥ 2 类 → `apt-suspect` 标签
- 引入 Shannon 熵、n-gram、时间间隔均匀性等统计特征
- 引入 CS DNS beacon 前缀识别（`api.` / `cdn.` + hex）
- 引入 DoH/DoT 非白名单出站识别

---

## 附录 H：真实 pcap 校准建议

护网期客户环境差异大，本 skill 的默认阈值（如 avg qname > 40、TXT > 30%、CV < 0.15）**必须在客户环境校准**：

### H.1 24h baseline 采集

- 抓 24h 客户流量 pcap
- 只跑 R-TRAF-070/071/072/073/074/077/081 规则
- 记录**误报率**：命中的告警中有多少是明确合法业务

### H.2 阈值调优

若误报率过高：
- R-TRAF-070（avg qname > 40）→ 提高到 > 45 或 > 50
- R-TRAF-072（父域子域 > 100）→ 提高到 > 200 或 > 500
- R-TRAF-073（TXT > 30%）→ 视客户邮件业务提高到 > 40%
- R-TRAF-081（CV < 0.15）→ 调低敏感度到 CV < 0.10

若误报率很低但命中数少：
- 阈值可微调放宽（如 R-TRAF-070 降到 > 35）
- 但**慎重**：护网期宁可略多误报也不要漏报

### H.3 客户侧维护建议

- 建立 `dns_whitelist_parent`：客户业务合法 parent domain
- 建立 `dns_baseline`：客户业务正常 avg qname 长度、TXT 占比等统计
- 每周复看 R-TRAF-999 命中（跨类关联最高置信）

---

**END OF DOCUMENT**
