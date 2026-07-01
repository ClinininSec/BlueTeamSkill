# C2 通信特征库

> 主流 C2（Cobalt Strike / Sliver / Metasploit / Empire / PoshC2 / Mythic / Brute Ratel）通信识别要点。
> **何时使用**：怀疑主机被植入后门，需要从流量层 + 主机层识别 C2 通信时。

仅给出"识别"用的特征碎片，不构成可复现 stager / payload。

---

## 一、Cobalt Strike (CS) —— 国内护网最常见

### 1.1 网络层特征

| rule_id | 特征 | 协议 | FP note |
|---|---|---|---|
| SIG-C2-001 | 默认 Malleable 未改 profile 时 GET 请求路径 `/aaa9` / `/ab2u` / `/ptj` / `/submit.php` 等已知 stager 路径 | HTTP | 默认 profile 不改才出现 |
| SIG-C2-002 | URI checksum8 算法可解：URI 单段除前缀外字符的 ASCII sum % 0x100 == 92 (x86) 或 93 (x64) | HTTP | 自定义 profile 也会保留此特征 |
| SIG-C2-003 | 伪装 Cookie：`__cfduid`、`PHPSESSID`、`__utma` 等带 base64 编码 + 长度异常（>200 字节） | HTTP cookie | CDN 真实 cookie 一般 <100 字节 |
| SIG-C2-004 | 心跳特征：固定间隔 jitter±25% 出现等长 GET 请求（DNS round-trip 行为） | netflow | 业务正常 keep-alive 通常无 jitter |
| SIG-C2-005 | sleep + jitter 表现：抓包看，请求间隔在 (sleep×0.75, sleep×1.25) 区间内均匀分布 | netflow | 心跳类业务 SDK 类似 |
| SIG-C2-006 | HTTPS Beacon JA3 指纹常见值：`72a589da586844d7f0818ce684948eea`（默认 Java keytool 证书） | TLS | 升级版 4.x 可改证书 |
| SIG-C2-007 | TLS 证书 CN/O 默认值：`Major Cobalt Strike` / `Cobalt Strike` / `cloudflare-inc` 长度异常 | TLS | 改 profile 可改 |
| SIG-C2-008 | DNS Beacon：高频 TXT/A 查询 + 子域名长度异常（base64 命令） | DNS | 类似 dnstunnel |
| SIG-C2-009 | SMB Beacon Named Pipe 默认名：`\\.\pipe\status_xxx` / `\\.\pipe\MSSE-xxxx-server` / `\\.\pipe\msagent_xx` | SMB | 默认 profile 不改才出现 |
| SIG-C2-010 | HTTP Beacon 响应：`Content-Type: application/octet-stream` 或 `text/html` 但 body 是密文（高熵 base64） | HTTP | 业务 API 类似但流量小 |

### 1.2 主机层特征

| rule_id | 特征 | 数据源 |
|---|---|---|
| SIG-C2-051 | 进程注入：legit 进程（svchost / rundll32 / explorer）出现远程线程注入（Sysmon EID 8） | Sysmon |
| SIG-C2-052 | `rundll32.exe` 无参或加载非常规 DLL（不含 `,` 入口点） | EID 4688 / Sysmon 1 |
| SIG-C2-053 | beacon 进程链异常：office → wmic / mshta / powershell → 远程下载 | EID 4688 |
| SIG-C2-054 | SMB pipe 创建（Sysmon EID 17/18） | Sysmon |
| SIG-C2-055 | `lsass.exe` 被打开 GrantedAccess = 0x1010 / 0x1410（凭据 dump） | Sysmon EID 10 |

---

## 二、Sliver

| rule_id | 特征 | 协议层 |
|---|---|---|
| SIG-C2-101 | 默认 mTLS：端口 31337 / 8443 + 客户端证书 + JA3 与已知 Sliver 指纹匹配 | TLS |
| SIG-C2-102 | HTTPS C2 路径：`/admin/`、`/login`、`/dist/`、`/static/` 含 `.woff` / `.svg` 等假静态资源后缀，但响应是密文 | HTTP |
| SIG-C2-103 | DNS C2：长子域 base64 / base32（默认 base32） + 单次查询多个 RR | DNS |
| SIG-C2-104 | Mutual TLS implant 默认开启，server 拒绝无客户端证书的连接 → 抓包看 alert 41 | TLS |
| SIG-C2-105 | implant binary 含 `sliver` / `wiregost` 字符串（虽然新版做了 strip 仍偶有残留） | binary |

---

## 三、Metasploit / Meterpreter

| rule_id | 特征 | 协议层 |
|---|---|---|
| SIG-C2-151 | reverse_tcp 默认端口 4444 / 4445 / 5555 | TCP |
| SIG-C2-152 | reverse_https stager URI 模式：`/[A-Za-z0-9_]{4}/` 4 字节随机段 + checksum8 算法（与 CS 类似但实现独立） | HTTP |
| SIG-C2-153 | meterpreter HTTPS 心跳：默认 jitter 0、interval 固定，行为非常机械 | netflow |
| SIG-C2-154 | shellcode in memory 含字符串 `meterpreter.dll` / `metsrv.dll` / `MSF::Core` | memory dump |
| SIG-C2-155 | 默认 Stage 0 大小约 281 字节（reverse_tcp x86） | netflow |

---

## 四、Empire / Starkiller / PoshC2

| rule_id | 特征 | 协议层 |
|---|---|---|
| SIG-C2-201 | Empire UA 默认：`Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko` | HTTP UA |
| SIG-C2-202 | Empire 默认 URI 路径：`/admin/get.php` / `/login/process.php` / `/news.php` | HTTP |
| SIG-C2-203 | Empire stager：base64 解码后 powershell + IEX 块 | HTTP body |
| SIG-C2-204 | PoshC2 默认 path：`/images/`、`/news.asp`、`/blogs/` | HTTP |
| SIG-C2-205 | PoshC2 默认 implant 心跳间隔 5 秒（极短） | netflow |

---

## 五、Mythic

| rule_id | 特征 | 备注 |
|---|---|---|
| SIG-C2-251 | Mythic 是 framework，需对接具体 agent（Apollo / Athena / Apfell / Medusa） 识别 | — |
| SIG-C2-252 | Mythic HTTP profile 默认 path `/api/v1.4/agent_message` 等可识别 | HTTP |
| SIG-C2-253 | Mythic 默认证书 CN = `Mythic` | TLS |

---

## 六、Brute Ratel (BRC4)

| rule_id | 特征 | 备注 |
|---|---|---|
| SIG-C2-301 | BRC4 implant 文件较大（PE size 通常 > 4MB，含 commercial 加壳） | file |
| SIG-C2-302 | 默认通过 office 文档 + ISO/IMG 投递，落地 `.dll` + `.lnk` | filesystem |
| SIG-C2-303 | HTTPS 通信默认 Cobalt Strike 兼容 profile，特征向 CS 看齐 | HTTP |
| SIG-C2-304 | 反射加载 + 反沙箱：内存中含 PEB 检测代码、`IsDebuggerPresent` 调用 | memory |

---

## 七、Havoc / Nighthawk / SilentTrinity（点到为止）

- **Havoc**：开源 CS-like，默认 demon agent UA 含 `Havoc-` 字样（部分 build）；通信特征与 CS 相近。
- **Nighthawk**：商业，国内护网 v0.1 罕见，识别要点同 Mythic。
- **SilentTrinity**：基于 .NET，IronPython 解释 payload，进程含 `ipy.exe` / `ironpython` 字符串。

---

## 八、易混淆 —— 不是 C2 但常被告警混入

| 工具 | 类型 | 易混点 |
|---|---|---|
| `goby` | 资产探测 | UA 含 `goby/`，是扫描器不是 C2 |
| `xray` | DAST 扫描 | UA 含 `xray`，是扫描器 |
| `fscan` | 内网扫描 | 无 UA，TCP 探测特征明显 |
| `frp` / `nps` | 内网穿透代理 | 是反代不是 C2，但常被攻击者用作 tunnel |
| `chisel` | tunnel | TLS over HTTP，特征类似 C2 但行为是代理 |
| `gost` / `ssh -R` | tunnel | 同上 |

→ 这些工具单独使用并不构成 C2 通信，但如果在被入侵主机出现 + 配合反向连接外网，就升级为 tunnel 持久化标记。

---

## 九、共同 C2 行为指标（不分工具）

| rule_id | 特征 | 数据源 |
|---|---|---|
| SIG-C2-901 | 定时长连接：单进程对外 TCP 长连超 1h，对端 IP 非业务清单 | netflow |
| SIG-C2-902 | 心跳：固定间隔（5/30/60/300s）出现等大小请求 | netflow |
| SIG-C2-903 | 出网到 VPS 段：DigitalOcean / Vultr / Linode / AWS Lightsail 等托管段，非业务 CDN | netflow |
| SIG-C2-904 | 反向连接：内网主机主动连接 外网高端口（>10000）且端口随时间变化 | netflow |
| SIG-C2-905 | TLS 证书 CN/O 中含 `localhost` / `example` / `test` / 随机字符串 | TLS |
| SIG-C2-906 | 出网 DNS 查询子域名熵值 > 4.0（典型 dnstunnel） | DNS |
| SIG-C2-907 | 进程链：office / browser / pdf reader → cmd / powershell → 出网 | EDR |

---

## 十、误报场景

- **业务 SDK 心跳**：微信 push / 推送服务 SDK / APM agent 的心跳类似 C2 jitter。
- **远程办公 SDK**：teamviewer / anydesk / sunlogin 长连接 + 高端口。
- **CDN 切换重连**：客户端切换 CDN 节点重建 TLS 触发 JA3 多样化。
- **CI/CD agent**：jenkins / gitlab runner 出网到 webhook 类似 reverse callback。
- **DDNS 服务**：动态 DNS 查询频繁，子域名长 → 类似 DNS C2。

→ 实战中以**多维证据交叉**（流量 + 主机进程 + 落盘文件）来去除以上 FP。

---

## 十一、规则总览

总计定义 rule_id：
- SIG-C2-001 ~ SIG-C2-010（CS 网络，10 条）
- SIG-C2-051 ~ SIG-C2-055（CS 主机，5 条）
- SIG-C2-101 ~ SIG-C2-105（Sliver，5 条）
- SIG-C2-151 ~ SIG-C2-155（Metasploit，5 条）
- SIG-C2-201 ~ SIG-C2-205（Empire/PoshC2，5 条）
- SIG-C2-251 ~ SIG-C2-253（Mythic，3 条）
- SIG-C2-301 ~ SIG-C2-304（Brute Ratel，4 条）
- SIG-C2-901 ~ SIG-C2-907（共同行为，7 条）

合计 **44 条**。
