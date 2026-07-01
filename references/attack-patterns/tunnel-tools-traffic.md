# Tunnel Tools Traffic Signatures — 内网穿透工具流量识别

> 内网穿透 / 反向代理工具的流量层识别知识库。护网期间攻击者常见持久化 & 数据外发通道。
> **何时使用**：出网流量中出现可疑长连接、非常规端口，需要判断是否为 frp / nps / chisel / gost / stowaway 类工具搭建的隧道。
> 仅描述识别特征，不给出可复现的隧道搭建 payload。
> 关联规则：`R-TRAF-201` ~ `R-TRAF-260`；知识库：`SIG-TRAF-201` ~ `SIG-TRAF-260`。

---

## 分类速查表

| 工具 | 常用默认端口 | 协议 | rule_id 段 | 主视图 |
|---|---|---|---|---|
| frp / frps / frpc | 7000, 7500, 7001 | TCP / TLS | R-TRAF-201~210 | flow + tls |
| nps / npc | 8024, 8080, 8082 | TCP | R-TRAF-211~220 | flow |
| chisel | 8080, 8443 | HTTP + WebSocket + SSH | R-TRAF-221~230 | http |
| gost | 8080, 8388, 1080 | 多协议 | R-TRAF-231~240 | http/socks |
| stowaway / venom / spp | 各自默认 | 自定义 | R-TRAF-241~250 | flow |
| ssh -R / -D | 22 | SSH | R-TRAF-251~260 | ssh |

---

## 1. frp / frps / frpc

### 1.1 默认端口

- **frps（服务端）监听**：`7000`（bind_port） / `7500`（dashboard） / `7001`（kcp）
- **frpc（客户端）**：无监听，主动连接 frps 的 7000
- 护网期间攻击者常改端口伪装成 HTTP（80）/ HTTPS（443）/ MySQL（3306）等常见服务

### 1.2 握手 magic 首包指纹

- frp 默认首包（TypeLogin，type=0x6f = 'o'）含 JSON 结构：
  - `"version": "0.x.x"`
  - `"hostname": ""`
  - `"os": "windows|linux|darwin"`
  - `"arch": "amd64|386|arm|arm64"`
  - `"user": ""`
  - `"privilege_key": "<md5>"`
  - `"timestamp": <unix>`
  - `"run_id": "<uuid>"`
  - `"metas": {}`
  - `"pool_count": 0`
- **明文识别**：默认 tcp 模式下 login 报文 base64/明文可见
- **首字节 magic**：frp 协议消息类型字节（0x6f = 'o' Login / 0x70 = 'p' Pong / 0x0 NewProxy 等）

### 1.3 心跳规律

- **frpc → frps**：默认每 **30 秒**发送心跳（`Ping`，type=0x68 'h'），固定长度约 2 字节 + payload
- **frps → frpc**：`Pong` 响应
- **jitter 极低**：默认无 jitter，标准差接近 0 —— 是强特征

### 1.4 TLS 模式识别

- **transport.tls.enable = true**：frp 支持 TLS 加密，此时无法从明文首包判断
- **SNI 常为空** 或含 `"frp"` / 与 dst_ip 不匹配的 SNI
- **JA3 指纹**：Go 语言默认 crypto/tls 客户端 JA3 与浏览器差别大
- **自签证书 CN**：默认自签证书常为空 CN 或 `localhost`

### 1.5 常见配置字符串泄露

明文抓包中如出现以下字段名（在 login 或配置协商包中），高度指向 frp：

- `pool_count` / `privilege_key` / `run_id` / `metas`
- `proxy_type: tcp|udp|http|https|stcp|xtcp`
- `subdomain` / `custom_domains`
- `use_encryption` / `use_compression`

### 1.6 关联 rule_id

- `R-TRAF-201`：TCP 到 7000 / 7500 / 7001 端口（默认端口探测）
- `R-TRAF-202`：明文流量含 frp login JSON 结构（`privilege_key` / `run_id` 字段）
- `R-TRAF-203`：长连接 + 每 30s ±5% 心跳（frp 默认节奏）
- `R-TRAF-204`：TLS + SNI 空或含 "frp" + 长连接
- `R-TRAF-205`：内网主机 → 外网 VPS 段的持久 TCP 连接（1h+）

### 1.7 tshark filter 备忘

```bash
# 默认端口连接
tshark -r <pcap> -Y "tcp.port == 7000 or tcp.port == 7500 or tcp.port == 7001"

# 疑似 frp login 明文
tshark -r <pcap> -Y 'tcp contains "privilege_key" or tcp contains "run_id"'

# 长连接统计
tshark -r <pcap> -q -z conv,tcp | awk '$1 > 3600 {print}'
```

### 1.8 误报排查

- 合法 frp 部署（客户 DevOps 用 frp 做正向映射）：需要客户报备源 IP + 目的 VPS
- 类 frp 协议的工具（fatedier 生态）：识别原理相同

### 1.9 处置

参考 `references/playbooks/traffic-audit.md` §4 场景 D 数据外发。

---

## 2. nps / npc（Chinese fork，与 frp 类似）

### 2.1 默认端口

- **nps（服务端）**：
  - `8024` —— 客户端连接管理端口
  - `8080` —— HTTP 代理
  - `8082` —— HTTPS 代理
  - `8090` —— Web 管理页面（!!! Web 管理页 title 常含 "nps"）
- **npc（客户端）**：主动连接 nps 8024

### 2.2 握手 magic

- npc → nps 首包：**前 4 字节为固定 magic "V2.0" 或类似版本字符串**（不同版本略有差异）
- 后接 vkey（客户端认证密钥）base64 编码

### 2.3 特有字段

- **vkey**：明文抓包中可见 `--vkey=<32 位字符串>`
- **client id**：认证成功后分配的 ID

### 2.4 Web 管理页指纹（护网期间偶尔攻击者忘关）

- 访问 `http://<vps>:8090/` 页面 title：`nps` 或含"内网穿透"字样
- 登录页面 URL：`/login/index`
- 静态资源路径：`/static/img/logo_go.png`

### 2.5 关联 rule_id

- `R-TRAF-211`：TCP 到 8024 端口（nps 默认）
- `R-TRAF-212`：HTTP 访问 `/login/index` 且 title 含 "nps"
- `R-TRAF-213`：明文流量首 4 字节匹配 nps magic

### 2.6 tshark filter 备忘

```bash
# nps 默认端口
tshark -r <pcap> -Y "tcp.port == 8024 or tcp.port == 8090"

# HTTP 层管理页
tshark -r <pcap> -Y 'http.request.uri contains "/login/index" or http.response.body contains "nps"'
```

### 2.7 误报排查

- 端口 8080 / 8082 是常见 HTTP 代理端口，需要看 host 内容判断是否真 nps
- Chinese 开源生态中类 nps 的分支较多，命中一个特征不一定构成结论，需组合判断

### 2.8 处置

同 frp。

---

## 3. chisel

### 3.1 协议特点

- **底层**：HTTP + WebSocket 升级 + SSH-in-WebSocket
- **默认端口**：`8080` / `8443`，护网期间常见改为 `80` / `443`
- **握手**：HTTP CONNECT 或 GET Upgrade: websocket

### 3.2 特有指纹

- **HTTP Header**：
  - `Sec-WebSocket-Protocol: chisel-v3` 或 `chisel-v4`（强特征）
  - `User-Agent: Go-http-client/1.1`（Go 默认 UA）
- **WebSocket 升级后**：底层是 SSH 协议 + `SSH-2.0-chisel-v...` 版本字符串
- **--auth 参数**：客户端命令行 `chisel client --auth user:pass https://<vps> ...`，认证信息以 HTTP Basic 形式带在 URL 中

### 3.3 反向 / 正向模式

- **反向模式**（`chisel client <vps> R:1080:socks`）：客户端在受害者内网，通过 WebSocket 反连 VPS 建立隧道
- **正向模式**（`chisel client <vps> 1080:target-ip:22`）：客户端本地开 socks / 端口转发

### 3.4 关联 rule_id

- `R-TRAF-221`：HTTP 请求头 `Sec-WebSocket-Protocol: chisel-v*`
- `R-TRAF-222`：WebSocket 升级 + Go-http-client UA + 内网发起
- `R-TRAF-223`：WebSocket 负载中出现 SSH-2.0 字符串（SSH-in-WebSocket 特征）
- `R-TRAF-224`：长时间 WebSocket 连接（> 1h）+ 双向数据流

### 3.5 tshark filter 备忘

```bash
# WebSocket 升级 + chisel 特征
tshark -r <pcap> -Y 'http.request.uri and http contains "chisel"'

# WebSocket 长连接
tshark -r <pcap> -Y 'websocket'
```

### 3.6 误报排查

- 合法 WebSocket 长连接（推送服务 / 前端 socket.io） —— 但通常有明确 host / SNI
- 其他 Go 编写的开源工具复用 Go-http-client UA

### 3.7 处置

参考 `references/playbooks/traffic-audit.md` §4。

---

## 4. gost

### 4.1 协议多样性

gost 支持超多协议：`http` / `http2` / `https` / `socks4` / `socks4a` / `socks5` / `relay` / `kcp` / `quic` / `ssh` / `redir` / `tls` / `ohttp` / `mws`（obfs4 WebSocket）等。

### 4.2 特有指纹

- **默认 UA**：`gost/2.x` 或 `gost/3.x`（v2/v3 差异）
- **HTTP CONNECT proxy**：使用 gost 做 HTTPS 代理时会出现 CONNECT 请求，UA 含 gost
- **相互认证 + 加密混淆**：--auth 参数带认证，--tls 参数打开加密
- **--node 与 --serve 参数**：命令行结构在配置协商流量中可能可见

### 4.3 常见部署形态

- `gost -L http://:8080` —— 开 HTTP proxy
- `gost -L socks5://:1080` —— 开 socks5
- `gost -L socks5://:1080 -F ss://method:pass@<vps>:8388` —— 链式转发
- `gost -L relay+tls://:443` —— TLS 混淆

### 4.4 关联 rule_id

- `R-TRAF-231`：HTTP UA 含 `gost/2.` 或 `gost/3.`
- `R-TRAF-232`：CONNECT 请求 + gost UA
- `R-TRAF-233`：内网 socks5 端口（1080 等）出站长连接

### 4.5 tshark filter 备忘

```bash
# gost UA
tshark -r <pcap> -Y 'http.user_agent contains "gost/"'

# socks5 出站
tshark -r <pcap> -Y "tcp.port == 1080 or tcp.port == 8388"
```

### 4.6 误报排查

- 合法运维用 gost 做出网代理（客户报备为准）
- shadowsocks（8388 端口默认）等其他代理工具

### 4.7 处置

参考 `references/playbooks/traffic-audit.md` §4。

---

## 5. stowaway / venom / spp / rustcat（简化描述）

### 5.1 stowaway

- Go 编写的多级代理工具
- 支持 admin-agent 反向 & 主动模式
- 首包 magic：固定 4 字节 header + AES 加密后续
- 支持 --listen / --connect 参数，默认端口无固定值
- 特征：内网主机 → 外网非常规端口 + 加密后无明显协议特征
- 关联 rule_id：`R-TRAF-241` ~ `R-TRAF-244`

### 5.2 venom

- Go 编写，支持多级 socks5 代理
- 默认端口 9999
- 特征：TCP 长连接 + AES 加密载荷 + 无 TLS 握手
- 关联 rule_id：`R-TRAF-245` ~ `R-TRAF-247`

### 5.3 spp（Simple Proxy Protocol / stcp）

- 简单反向代理，代码短小
- 无固定 magic，纯 TCP 转发
- 特征：内网发起 + 长连接 + 无协议 header 的纯字节流
- 关联 rule_id：`R-TRAF-248` ~ `R-TRAF-249`

### 5.4 rustcat / rustscan-tunnel 类

- Rust 生态新兴工具，特征相对少
- 通常需要主机侧结合 process + netconn 才能确定
- 关联 rule_id：`R-TRAF-250`

### 5.5 通用识别思路

- 无法从协议 magic 判断 → 从**行为**判断：
  - 内网主机 → 外网非业务白名单 IP
  - 长连接（> 30 min）
  - 数据流双向 + 混合大小包
  - 无 SNI / 无 HTTP header / 无 SSH header
  - 目的 IP 是 VPS 段（DigitalOcean / Vultr / Linode / Cloudflare Warp）

### 5.6 处置

- 单一无 magic 长连接：升级 P1，联合主机侧确认发起进程
- 主机侧看 `netstat -antp` / `ss -antp` 找发起进程

---

## 6. ssh -R / -D 隧道

### 6.1 特征

- **端口**：默认 22（也可改）
- **SSH 版本字符串**：Client Hello 首包明文可见
  - `SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4`
  - `SSH-2.0-Go` (Go 生态 SSH client)
  - `SSH-2.0-PuTTY_Release_0.78`
  - `SSH-2.0-libssh_0.10.5`
- **-R 反向端口转发**：客户端建立 SSH 后要求 server 端监听某端口 → 数据从 server 侧回流到客户端 → 客户端再本地转发
- **-D 动态代理（socks）**：客户端本地开 socks5，SSH 通道转发所有出站

### 6.2 单向数据流特征

- **反向隧道**：server → client 大量数据（不像正常 SSH 交互）
- **动态代理**：client → 各种目的 IP 的数据混流走 SSH
- **长连接**：> 1h + 无空闲（正常 SSH 空闲期间无数据，隧道期间持续有流量）

### 6.3 SSH 版本识别

- 首包明文识别客户端 / 服务端类型
- 攻击者常见改 `SSH-2.0-` 前缀伪装 Windows Update / 内部工具

### 6.4 关联 rule_id

- `R-TRAF-251`：内网主机 SSH 出站到非管理白名单 IP
- `R-TRAF-252`：SSH 会话时长 > 1h 且双向数据 > 100MB
- `R-TRAF-253`：SSH client 版本字符串异常（非 OpenSSH / PuTTY / 常见 libssh）
- `R-TRAF-254`：SSH 到 22 之外端口（非常规 SSH 端口 + 长连接）

### 6.5 tshark filter 备忘

```bash
# SSH 会话
tshark -r <pcap> -Y "tcp.port == 22"

# SSH 版本字符串（首包明文）
tshark -r <pcap> -Y "tcp.port == 22 and frame.number < 100" -T fields -e ip.src -e ip.dst -e tcp.payload | head

# SSH 长连接
tshark -r <pcap> -q -z conv,tcp -f "port 22"
```

### 6.6 误报排查

- 运维 SSH 到跳板机 —— 有固定管理源 / 目标白名单
- Git-over-SSH：短时间数据流，通常几分钟内结束
- 自动化脚本（Ansible SSH）：源固定 + 目的多主机的短会话集群

### 6.7 处置

参考 `references/playbooks/lateral-movement.md` §SSH 隧道 章节。

---

## 通用识别思路（工具无关）

在无明确工具 magic 时，如下**行为特征组合**几乎确定是隧道：

1. **内网主机 → 外网非白名单 IP**（尤其是 VPS 段）
2. **长连接 > 30 min** 或**超长会话 > 1h**
3. **双向数据流量均衡**（业务场景通常入 >> 出，或 出 >> 入；代理是 1:1）
4. **无标准协议 header**（不是 HTTP / DNS / 明确的 TLS）
5. **加密封装但 SNI 空 / 自签证书**

命中 3 项以上 → P1；命中 4 项以上 + 主机侧异常进程 → P0。

---

## 附录 A：默认端口速查

| 工具 | 默认端口 |
|---|---|
| frp | 7000, 7500, 7001 |
| nps | 8024, 8080, 8082, 8090 |
| chisel | 8080, 8443 |
| gost | 8080, 8388, 1080 |
| stowaway | 无固定 |
| venom | 9999 |
| ssh | 22 |
| shadowsocks | 8388 |
| v2ray | 10086 |
| trojan | 443 (TLS 混淆) |

---

## 附录 B：工具指纹字符串快速索引

| 字符串 | 指向工具 |
|---|---|
| `privilege_key` | frp |
| `run_id` | frp |
| `Sec-WebSocket-Protocol: chisel-v` | chisel |
| `SSH-2.0-chisel-v` | chisel |
| `gost/2.` / `gost/3.` | gost |
| `vkey` | nps |
| `Go-http-client/1.1` + 长连接 | Go 生态工具（frp / chisel / gost 等） |

---

## 附录 C：与其他文档的交叉索引

- pcap 端到端审计流程：`references/playbooks/traffic-audit.md`
- C2 通信识别（工具 vs C2 区分）：`references/attack-patterns/c2-signatures.md` §八
- 基础 12 类流量：`references/attack-patterns/malicious-traffic.md` §12 C2 心跳
- Windows 横向流量：`references/attack-patterns/windows-lateral-traffic.md`
