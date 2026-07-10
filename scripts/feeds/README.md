# scripts/feeds/ — 规则源同步器

构建期离线拉取外部规则源，转换为 hvv-defender 的 `data/*.json` 格式，运行时零外发。

## 设计原则

- **离线优先**：同步器只在构建期/维护期运行（需联网），产物落 `data/`。检测脚本运行时只读本地 JSON，不联网。
- **红线**：只提取"触发字段 + 关键词"层级检测特征（UA/URI/参数名/正则模式），不输出完整可复现 exploit payload。
- **幂等合并**：同步器按 `pattern`/`id` 去重追加，不覆盖项目原有手维护规则。
- **健壮克隆**：每个同步器浅克隆 + 3 次重试，网络抖动可恢复。

## 已实现

| 同步器 | 源 | 目标 JSON | 条数 | 说明 |
|---|---|---|---|---|
| `sync_owasp_crs.py` | [OWASP CRS](https://github.com/coreruleset/coreruleset) | `data/traffic-signatures.json` (http view) | +149 | 通用 Web 攻击正则（SQLi/RCE/XSS/LFI/RFI），解析 SecRule `@rx` |
| `sync_yara.py` | [bartblaze/Yara-rules](https://github.com/bartblaze/Yara-rules) | `data/webshell-patterns.json` | +4 | 通用 webshell 正则特征（eval/base64），解析 YARA `strings` |
| `sync_et_open.py` | [ET Open](https://rules.emergingthreats.net/) (Proofpoint) | `data/traffic-signatures.json` (http view) | +1512 | 通用扫描器 UA/webshell 标题/挖矿/exploit kit，解析 Suricata `content`/`pcre` |
| `sync_sigma.py` | [SigmaHQ/sigma](https://github.com/SigmaHQ/sigma) | `data/sysmon-detection-rules.json` | +437 | 通用 Windows 持久化/提权/横向/Sysmon，解析 Sigma `detection`（`|contains`/`|endswith`/`|re`） |

## 用法

```bash
# 同步并合并到 data/（默认）
python3 scripts/feeds/sync_owasp_crs.py

# 只预览不写文件
python3 scripts/feeds/sync_owasp_crs.py --dry-run
```

## 待实现（见项目根 todo.md）

- `sync_webshell_traffic.py` — 国内 webshell 管理工具流量特征（Behinder/Godzilla/AntSword）→ `data/traffic-signatures.json`
- `sync_kunpeng.py` — 国内漏洞 POC（FastJSON/Shiro/Struts2/泛微/通达/用友）→ `data/tool-signatures.json`
- `sync_cn_tools.py` — 国内红队/穿透工具流量（frp/nps/chisel/suo5 等）→ `data/traffic-signatures.json`

## 依赖

同步器仅依赖 Python stdlib + PyYAML（Sigma 同步器用）。`hvv_init.sh` 已装 PyYAML。
