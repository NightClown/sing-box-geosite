# geo-ruleset-converter

**[English](#english) | [中文](#中文)**

---

<a name="english"></a>

## English

Automatically convert upstream rule lists into **sing-box** (`.json` / `.srs`) and **Mihomo** (`.mrs`) rule-set formats, organised into clean output directories.

> Fork this repo, add your own rules, and let GitHub Actions regenerate everything on every push.

### 📁 Directory Structure

```
.
├── links.txt          # Remote URL list — one URL or ruleset= line per line
├── list/              # Local .list files (e.g. exchange.list, wallet.list)
├── rule/              # Output: sing-box JSON + .srs files
├── mrs/               # Output: Mihomo .mrs binary rule-sets
├── main.py            # Conversion script
└── requirements.txt   # Python dependencies
```

### ✨ Features

| Feature | Description |
|---------|-------------|
| **Plain URL → sing-box** | Fetches `.list`, `.yaml`, or `.txt` rule files from remote URLs and converts to sing-box `.json` + compiled `.srs` |
| **`ruleset=` merging** | Groups multiple remote sources under one tag name into a single merged rule-set (e.g. all Google sub-rules → `Google.json`) |
| **Local `.list` → Mihomo** | Compiles hand-written `.list` files in `list/` directly to Mihomo `.mrs` binaries |
| **JSON → Mihomo** | Every `.json` in `rule/` is also compiled to a matching `.mrs` in `mrs/` |
| **Auto dedup & sort** | All domain and IP rules are deduplicated and sorted before output |
| **Supports all rule types** | `DOMAIN`, `DOMAIN-SUFFIX`, `DOMAIN-KEYWORD`, `IP-CIDR`, `IP-CIDR6`, `DOMAIN-REGEX` |
| **Clash format support** | Handles `clash-classic`, `clash-domain`, and `clash-ipcidr` rule provider formats |
| **`no-resolve` stripping** | Automatically strips `,no-resolve` suffixes from IP-CIDR entries |

### 🚀 Usage

#### Prerequisites

```bash
pip install -r requirements.txt  # Python deps
brew install sing-box             # For .srs compilation
brew install mihomo               # For .mrs compilation
```

#### Run locally

```bash
python3 main.py
```

Output files appear in:
- `rule/` → `*.json` (sing-box source format) + `*.srs` (compiled binary)
- `mrs/`  → `*.mrs` (Mihomo compiled binary)

### ✏️ Adding Rules

#### 1. Remote URL (Plain)

Add a direct link to any `.list`, `.yaml` or `.txt` rule file in `links.txt`:

```
https://raw.githubusercontent.com/NobyDa/Script/master/QuantumultX/Bilibili.list
https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/AppleMusic/AppleMusic.yaml
```

Each URL produces a file named after the remote filename (e.g. `Bilibili.json`, `Bilibili.srs`, `Bilibili.mrs`).

#### 2. Grouped Remote Sources (`ruleset=` format)

Merge multiple remote sources under **one output name** using the `ruleset=` syntax in `links.txt`:

```
ruleset=🔍 Google,clash-domain:https://...google_domain.yaml
ruleset=🔍 Google,clash-ipcidr:https://...google_ipcidr.yaml,no-resolve
ruleset=🔍 Google,clash-classic:https://...Google_No_Resolve.yaml
ruleset=🌟 Gemini,clash-classic:https://...Gemini_No_Resolve.yaml
```

**Format:** `ruleset=<emoji> <Name>,<clash-type>:<url>[,no-resolve]`

Supported clash types:
- `clash-domain` — YAML payload with domain suffixes
- `clash-ipcidr` — YAML payload with IP CIDRs
- `clash-classic` — Mixed Clash rule format

All lines sharing the same `<Name>` are merged into one output:
- `rule/<Name>.json` + `rule/<Name>.srs`
- `mrs/<Name>.mrs`

#### 3. Local `.list` Files → Mihomo `.mrs`

Place a hand-written `.list` file in the `list/` directory:

```
list/
├── exchange.list   # Top crypto exchanges (Binance, OKX, Bybit, Coinbase …)
└── wallet.list     # Fintech wallets (WISE, IBKR, iFAST, N26, Fiat24 …)
```

Supported formats (one rule per line):
```
+.example.com      # domain suffix — matches example.com and all subdomains
example.com        # exact domain match
```

Running `main.py` compiles each file → `mrs/<name>.mrs`.

### 📦 Using the Generated Files

#### sing-box (`.json` source format)

```json
{
  "tag": "geosite-google",
  "type": "remote",
  "format": "source",
  "url": "https://raw.githubusercontent.com/NightClown/geo-ruleset-converter/main/rule/Google.json",
  "download_detour": "proxy"
}
```

#### sing-box (`.srs` compiled binary — faster)

```json
{
  "tag": "geosite-google",
  "type": "remote",
  "format": "binary",
  "url": "https://raw.githubusercontent.com/NightClown/geo-ruleset-converter/main/rule/Google.srs",
  "download_detour": "proxy"
}
```

#### Mihomo / Clash.Meta (`.mrs` compiled binary)

```yaml
rule-providers:
  google:
    type: http
    behavior: domain
    format: mrs
    url: "https://raw.githubusercontent.com/NightClown/geo-ruleset-converter/main/mrs/Google.mrs"
    interval: 86400

rules:
  - RULE-SET,google,PROXY
```

### ⚙️ GitHub Actions (Auto-Update)

Fork this repo and set up a Personal Access Token so Actions can push generated files back:

1. **GitHub → Settings → Developer settings → Personal access tokens** → create token with `repo` scope
2. Add it to your fork: **Settings → Secrets → `GH_TOKEN`**

Actions will re-run `main.py` on every push and commit the updated `rule/` and `mrs/` automatically.

---

<a name="中文"></a>

## 中文

自动将上游规则列表转换为 **sing-box**（`.json` / `.srs`）和 **Mihomo**（`.mrs`）规则集格式，并分类存放到独立目录。

> Fork 本仓库后自行添加规则，由 GitHub Actions 在每次推送时自动重新生成所有文件。

### 📁 目录结构

```
.
├── links.txt          # 远程 URL 列表，每行一个 URL 或 ruleset= 条目
├── list/              # 本地 .list 文件（如 exchange.list、wallet.list）
├── rule/              # 输出：sing-box JSON + .srs 文件
├── mrs/               # 输出：Mihomo .mrs 二进制规则集
├── main.py            # 转换脚本
└── requirements.txt   # Python 依赖
```

### ✨ 功能特性

| 功能 | 说明 |
|------|------|
| **普通 URL → sing-box** | 从远程下载 `.list`、`.yaml`、`.txt` 规则文件并转换为 sing-box `.json` + `.srs` |
| **`ruleset=` 合并** | 将多个远程来源按标签名合并为一个规则集（如所有 Google 子规则 → `Google.json`） |
| **本地 `.list` → Mihomo** | 将 `list/` 目录中的手写 `.list` 文件直接编译为 Mihomo `.mrs` 二进制 |
| **JSON → Mihomo** | `rule/` 下的每个 `.json` 同时编译为 `mrs/` 下对应的 `.mrs` |
| **自动去重排序** | 所有域名和 IP 规则在输出前自动去重并排序 |
| **支持所有规则类型** | `DOMAIN`、`DOMAIN-SUFFIX`、`DOMAIN-KEYWORD`、`IP-CIDR`、`IP-CIDR6`、`DOMAIN-REGEX` |
| **Clash 格式支持** | 支持 `clash-classic`、`clash-domain`、`clash-ipcidr` 规则提供者格式 |
| **自动去除 `no-resolve`** | 自动去除 IP-CIDR 条目中的 `,no-resolve` 后缀，避免编译错误 |

### 🚀 使用方法

#### 环境准备

```bash
pip install -r requirements.txt  # 安装 Python 依赖
brew install sing-box             # 用于编译 .srs
brew install mihomo               # 用于编译 .mrs
```

#### 本地运行

```bash
python3 main.py
```

生成文件位置：
- `rule/` → `*.json`（sing-box 源格式）+ `*.srs`（编译二进制）
- `mrs/` → `*.mrs`（Mihomo 编译二进制）

### ✏️ 添加规则

#### 1. 普通远程 URL

在 `links.txt` 中直接写入远程 `.list`、`.yaml` 或 `.txt` 链接，每行一个：

```
https://raw.githubusercontent.com/NobyDa/Script/master/QuantumultX/Bilibili.list
https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/AppleMusic/AppleMusic.yaml
```

输出文件以远程文件名命名（如 `Bilibili.json`、`Bilibili.srs`、`Bilibili.mrs`）。

#### 2. 多源合并（`ruleset=` 格式）

在 `links.txt` 中使用 `ruleset=` 语法，将多个远程来源合并为**同一个输出文件**：

```
ruleset=🔍 Google,clash-domain:https://...google_domain.yaml
ruleset=🔍 Google,clash-ipcidr:https://...google_ipcidr.yaml,no-resolve
ruleset=🔍 Google,clash-classic:https://...Google_No_Resolve.yaml
ruleset=🌟 Gemini,clash-classic:https://...Gemini_No_Resolve.yaml
```

**格式：** `ruleset=<emoji> <名称>,<clash类型>:<url>[,no-resolve]`

支持的 clash 类型：
- `clash-domain` — YAML payload，包含域名后缀
- `clash-ipcidr` — YAML payload，包含 IP 段
- `clash-classic` — 混合 Clash 规则格式

相同 `<名称>` 的所有行将合并为一个输出：
- `rule/<名称>.json` + `rule/<名称>.srs`
- `mrs/<名称>.mrs`

#### 3. 本地 `.list` 文件 → Mihomo `.mrs`

将手写的 `.list` 文件放入 `list/` 目录：


运行 `main.py` 后每个文件编译为 `mrs/<名称>.mrs`。

### 📦 使用生成的文件

#### sing-box（`.json` 源格式）

```json
{
  "tag": "geosite-google",
  "type": "remote",
  "format": "source",
  "url": "https://raw.githubusercontent.com/NightClown/geo-ruleset-converter/main/rule/Google.json",
  "download_detour": "proxy"
}
```

#### sing-box（`.srs` 编译二进制，加载更快）

```json
{
  "tag": "geosite-google",
  "type": "remote",
  "format": "binary",
  "url": "https://raw.githubusercontent.com/NightClown/geo-ruleset-converter/main/rule/Google.srs",
  "download_detour": "proxy"
}
```

#### Mihomo / Clash.Meta（`.mrs` 编译二进制）

```yaml
rule-providers:
  google:
    type: http
    behavior: domain
    format: mrs
    url: "https://raw.githubusercontent.com/NightClown/geo-ruleset-converter/main/mrs/Google.mrs"
    interval: 86400

rules:
  - RULE-SET,google,PROXY
```

### ⚙️ GitHub Actions（自动更新）

Fork 仓库后配置 Personal Access Token，让 Actions 有权限将生成的文件推送回仓库：

1. **GitHub → Settings → Developer settings → Personal access tokens** → 创建具有 `repo` 权限的 Token
2. 在 Fork 的仓库中添加：**Settings → Secrets → `GH_TOKEN`**

之后每次推送代码，Actions 将自动运行 `main.py` 并提交更新后的 `rule/` 和 `mrs/` 目录。

---

## 🙏 致谢 / Credits

- [@izumiChan16](https://github.com/izumiChan16)
- [@ifaintad](https://github.com/ifaintad)
- [@NobyDa](https://github.com/NobyDa)
- [@blackmatrix7](https://github.com/blackmatrix7)
- [@DivineEngine](https://github.com/DivineEngine)
- [@MetaCubeX](https://github.com/MetaCubeX) — meta-rules-dat
- [@chinnsenn](https://github.com/chinnsenn) — ClashCustomRule
