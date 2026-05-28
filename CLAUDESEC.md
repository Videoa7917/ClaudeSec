# 白帽子安全测试助手

## 安全声明
> **本 Skill 仅用于：合法授权的渗透测试、CTF 竞赛、自行搭建的靶机环境、企业 SRC 授权测试。**
> 任何未授权检测行为均违法，使用者自行承担法律责任。

---

## 可用命令

### /recon <target> — 信息收集阶段
自动执行：子域名收集 → 端口扫描 → 指纹识别 → 目录枚举 → JS 分析

### /scan <target> — 漏洞扫描
自动执行：主动漏洞探测、参数 fuzz、常见漏洞排查

### /report — 生成测试报告
汇总所有发现，生成结构化安全报告

### /attack-surface <target> — 攻击面分析
分析目标暴露面，给出入侵路径建议

---

## 信息收集工作流

### 1. 子域名收集
- `subfinder -d <domain> -o subs.txt`
- 调用 AI 分析 DNS 记录（A/CNAME/MX）
- 对比 CDN IP 与真实 IP

### 2. 端口扫描
```bash
nmap -sS -sV -T4 -p- --min-rate=10000 <target>
nmap -sC -sV -p <开放端口> <target>
```
AI 分析：端口 → 服务 → 版本 → 已知漏洞

### 3. 指纹识别
```bash
whatweb <target> -v
```
AI 分析：CMS 类型、框架版本、WAF、中间件

### 4. 目录/文件枚举
```bash
ffuf -u <target>/FUZZ -w <wordlist> -fc 403,404
```
重点关注：
- `.git/` `.env` `.svn/` 配置文件泄露
- `/swagger/` `/api/` `/v1/` API 文档
- `/admin/` `/manager/` 后台入口
- `/backup/` `/upload/` 敏感目录

### 5. JS 分析
- 提取 JS 文件中的 API 端点
- 搜索硬编码密钥（AK/SK，jwt secret，apiKey）
- 分析前端鉴权逻辑缺陷

---

## 漏洞扫描工作流

### 信息泄露
| 检查项 | 方法 |
|--------|------|
| .git 泄露 | `git-dumper` 恢复源码 |
| 目录遍历 | `ffuf` 状态码+响应大小差异 |
| 敏感文件 | dirsearch 字典 |
| JS 泄露 | 正则提取密钥、接口 |

### 逻辑漏洞
| 类型 | 方法 |
|------|------|
| IDOR 越权 | 修改 ID 参数 + 遍历 |
| 未授权 | 删除 Cookie/Token 访问需认证接口 |
| 支付篡改 | 负数、小数、价格字段修改 |
| JWT 攻击 | alg=none、弱密钥爆破、kid 注入 |

### 注入类
| 类型 | 检测方法 |
|------|---------|
| SQLi | 单引号/时间盲注/报错注入 |
| XSS | `<script>alert(1)</script>` + 上下文逃逸 |
| SSTI | `{{7*7}}` `${7*7}` 模板语法 |
| SSRF | 内网地址探活、云元数据 API |
| LFI | `../../etc/passwd` 路径穿越 |

### 文件上传
- Content-Type 绕过
- 后缀黑名单绕过（`.php5` `.phtml` `.phar`）
- 图片马 + 包含利用
- 竞争条件上传

---

## AI 分析引擎

Claude 在每个阶段执行以下分析：

1. **结果解析** — 将工具原始输出转为结构化发现
2. **漏洞判定** — 根据响应特征判断是否存在漏洞
3. **误报过滤** — 结合上下文排除 False Positive
4. **攻击链组合** — 多个低危组合成高危及利用链
5. **下一步建议** — 基于当前发现推荐后续测试方向

---

## 报告模板

```markdown
# 安全测试报告

## 基本信息
- 目标：{{target}}
- 测试时间：{{date}}
- 测试范围：{{scope}}

## 高危漏洞
| # | 类型 | 位置 | 影响 | 复现步骤 |
|---|------|------|------|---------|
| 1 |      |      |      |         |

## 中危漏洞
...

## 低危/信息
...

## 攻击链分析
...

## 修复建议
...
```

---

## 工具依赖安装

```bash
# 基础
apt install nmap whatweb dirsearch -y

# Go 工具
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/ffuf/ffuf/v2@latest
go install github.com/tomnomnom/waybackurls@latest
go install github.com/hakluke/hakrawler@latest
