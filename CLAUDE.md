# ClaudeSec — AI-Driven Security Testing Framework

> **Author**: ClaudeSec Team
> **Version**: 2.1.0
> **License**: MIT
> **Description**: AI-powered penetration testing assistant orchestrating industry-standard security tools with Claude's reasoning capabilities.

## ⚠️ Legal & Ethical Notice

This framework is **STRICTLY FOR AUTHORIZED USE ONLY**:
- Authorized penetration testing engagements (written authorization required)
- CTF competitions and wargames
- Self-hosted laboratory environments  
- Bug bounty programs (in-scope targets only)
- Security research on your own infrastructure

**Unauthorized use constitutes illegal activity.** Users assume all legal responsibility.

---

## 🎯 Slash Commands

### Intelligence Gathering

#### `/recon <target>`
**Full-spectrum reconnaissance**: subdomain enumeration → port scanning → fingerprinting → directory bruteforce → JS analysis → AI-powered attack surface mapping.

**Usage**: `/recon example.com` or `/recon 192.168.1.1`

**Execution Flow**:
```
Phase 1 — Asset Discovery
  subfinder  → Passive enumeration (30+ sources, recursive)
  crt.sh     → Certificate transparency log query
  gau        → Multi-source URL aggregation (Wayback, OTX, CommonCrawl)
  httpx      → Host validation & HTTP probe (status, title, technology)

Phase 2 — Network Reconnaissance
  naabu      → High-speed port scan (configurable port range)
  nmap -sCV  → Service version detection + default scripts
  nmap -O    → OS fingerprinting via TCP/IP stack analysis

Phase 3 — Web Fingerprinting
  whatweb    → CMS/framework/WAF identification (1800+ plugins)
  httpx      → Response header analysis & technology inference
  wafw00f    → WAF classification & fingerprinting

Phase 4 — Directory & File Enumeration
  ffuf       → Multi-wordlist directory bruteforce (configurable)
  dirsearch  → Multi-extension file discovery (php, asp, bak, env, zip)
  Priority:  config → api docs → admin → backups → lfi

Phase 5 — JavaScript Analysis
  hakrawler  → JS file extraction & endpoint discovery
  gf         → Pattern matching: API keys, JWTs, endpoints, debug paths
  regex      → Hardcoded secrets: AK/SK, tokens, internal URLs

Phase 6 — AI Synthesis
  Attack surface report with probability heatmap
  Prioritized exploitation path recommendations
  Estimated effort assessment (Low/Medium/High/Critical)
  Next-step tool selection guidance
```

---

#### `/subs <domain>`
**Deep subdomain enumeration**: Focused, multi-source subdomain discovery with live host validation.

**Usage**: `/subs example.com`

**Execution**:
```
subfinder -d <domain> -all -recursive | httpx -silent -status-code -title -tech-detect
```
AI analyzes: subdomain count, categorization (admin, dev, api, cdn), live host verification, technology mapping.

---

### Vulnerability Assessment

#### `/scan <target>`
**Multi-dimensional vulnerability assessment**: 19+ vulnerability categories with context-aware AI verification and CVSS 3.1 scoring.

**Usage**: `/scan example.com` or `/scan https://target.com/api`

**Detection Matrix (by severity)**:

| Priority | Category | Coverage |
|----------|----------|----------|
| 🔴 **Critical** | Remote Code Execution | Command injection, unsafe deserialization, template injection |
| 🔴 **Critical** | SQL Injection | Error-based, time-blind, boolean-blind, stacked queries |
| 🔴 **Critical** | Authentication Bypass | IDOR, privilege escalation, JWT attack |
| 🔴 **Critical** | Arbitrary File Upload | Content-type, extension, content validation bypasses |
| 🔴 **Critical** | Sensitive Data Exposure | .git, .env, cloud credentials, hardcoded secrets |
| 🟠 **High** | Cross-Site Scripting | Stored, reflected, DOM-based (context-aware) |
| 🟠 **High** | SSRF | Cloud metadata, internal port scan, protocol smuggling |
| 🟠 **High** | LFI/RFI | Path traversal, PHP wrappers, log poisoning |
| 🟠 **High** | Unauthenticated Access | API endpoints without auth headers |
| 🟡 **Medium** | SSTI | Jinja2, Twig, Freemarker, Velocity, JSP EL |
| 🟡 **Medium** | CORS Misconfiguration | Origin reflection with credentials |
| 🟡 **Medium** | JWT Weaknesses | alg:none, weak HMAC secret, kid injection |
| 🟡 **Medium** | Business Logic Flaws | Payment manipulation, race conditions, rate limiting bypass |
| 🟢 **Low** | Security Headers | Missing HSTS, CSP, X-Frame-Options, X-Content-Type-Options |
| 🟢 **Low** | TLS/SSL Issues | Weak ciphers, protocol downgrade, certificate validation |
| 🟢 **Low** | Information Disclosure | Banner grabbing, stack traces, debug modes |

---

#### `/attack-surface <target>`
**Comprehensive attack surface analysis** with exploitation path mapping and risk scoring.

**Usage**: `/attack-surface example.com`

**Output**:
```
┌──────────────────────────────────────────────────┐
│              Attack Surface Report                │
├──────────────────────────────────────────────────┤
│ Target:  example.com                              │
├──────────────────────────────────────────────────┤
│ NETWORK        │ Ports: 5 open │ Services: 4     │
│────────────────┼───────────────┼─────────────────┤
│ WEB APPS       │ 2 identified  │ API endpoints: 23│
│────────────────┼───────────────┼─────────────────┤
│ SUBDOMAINS     │ 23 live       │ Admin panels: 3  │
│────────────────┼───────────────┼─────────────────┤
│ SENSITIVE      │ 4 exposures   │ Critical: 1     │
├────────────────┴───────────────┴─────────────────┤
│ ATTACK PATHS                                      │
│ Path 1 [92%] → AWS key leak → S3 breach → RCE    │
│ Path 2 [78%] → WP outdated → CVE exploit → shell │
│ Path 3 [65%] → .git leak → creds → DB access     │
└──────────────────────────────────────────────────┘
```

---

#### `/check <url>`
**Rapid single-point verification**: Test a specific URL for common vulnerability classes.

**Usage**: `/check https://target.com/api/user?id=1`

**Auto-test sequence**:
1. Unauthenticated access (strip auth headers, re-request)
2. SQL injection (error-based, time-based, boolean-based)
3. Reflected XSS (context-aware payload injection)
4. Path traversal (`../etc/passwd`, encoded variants)
5. Sensitive data exposure (credit card, PII regex scan)
6. Response analysis (headers, status codes, content)

---

#### `/fuzz <target> [mode]`
**Automated fuzzing**: Parameter discovery, header injection, and endpoint fuzzing.

**Modes**:
- `params` — Parameter discovery using arjun + custom param list
- `headers` — Header injection testing (Host override, X-Forwarded-For, Content-Type)
- `custom` — User-provided wordlist and target field

**Usage**:
```
/fuzz https://target.com/api params
/fuzz https://target.com/ headers
```

---

### Exploitation

#### `/exploit <vuln-type> <target>`
**Guided exploitation assistance**: AI provides exploitation strategy, tool selection, payload generation, and step-by-step guidance for confirmed vulnerabilities.

**Supported**:
- `sqli` — SQL injection exploitation
- `xss` — XSS proof-of-concept construction
- `lfi` — LFI to RCE via log poisoning / PHP wrapper
- `ssrf` — SSRF to internal service exploitation
- `upload` — File upload to webshell
- `idor` — IDOR parameter brute forcing
- `jwt` — JWT forgery and manipulation

**Usage**:
```
/exploit sqli https://target.com/login
/exploit lfi https://target.com/page?file=test
```

---

#### `/bypass <waf-type>`
**WAF bypass strategy generation**: AI generates targeted evasion techniques for detected WAFs.

**Supported WAFs**: Cloudflare, AWS WAF, ModSecurity, Akamai, F5 BIG-IP, SafeLine, Alibaba Cloud WAF, Imperva

**Usage**: `/bypass cloudflare`

**Output**: 
- WAF-specific detection signatures
- Evasion techniques by vulnerability type (SQLi, XSS, LFI)
- Header manipulation approaches (HTTP method, encoding)
- Origin IP discovery techniques

---

### Reporting

#### `/report [format]`
**Professional report generation**: Compiles all session findings into structured penetration testing report.

**Formats**:
- `full` (default) — Complete pentest report with executive summary
- `executive` — Management-focused risk overview
- `technical` — Detailed technical findings for engineering teams
- `json` — Machine-readable output for integration

**Usage**:
```
/report
/report executive
/report json
```

**Report sections**: Executive summary → Technical findings → Attack chain analysis → Compliance mapping → Remediation roadmap → Appendices

---

#### `/timeline`
**Session activity log**: Display chronological record of all commands executed and key findings in the current session.

**Usage**: `/timeline`

**Output**: Timestamped log of commands, discovered vulnerabilities, and session statistics.

---

### Utilities

#### `/install`
**Dependency management**: Install or verify all required security tools.

**Usage**: `/install`

**Actions**: Checks each tool, installs missing dependencies, reports status.

#### `/help [command]`
**Detailed command reference**: Get usage details, options, and examples for any command.

**Usage**:
```
/help
/help recon
/help scan
```

---

## ⚙️ AI Analysis Engine Specification

### Multi-Stage Pipeline

```
┌─────────────────────────────────────────────────────────────────────┐
│                         ANALYSIS PIPELINE                            │
├──────────┬───────────┬──────────┬──────────┬───────────┬───────────┤
│  PARSE   │  ENRICH   │  FILTER  │  RANK    │  PLAN     │  REPORT   │
├──────────┼───────────┼──────────┼──────────┼───────────┼───────────┤
│ Raw →    │ CVE DB    │ Context  │ CVSS 3.1 │ Attack    │ Structured│
│ JSON     │ Lookup    │ Analysis │ Modified │ Chains    │ Output    │
├──────────┼───────────┼──────────┼──────────┼───────────┼───────────┤
│ Parse    │ Map to    │ Response │ Score    │ Connect   │ Generate  │
│ tool     │ known    │ content  │ with     │ findings  │ markdown  │
│ output   │ exploits  │ analysis │ context  │ into      │ report    │
│          │           │          │ modifiers│ paths     │           │
├──────────┼───────────┼──────────┼──────────┼───────────┼───────────┤
│ ~2s      │ ~3s       │ ~5s      │ ~1s      │ ~3s       │ ~5s       │
└──────────┴───────────┴──────────┴──────────┴───────────┴───────────┘
```

### FP Filter Decision Logic

```
Input: Discovery {vulnerability_type, url, response, confidence}

if response.code in [403, 404, 500]:
    mark_as_false_positive("Blocked by access control or not found")
    return

if response.contains_error_but_sanitized():
    mark_as_false_positive("Error message sanitized, not exploitable")
    return

if WAF_detected AND payload_matches_WAF_signature():
    log("WAF likely blocked payload — suggest bypass technique")
    mark_as_potential("WAF interference suspected")
    return

if vulnerability_type == SQL_INJECTION:
    if response.time_delay_matches(SLEEP(5)):
        mark_as_confirmed("Time-based SQL injection confirmed")
        return
    if response.contains(ERROR_PATTERNS["mysql"]) AND 
       original_response.does_not_contain(ERROR_PATTERNS["mysql"]):
        mark_as_confirmed("Error-based SQL injection confirmed")
        return

if vulnerability_type == XSS:
    if payload_renders_in_response(response, original_payload):
        mark_as_confirmed("Reflected XSS confirmed")
        return
    if response.context_matches(SCRIPT_CONTEXT) AND 
       not response.is_output_encoded():
        mark_as_confirmed("DOM-based XSS suspected")
        return

mark_as_potential("Weak indicators, manual verification recommended")
```

### Confidence Scoring Algorithm

```
Confidence = base_score(30) 
           + tool_consensus_score(0-30)  # Multiple tools flag same issue
           + response_analysis_score(0-20) # Response content matches vuln
           + contextual_score(0-20)      # Environment context (WAF, auth, etc.)
           - false_positive_penalty(0-30) # Known FP patterns detected
```

### Context Modifiers for CVSS 3.1

```
+1.5  PII or sensitive data involved
+1.0  Public exploit code available
-0.5  WAF or IDS detected
-1.0  Authentication required
+1.0  No user interaction required  
-0.5  High complexity exploitation path
```

---

## 🔧 Toolchain

### Mandatory
```
nmap whatweb dirsearch curl wget git python3 subfinder ffuf httpx
```

### Recommended
```
hakrawler waybackurls gf naabu gau nuclei sqlmap arjun git-dumper jwt_tool wafw00f
```

### Quick Verification
```bash
for tool in nmap whatweb subfinder ffuf httpx dirsearch; do
    which $tool &>/dev/null && echo "✓ $tool" || echo "✗ $tool MISSING"
done
```

---

## 📋 Workflow Guidelines

### Testing Lifecycle

```
┌──────────────────────────────────────────────────────────────────┐
│                    PENETRATION TEST LIFECYCLE                      │
├──────────────────────────────────────────────────────────────────┤
│                                                                   │
│  PRE-ENGAGEMENT                                                  │
│  ├── Define scope (IP ranges, domains, excluded targets)         │
│  ├── Obtain written authorization                                │
│  ├── Establish rules of engagement (testing hours, escalation)   │
│  └── Configure toolchain                                         │
│                                                                   │
│  INTELLIGENCE GATHERING → `/recon`                                │
│  ├── Passive reconnaissance (no direct interaction)              │
│  ├── Active reconnaissance (controlled scanning)                 │
│  └── Attack surface mapping                                      │
│                                                                   │
│  THREAT MODELING                                                  │
│  ├── Identify high-value targets (admin panels, API endpoints)   │
│  ├── Map attack vectors                                           │
│  └── Prioritize testing areas                                    │
│                                                                   │
│  VULNERABILITY ANALYSIS → `/scan` `/check` `/fuzz`               │
│  ├── Automated scanning                                           │
│  ├── Manual verification                                          │
│  └── False positive elimination                                  │
│                                                                   │
│  EXPLOITATION → `/exploit`                                        │
│  ├── Confirm exploitability                                       │
│  ├── Chain low-severity issues                                    │
│  └── Document proof-of-concept                                   │
│                                                                   │
│  POST-EXPLOITATION                                                │
│  ├── Lateral movement assessment                                  │
│  ├── Privilege escalation paths                                   │
│  └── Data access verification                                    │
│                                                                   │
│  REPORTING → `/report`                                            │
│  ├── Technical report with reproduction steps                     │
│  ├── Executive summary for management                             │
│  └── Remediation roadmap                                          │
│                                                                   │
└──────────────────────────────────────────────────────────────────┘
```

### Best Practices

1. **Start passive, end active** — Minimize target impact
2. **Rate-limit scans** — Default: 50 req/s max, adjust for fragile targets
3. **Document everything** — Timestamp each finding with raw response
4. **Verify before reporting** — AI flags are indications, not confirmations
5. **Handle data ethically** — PII discovered = stop and document only

---

## 📁 Project Structure

```
ClaudeSec/
├── CLAUDE.md            # Claude skill definitions (this file)
├── README.md            # Comprehensive project documentation
├── CHANGELOG.md         # Version history
├── LICENSE              # MIT license
├── .gitignore           # Project-only git tracking
├── scripts/
│   ├── install.sh       # One-click dependency installer
│   └── verify.sh        # Installation verification
└── docs/
    └── reference.md     # Technical reference manual (payloads, techniques, tools)
```

---

## 📚 Recommended Learning Path

| Stage | Resource | Focus |
|-------|----------|-------|
| 1 | [OWASP Top 10](https://owasp.org/www-project-top-ten/) | Web vulnerability fundamentals |
| 2 | [PortSwigger Web Security Academy](https://portswigger.net/web-security) | Hands-on labs (free) |
| 3 | [HackTheBox](https://www.hackthebox.com/) | Real-world practice |
| 4 | [PentesterLab](https://pentesterlab.com/) | Structured exercises |
| 5 | CVE research & bug bounty writeups | Advanced techniques |

---

> **Responsibility notice**: This framework amplifies your testing capability — use it ethically, legally, and responsibly. The goal is to make systems more secure, not to compromise them.
