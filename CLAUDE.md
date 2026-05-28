# ClaudeSec — AI-Driven Security Testing Framework

> **Author**: ClaudeSec Team
> **Version**: 2.0.0
> **License**: MIT
> **Description**: An AI-powered penetration testing assistant framework that orchestrates industry-standard security tools with Claude's reasoning capabilities.

## ⚠️ Legal Notice

This framework is **ONLY** for:
- Authorized penetration testing engagements
- CTF (Capture The Flag) competitions
- Self-hosted lab environments
- Bug bounty programs with clear scope authorization
- Security research on your own infrastructure

**Unauthorized use is illegal.** Users assume all legal responsibility.

---

## 🎯 Slash Commands

### Intelligence Gathering

#### `/recon <target>`
Full-spectrum reconnaissance: subdomain enumeration → port scanning → fingerprinting → directory bruteforce → JS analysis → AI-powered attack surface mapping.

**Usage**: `/recon example.com` or `/recon 192.168.1.1`

```yaml
Execution Flow:
  Phase 1 - Asset Discovery:
    subfinder        → Passive subdomain enumeration (30+ sources)
    waybackurls      → Historical URL extraction
    crt.sh           → Certificate transparency logs
    gau              → Multi-source URL aggregation
  Phase 2 - Network Probe:
    naabu            → Fast port scan (top 1000)
    nmap -sC -sV     → Service version detection
    nmap -O          → OS fingerprinting
  Phase 3 - Web Recon:
    whatweb          → CMS/framework/WAF identification
    httpx            → HTTP probe & response analysis
  Phase 4 - Directory Enum:
    ffuf             → High-speed directory bruteforce
    dirsearch        → Multi-extension file discovery
  Phase 5 - JS Analysis:
    hakrawler        → JS file extraction
    gf patterns      → API endpoints & secret scanning
  Phase 6 - AI Synthesis:
    Attack surface report
    Vulnerability probability assessment
    Recommended next steps
```

---

### Vulnerability Assessment

#### `/scan <target>`
Multi-dimensional vulnerability scanning covering OWASP Top 10 and business logic flaws.

**Usage**: `/scan example.com` or `/scan https://target.com/api`

```yaml
Detection Matrix:
  🔴 Critical/High:
    - SQL Injection (error-based, time-blind, boolean-blind)
    - Authentication bypass (IDOR, privilege escalation)
    - Remote Code Execution (if applicable)
    - Arbitrary file upload
    - Sensitive data exposure (.git, .env, credentials)

  🟡 Medium:
    - Cross-Site Scripting (stored, reflected, DOM)
    - Server-Side Template Injection
    - Server-Side Request Forgery
    - Local/Remote File Inclusion
    - JWT vulnerabilities (alg:none, weak key, kid injection)
    - Business logic flaws
    - CSRF / SSO misconfiguration

  🟢 Low:
    - CORS misconfiguration
    - Missing security headers
    - Information disclosure (banner, debug info)
    - Weak password policy
    - HTTPS configuration issues
```

---

### Specialized Operations

#### `/attack-surface <target>`
Comprehensive attack surface analysis and exploitation path mapping.

**Usage**: `/attack-surface example.com`

**Output structure**:
```
Target: example.com
├── Exposed Ports & Services
│   ├── 80/tcp  → Apache 2.4.49 (CVE-2021-41773)
│   └── 22/tcp  → OpenSSH 7.9
├── Web Application
│   ├── Fingerprint: WordPress 5.8 (known CVEs)
│   └── WAF: Cloudflare (bypass techniques available)
├── Subdomains
│   ├── admin.example.com (login portal)
│   └── dev.example.com (staging environment)
├── Sensitive Findings
│   ├── /.git/config exposed
│   └── /swagger/ API documentation
├── Attack Paths (sorted by likelihood)
│   ├── [EXPLOITABLE] Path 1: ... → ... → ...
│   └── [THEORETICAL] Path 2: ... → ... → ...
└── Difficulty Assessment
    └── Estimated effort: Medium (2-3 hours)
```

#### `/check <url>`
Rapid single-point vulnerability verification.

**Usage**: `/check https://target.com/api/user?id=1`

```yaml
Automatic Checks:
  - Unauthenticated access (remove auth headers)
  - SQL injection (parameter fuzzing)
  - XSS (context-aware payload injection)
  - Path traversal (../ injection)
  - Sensitive data in response
  - Parameter pollution
  - Rate limiting testing
```

---

### Reporting

#### `/report`
Generate a comprehensive penetration testing report in markdown format. Compiles all findings from the current session.

**Usage**: `/report`

**Report sections**:
- Executive summary (management overview)
- Vulnerability details (per severity)
- Attack chain analysis
- Remediation recommendations
- Appendices (raw data, tool output)

---

## ⚙️ AI Analysis Engine

Claude processes all tool outputs through a multi-stage analysis pipeline:

### Analysis Pipeline

```
Raw Tool Output
     ↓
┌─────────────────────┐
│  Stage 1: Parser   │ → Structured data (JSON schema)
└─────────────────────┘
     ↓
┌─────────────────────┐
│  Stage 2: Enricher │ → Cross-reference (CVE DB, known exploits)
└─────────────────────┘
     ↓
┌─────────────────────┐
│  Stage 3: Filter   │ → False positive reduction (response size, status codes, context)
└─────────────────────┘
     ↓
┌─────────────────────┐
│  Stage 4: Ranker   │ → Priority scoring (CVSS, exploitability, impact)
└─────────────────────┘
     ↓
┌─────────────────────┐
│  Stage 5: Planner  │ → Attack chain construction + next-step recommendation
└─────────────────────┘
     ↓
Structured Report
```

### Analysis Rules

| Rule | Description |
|------|-------------|
| **Context-Aware FP Filter** | Analyzes response content, not just status codes. Example: a 200 response containing `"error":"invalid input"` is marked as NOT exploitable |
| **Multi-Source Correlation** | Cross-correlates findings across tools. Same vulnerability detected by nmap + whatweb + manual check = higher confidence |
| **Attack Chain Inference** | Identifies how low-severity issues combine into critical exploits (e.g., LFI + log poisoning = RCE) |
| **WAF-Aware Detection** | Adjusts interpretation when WAF is detected (false negatives expected, suggests bypass techniques) |
| **Priority Scoring** | Uses modified CVSS 3.1 scoring with contextual exploitation difficulty adjustment |

---

## 🔧 Tool Requirements

### Mandatory Tools

```bash
# System packages
sudo apt install -y nmap whatweb dirsearch curl wget git python3-pip

# Go tools (requires Go 1.18+)
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/ffuf/ffuf/v2@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest

# Python tools
pip3 install uro beautifulsoup4
```

### Recommended Tools

```bash
# Go
go install github.com/hakluke/hakrawler@latest
go install github.com/tomnomnom/waybackurls@latest
go install github.com/tomnomnom/gf@latest
go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
go install github.com/lc/gau@latest

# Python
pip3 install arjun git-dumper

# Others
sudo apt install -y sqlmap
```

### Tool Verification

```bash
for tool in nmap whatweb subfinder ffuf httpx; do
    which $tool >/dev/null 2>&1 && echo "✓ $tool" || echo "✗ $tool (missing)"
done
```

---

## 📋 Workflow Guidelines

### Before Testing

1. Confirm written authorization from target owner
2. Define clear scope boundaries (IP ranges, domains, test depth)
3. Set up isolated testing environment if possible
4. Verify all tools are installed and functional

### During Testing

- Start with passive techniques before active scanning
- Control request rate to avoid service disruption
- Document every finding with timestamp and raw response
- Verify findings manually before reporting
- Handle PII/data with extreme care

### After Testing

- Remove any testing tools from target environment
- Securely store test data (encrypted, access-controlled)
- Generate comprehensive report within 48 hours
- Follow responsible disclosure timeline (typically 90 days)

---

## 📁 Project Structure

```
ClaudeSec/
├── CLAUDE.md              # Claude skill definitions (this file)
├── README.md              # Project documentation
├── scripts/
│   ├── install.sh         # One-click dependency installer
│   └── verify.sh          # Tool installation verification
├── wordlists/             # Custom wordlists (optional)
├── docs/
│   └── reference.md       # Detailed technical reference
└── .gitignore
```

---

## 📚 Learning Resources

- [OWASP Top 10](https://owasp.org/www-project-top-ten/) — Web application security risks
- [PortSwigger Web Security Academy](https://portswigger.net/web-security) — Free hands-on security training
- [HackTheBox](https://www.hackthebox.com/) — Practice platform
- [PentesterLab](https://pentesterlab.com/) — Hands-on security exercises
- [CVE Details](https://www.cvedetails.com/) — Vulnerability database

---

> **Remember**: With great power comes great responsibility. This framework amplifies your testing capability — use it ethically and legally.
