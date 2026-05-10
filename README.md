# ═══════════════════════════════════════════════
# KOVSCAN v3.0 — God Tier Vulnerability Scanner
# ═══════════════════════════════════════════════

**Authorized Penetration Testing & Security Assessment Tool**

KOVSCAN is a multi-phase web application and network vulnerability scanner designed for authorized cybersecurity professionals. It combines web crawling, port scanning, directory enumeration, subdomain discovery, and deep vulnerability assessment into a single automated pipeline.

---

## Features

| Phase | Module | Description |
|-------|--------|-------------|
| 1 | **Spider / Crawler** | Recursive web crawling with form extraction, email harvesting, JS discovery, HTML comment analysis, API endpoint detection, and technology fingerprinting |
| 2 | **Port Scanner** | Multi-threaded TCP port scan against 200+ common ports with service detection and banner grabbing (including SSL) |
| 3 | **Directory Brute Forcer** | Dictionary-based discovery of hidden directories, files, endpoints, and sensitive paths |
| 4 | **Subdomain Enumerator** | DNS resolution and HTTP probing of 200+ common subdomains |
| 5 | **Vulnerability Engine** | 13+ vulnerability checks in parallel |

### Vulnerability Checks

| Vuln Type | Severity | Description |
|-----------|----------|-------------|
| SQL Injection | CRITICAL | Error-based, boolean-based, time-based (SLEEP/WAITFOR) |
| XSS (Reflected/Stored) | HIGH | Form and parameter-based reflected/stored XSS |
| LFI / RFI | CRITICAL | Local & remote file inclusion with /etc/passwd verification |
| SSTI | CRITICAL | Server-Side Template Injection (Jinja2, Freemarker, Smarty, ERB) |
| SSRF | CRITICAL | Server-Side Request Forgery targeting internal/cloud metadata |
| XXE | CRITICAL | XML External Entity injection |
| Command Injection | CRITICAL | OS command injection (sync & time-based) |
| Open Redirect | MEDIUM | Unvalidated redirects to external domains |
| CSRF | MEDIUM | Forms lacking anti-CSRF tokens |
| Path Traversal | HIGH | Directory traversal to filesystem |
| IDOR | HIGH | Insecure Direct Object References |
| CORS Misconfig | MEDIUM/HIGH | Permissive Cross-Origin Resource Sharing |
| Sensitive Data | VARIES | API keys, tokens, passwords, private keys, JWTs |

---

## Installation

```bash
# Clone or download the script
# Install dependencies
pip install -r requirements.txt
