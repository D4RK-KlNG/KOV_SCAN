<div align="center">

# KOVSCAN v3.0
### Advanced Vulnerability Assessment Framework

Developed by **D4RK-K1NG**

<br>

<img src="https://img.shields.io/badge/Python-3.x-0f0f0f?style=for-the-badge&logo=python">
<img src="https://img.shields.io/badge/Security-Framework-0f0f0f?style=for-the-badge">
<img src="https://img.shields.io/badge/Version-v3.0-0f0f0f?style=for-the-badge">
<img src="https://img.shields.io/badge/Platform-Linux%20%7C%20Termux%20%7C%20Windows-0f0f0f?style=for-the-badge">

<br><br>

High-performance reconnaissance and vulnerability scanning framework  
built for authorized penetration testing and security research.

</div>

---

# Overview

KOVSCAN is a multi-phase security assessment framework that combines:

- Web Crawling
- Reconnaissance
- Port Scanning
- Directory Enumeration
- Subdomain Discovery
- Vulnerability Detection
- Sensitive Data Exposure Analysis

into a unified automated pipeline.

The framework is designed for security professionals, penetration testers, bug bounty researchers, and cybersecurity enthusiasts performing authorized testing.

---

# Repository

Source code and updates:

[github.com/D4RK-KlNG/KOV_SCAN](https://github.com/D4RK-KlNG/KOV_SCAN/?utm_source=chatgpt.com)

---

# Features

| Module | Description |
|--------|-------------|
| Spider Engine | Recursive crawling and reconnaissance |
| Port Scanner | Multi-threaded TCP scanning |
| Directory Enumeration | Hidden file and endpoint discovery |
| Subdomain Enumeration | DNS and HTTP probing |
| Vulnerability Engine | Automated vulnerability testing |
| Sensitive Data Scanner | Credential and secret detection |
| HTML Reporting | Detailed professional reports |

---

# Spider Engine

The crawler performs deep reconnaissance against target applications.

## Capabilities

- Recursive crawling
- Form extraction
- Parameter discovery
- Email harvesting
- HTML comment analysis
- JavaScript endpoint extraction
- API endpoint detection
- Robots.txt parsing
- Sitemap discovery
- Technology fingerprinting
- JWT token detection
- WebSocket endpoint detection

## Extracted Data

```txt
URLs
Forms
Parameters
Comments
Emails
JavaScript Files
API Endpoints
Technologies
Session Tokens
```

---

# Port Scanner

High-speed multi-threaded TCP scanner with service fingerprinting.

## Features

- 200+ common ports
- Concurrent scanning
- Banner grabbing
- SSL detection
- Reverse DNS lookup
- HTTP/HTTPS probing
- Service identification
- Configurable timeout support

## Supported Services

| Port | Service |
|------|----------|
| 21 | FTP |
| 22 | SSH |
| 25 | SMTP |
| 53 | DNS |
| 80 | HTTP |
| 110 | POP3 |
| 143 | IMAP |
| 443 | HTTPS |
| 3306 | MySQL |
| 5432 | PostgreSQL |
| 6379 | Redis |
| 27017 | MongoDB |

---

# Directory Enumeration

Dictionary-based hidden content discovery engine.

## Detection Targets

```txt
/admin
/login
/dashboard
/.git
/.env
/backup.zip
/config.php
/database.sql
/uploads
/api
```

## Supported Extensions

```txt
.php
.asp
.aspx
.jsp
.do
.action
.html
.htm
```

---

# Subdomain Enumeration

DNS resolution and HTTP probing engine for infrastructure discovery.

## Example Targets

```txt
admin.target.com
api.target.com
dev.target.com
mail.target.com
vpn.target.com
staging.target.com
beta.target.com
```

## Features

- DNS resolution
- Alive host detection
- HTTP status detection
- Page title extraction
- Server header collection
- Wildcard detection

---

# Vulnerability Engine

KOVSCAN includes automated checks for multiple vulnerability classes.

| Vulnerability | Severity |
|---------------|-----------|
| SQL Injection | Critical |
| Cross-Site Scripting (XSS) | High |
| Local / Remote File Inclusion | Critical |
| Server-Side Template Injection | Critical |
| Server-Side Request Forgery | Critical |
| XML External Entity Injection | Critical |
| Command Injection | Critical |
| Open Redirect | Medium |
| Cross-Site Request Forgery | Medium |
| Path Traversal | High |
| Insecure Direct Object References | High |
| CORS Misconfiguration | High |
| Sensitive Data Exposure | Critical |

---

# Detection Techniques

## SQL Injection

- Error-based injection
- Boolean-based injection
- UNION-based injection
- Time-based payload testing

### Example Payloads

```sql
'
' OR '1'='1
admin'--
SLEEP(5)
WAITFOR DELAY '0:0:5'
```

---

## Cross-Site Scripting

- Reflected XSS
- Stored XSS
- DOM-based XSS

### Example Payloads

```html
<script>alert(1)</script>
<img src=x onerror=alert(1)>
"><svg/onload=alert(1)>
```

---

## SSRF Detection

Internal service probing and cloud metadata targeting.

### Internal Targets

```txt
127.0.0.1
localhost
169.254.169.254
metadata.google.internal
```

---

## Command Injection

### Example Payloads

```bash
;id
&& whoami
| uname -a
$(sleep 5)
```

---

# Sensitive Data Detection

The framework searches for exposed credentials and secrets including:

- API Keys
- JWT Tokens
- AWS Credentials
- SMTP Credentials
- Database Passwords
- Firebase Secrets
- GitHub Tokens
- SSH Private Keys
- Configuration Secrets

---

# Output

KOVSCAN generates a detailed HTML report containing:

- Executive summary
- Severity statistics
- Vulnerability breakdown
- Vulnerability evidence
- Payload details
- Open ports and services
- Directory findings
- Subdomain enumeration results
- Crawl statistics
- Technology fingerprinting
- Extracted forms and parameters

## Default Report File

```txt
kovscan_report.html
```

---

# Installation

## Clone Repository

```bash
git clone https://github.com/D4RK-KlNG/KOV_SCAN.git
cd KOV_SCAN
```

## Install Requirements

```bash
pip install -r requirements.txt
```

---

# Usage

```bash
python kovscan.py <target> [options]
```

---

# Basic Examples

## Full Scan

```bash
python kovscan.py https://example.com
```

## Quick Scan

```bash
python kovscan.py https://example.com --quick
```

## Scan Using Proxy

```bash
python kovscan.py https://example.com --proxy http://127.0.0.1:8080
```

## Scan with Authenticated Session

```bash
python kovscan.py https://example.com --cookie "PHPSESSID=abc123"
```

## Port Scan Only

```bash
python kovscan.py 192.168.1.100 --only-port
```

## Directory Enumeration Only

```bash
python kovscan.py https://example.com --only-dir
```

## Subdomain Enumeration Only

```bash
python kovscan.py https://example.com --only-sub
```

## Vulnerability Scan Only

```bash
python kovscan.py https://example.com --only-vuln
```

---

# Options

| Option | Description |
|--------|-------------|
| -h, --help | Show help message |
| --no-crawl | Skip web crawling |
| --no-port | Skip port scanning |
| --no-dir | Skip directory enumeration |
| --no-sub | Skip subdomain enumeration |
| --no-vuln | Skip vulnerability scanning |
| --threads N | Thread count (default: 30) |
| --timeout N | Request timeout |
| --depth N | Crawl depth |
| --max-pages N | Maximum pages to crawl |
| --cookie NAME=VAL | Add cookie |
| --proxy URL | Use HTTP/HTTPS/SOCKS proxy |
| --output FILE | Report filename |
| --only-vuln | Vulnerability scan only |
| --only-port | Port scan only |
| --only-dir | Directory enumeration only |
| --only-sub | Subdomain enumeration only |
| --quick | Quick scan mode |

---

# Example Output

```txt
[+] Target: https://target.com
[+] Crawled URLs: 134
[+] Open Ports: 6
[+] Subdomains Found: 18
[+] Sensitive Files: 3

[CRITICAL] SQL Injection Found
[HIGH] Reflected XSS Found
[MEDIUM] Missing CSRF Protection
```

---

# Performance

| Feature | Details |
|----------|---------|
| Concurrent Workers | High-speed scanning |
| Async Networking | Optimized requests |
| Smart Retry Logic | Improved reliability |
| Adjustable Timeouts | Flexible tuning |
| Export Formats | TXT / JSON / HTML |

---

# Legal Notice

```txt
╔═══════════════════════════════════════════════════════════════╗
║                                                               ║
║   KOVSCAN is a penetration testing framework intended         ║
║   for AUTHORIZED security professionals ONLY.                 ║
║                                                               ║
║   Unauthorized testing against systems you do not own         ║
║   or have explicit written permission to assess may           ║
║   violate applicable laws and regulations.                    ║
║                                                               ║
║   Users are solely responsible for ensuring compliance        ║
║   with local, state, federal, and international laws.         ║
║                                                               ║
║   The developer assumes no liability for misuse, damage,      ║
║   or illegal activities performed using this software.        ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝
```

---

# Developer

```txt
Developer : D4RK-K1NG
Framework : KOVSCAN
Version   : v3.0
Category  : Vulnerability Assessment Framework
```

---

<div align="center">

KOVSCAN v3.0  
Advanced Vulnerability Assessment Framework

</div>
