<div align="center">

# KOVSCAN v3.0
### Advanced Vulnerability Assessment Framework

Developed by **D4RK-K1NG**

<br>

<img src="https://img.shields.io/badge/Python-3.x-111111?style=for-the-badge&logo=python">
<img src="https://img.shields.io/badge/Security-Framework-111111?style=for-the-badge">
<img src="https://img.shields.io/badge/Version-v3.0-111111?style=for-the-badge">
<img src="https://img.shields.io/badge/License-Educational-111111?style=for-the-badge">

</div>

---

## Overview

KOVSCAN is a high-performance vulnerability assessment and reconnaissance framework designed for authorized penetration testing and cybersecurity research.

The framework combines crawling, enumeration, service analysis, and vulnerability detection into a unified automated pipeline built for modern web application testing.

---

## Core Modules

| Module | Description |
|--------|-------------|
| Spider Engine | Recursive crawling and reconnaissance |
| Port Scanner | Multi-threaded TCP scanning and banner grabbing |
| Directory Enumeration | Hidden path and sensitive file discovery |
| Subdomain Enumeration | DNS resolution and HTTP probing |
| Vulnerability Engine | Automated vulnerability detection |
| Sensitive Data Scanner | Secret and credential exposure detection |

---

## Spider Engine

The crawler performs deep reconnaissance against target applications.

### Features

- Recursive crawling
- Form extraction
- JavaScript endpoint discovery
- HTML comment analysis
- API endpoint detection
- Email harvesting
- Technology fingerprinting
- Robots.txt parsing
- Sitemap extraction
- Session token analysis
- JWT discovery
- WebSocket detection

---

## Port Scanner

The scanning engine supports high-speed concurrent port scanning with service fingerprinting.

### Capabilities

- Multi-threaded TCP scanning
- 200+ common ports
- Banner grabbing
- SSL service detection
- Reverse DNS lookup
- HTTP/HTTPS probing
- Timeout handling
- Service identification

### Supported Services

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

## Directory Enumeration

The directory engine performs dictionary-based discovery of hidden files, endpoints, and administrative panels.

### Detection Targets

```txt
/admin
/login
/dashboard
/.git
/.env
/backup.zip
/config.php
/database.sql
```

---

## Subdomain Enumeration

The subdomain engine identifies accessible hosts and exposed infrastructure.

### Example Targets

```txt
admin.target.com
api.target.com
dev.target.com
mail.target.com
vpn.target.com
staging.target.com
beta.target.com
```

---

## Vulnerability Engine

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

## Detection Techniques

### SQL Injection

- Error-based injection
- Boolean-based injection
- Time-based injection
- UNION-based injection

### Cross-Site Scripting

- Reflected XSS
- Stored XSS
- DOM-based XSS

### Command Injection

- Synchronous execution detection
- Time-delay analysis
- OS command payload testing

### SSRF Detection

Internal service probing and cloud metadata targeting.

---

## Sensitive Data Detection

The framework searches for exposed credentials and secrets including:

- API Keys
- JWT Tokens
- AWS Credentials
- SMTP Credentials
- Database Passwords
- Firebase Secrets
- Private Keys
- GitHub Tokens

---

## Installation

### Clone Repository

```bash
git clone https://github.com/D4RK-K1NG/KOVSCAN.git
cd KOVSCAN
```

### Install Dependencies

```bash
pip install -r requirements.txt
```

---

## Usage

### Basic Scan

```bash
python kovscan.py -u https://target.com
```

### Deep Scan

```bash
python kovscan.py -u https://target.com --deep
```

### Port Scan

```bash
python kovscan.py --ports target.com
```

### Directory Enumeration

```bash
python kovscan.py --dirs https://target.com
```

### Subdomain Enumeration

```bash
python kovscan.py --subs target.com
```

---

## Example Output

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

## Performance

| Feature | Details |
|----------|---------|
| Concurrent Workers | High-speed scanning |
| Async Networking | Optimized requests |
| Smart Retry Logic | Improved reliability |
| Adjustable Timeouts | Flexible performance tuning |
| Export Formats | TXT / JSON / HTML |

---

## Legal Disclaimer

KOVSCAN is intended strictly for authorized security testing, educational purposes, and research.

Unauthorized scanning or exploitation of systems without explicit permission may violate applicable laws and regulations.

The developer assumes no responsibility for misuse or damages caused by this software.

---

## Developer

```txt
Developer : D4RK-K1NG
Framework : KOVSCAN
Version   : v3.0
Category  : Vulnerability Assessment Framework
```

---

<div align="center">

KOVSCAN v3.0  
Advanced Security Assessment Framework

</div>
