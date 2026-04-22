# W3B_SC4NN3R 🔍

> A Python-based web vulnerability scanner for authorized security testing.

![Python](https://img.shields.io/badge/Python-3.8%2B-blue?style=flat-square&logo=python)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)
![Status](https://img.shields.io/badge/Status-Active-brightgreen?style=flat-square)

---

## ⚠️ Disclaimer

**This tool is intended for authorized security testing and educational purposes only.**  
Running this scanner against systems you do not own or have explicit permission to test is **illegal**.  
The author is not responsible for any misuse or damage caused by this tool.

---

## Features

| Module | What it checks |
|---|---|
| **SQL Injection** | URL params & form inputs tested with 14 payloads; detects MySQL/MSSQL error leaks |
| **XSS** | Reflected XSS across form fields using 12 payloads including SVG & event-handler vectors |
| **Remote Code Execution** | Probes query params for command-output indicators |
| **Security Misconfiguration** | Checks for exposed `Server`/`X-Powered-By` headers and missing security headers (CSP, HSTS, etc.) |
| **Broken Authentication** | Tests common weak credential pairs; inspects session cookie behaviour |
| **CSRF** | Detects POST forms without a CSRF/anti-forgery token |

---

## Requirements

- Python 3.8+
- pip packages:

```
requests
beautifulsoup4
pyfiglet
```

Install all dependencies:

```bash
pip install -r requirements.txt
```

**`requirements.txt`:**
```
requests>=2.28.0
beautifulsoup4>=4.11.0
pyfiglet>=0.8.0
```

---

## Installation

```bash
git clone https://github.com/0xMiSHR4/W3B_SC4NN3R.git
cd W3B_SC4NN3R
pip install -r requirements.txt
```

---

## Usage

```bash
python W3B_SC4NN3R.py <URL> [options]
```

### Arguments

| Argument | Description | Default |
|---|---|---|
| `url` | Target URL (must include `http://` or `https://`) | required |
| `-t`, `--timeout` | Request timeout in seconds | `5` |
| `--skip` | Skip specific modules | none |

### Examples

**Basic scan:**
```bash
python W3B_SC4NN3R.py https://example.com
```

**Custom timeout:**
```bash
python W3B_SC4NN3R.py https://example.com -t 10
```

**Skip RCE and CSRF modules:**
```bash
python W3B_SC4NN3R.py https://example.com --skip rce csrf
```

**Available skip values:** `sqli`, `xss`, `rce`, `misconfig`, `auth`, `csrf`

---

## Output

Results are printed to the terminal with color-coded severity levels and simultaneously saved to a `.txt` report file in the same directory.

```
[VULN]  — Vulnerability confirmed
[WARN]  — Potential issue / missing best-practice header
[SAFE]  — No issue detected for this module
[ERROR] — Request or connection error
[INFO]  — Informational (e.g. number of forms found)
```

Report files are named after the target URL, e.g.:
```
https___example_com.txt
```

---

## Project Structure

```
W3B_SC4NN3R/
├── W3B_SC4NN3R.py     # Main scanner script
├── requirements.txt   # Python dependencies
└── README.md
```

---

## License

[MIT License](LICENSE)
