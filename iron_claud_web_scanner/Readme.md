# 🛡️ Advanced Web Application Security Scanner + IronClad WAF

An educational, end-to-end web application security toolkit. It combines a Streamlit UI for interactive scanning, deep recon and vulnerability checks aligned with OWASP guidance, infrastructure and content auditing, programmatic report export, and an optional lightweight reverse-proxy WAF for virtual patching and anomaly blocking.
Use this strictly on targets you are authorized to test.

---

## Overview
- Streamlit app: interactive scanning with dashboards, tabs, and export tools.
- Scanner engine: multi-module checks for OWASP categories and specialized attacks.
- Infrastructure audit: cloud buckets, APIs, DNS zone transfer, email security.
- Content audit: PII, developer comments, backup files, robots.txt paths.
- Defense generation: Nginx/Apache header hardening and ModSecurity rule snippets.
- IronClad WAF: simple reverse-proxy with signature blocking, rate limiting, honeypot, and live logs.

---

## Quick Start

1) Install Python packages

```bash
pip install -r requirements.txt
```

2) Launch the Streamlit UI

```bash
streamlit run app.py
```

3) Optional: Run the IronClad WAF reverse proxy

```bash
python ironclad_waf.py
```

Then enter a target URL (must start with http:// or https://) in the app and press “Start Scan”.

---

## Features

### Streamlit UI Tabs
- Dashboard: status code, HTTP/2, WAF detection, tech stack, secrets, charts.
- Defense & Patching: header configs (Nginx/Apache), ModSecurity rules, live WAF log.
- Infrastructure: cloud bucket checks, API discovery, subdomains, DNS transfer test, email security, reverse DNS, bypass trials.
- Content & PII: PII/secret patterns, developer comments, sensitive backups, robots.txt accessible paths.
- Recon: Wappalyzer-based tech stack + regex fallback, SSL certificate info, emails, subdomains, sitemap, open ports, admin/sensitive files, robots disallowed, JS files, WHOIS.
- Vulnerabilities: Open Redirect, Command Injection, Security Headers, Crypto Failures, Vulnerable Components, XSS, Directory Listing, CORS, Missing SRI, plus findings summary.
- Headers & Cookies: shows response/request headers and cookie attributes.
- Crawl Data: lists crawled links collected during the scan.
- Mitigation Plan: prioritized remediation checklist based on findings.
- Export: JSON and CSV report downloads of the full results.

### Scanner Modules
- `scanner.py` (`OWASPTester`): orchestrates async/sync checks, results aggregation, recon, and vulnerability tests.
- `advanced_checks.py` (`AdvancedAuditor`): subdomain takeover via DNS+HTTP fingerprints, JWT analysis (`alg: none`), `.git` exposure verification, broken-link hijacking.
- `advanced_recon.py` (`InfrastructureAuditor`): cloud bucket enumeration, API discovery, SPF/DMARC checks, CMS sensitive files, DNS zone transfer (AXFR), WAF/403 header bypass, reverse DNS, active robots scanning.
- `content_discovery.py` (`ContentAuditor`): PII detection with Luhn validation, developer comment mining, backup mutation fuzzing, mixed content and dangerous JS sinks.
- `specialized_checks.py` (`SpecializedAuditor`): GraphQL introspection exposure, Host header injection indicators, client-side prototype pollution code patterns.
- `activeattackers.py` (`ActiveAttacker`): SSTI probes, CRLF header injection attempts, time-based blind SQLi.
- `traffanomaly.py` (`AnomalyTester`): rate limiting flood test and bad-bot user-agent behavior.
- `defensegenerator.py` (`DefenseGenerator`): Nginx/Apache header hardening snippets and ModSecurity rule generation for virtual patching.
- `pdf_report.py`: programmatic PDF report builder for results.
- `ironclad_waf.py`: reverse-proxy WAF with regex signatures, rate limit, honeypot field, IP ban duration, and upstream forwarding.

### Key Checks & Signals
- OWASP-style: A01 Broken Access Control, A01 Open Redirect, A02 Crypto Failures, A03 Injection + Command Injection, A05 Security Misconfiguration (headers), A05 Clickjacking, A05 CORS, A05 Directory Listing, A06 Vulnerable Components, A06 Missing SRI, A07 XSS, secrets in JS, IDOR hints.
- Recon & infra: WAF fingerprinting (wafw00f), Wappalyzer tech detection, SSL cert info, subdomains (crt.sh), ports + banner snippets, admin paths, sensitive files, robots, WHOIS, reverse DNS.
- Specialized: GraphQL introspection, Host header poisoning, prototype pollution, JWT weaknesses, `.git` exposure, cloud buckets, API endpoints, DNS zone transfer.
- Defense: auto header config recommendations; ModSecurity rules for SQLi/XSS/path traversal; live WAF monitoring via `waf_events.log`.

---

## Configuration

Primary settings live in `config.py`:
- WAF signatures and `WAF_RULES`, `RATE_LIMIT_THRESHOLD`, `BAN_DURATION`, `HONEYPOT_FIELD_NAME` for `ironclad_waf.py`.
- `SECURITY_HEADERS` baseline; header defaults are applied by `DefenseGenerator`.
- Payload sets: SQLi/XSS/command injection, SSTI/CRLF, prototype pollution regex.
- Recon lists: `ADMIN_PATHS`, `SENSITIVE_PATHS`, `API_ENDPOINTS`, `CLOUD_BUCKET_PATTERNS`, CMS file lists, takeover fingerprints, etc.
- `MITIGATIONS` text used inside the UI for educational guidance.

Adjust `TARGET_SERVER` inside `ironclad_waf.py` to point the WAF to your upstream app (default: `http://localhost:5000`).

---

## Outputs
- JSON and CSV: downloadable from the Export tab in the app.
- WAF events: `waf_events.log` (live entries displayed in the Defense tab).
- PDF: see “Programmatic PDF” below for generating a report from code.

---

## Programmatic PDF (Optional)
You can generate a PDF directly from Python using `pdf_report.py` after obtaining a `results` dict from the scanner.

```python
from pdf_report import create_pdf_report

# results = OWASPTester(base_url).run_all_checks()
# domain = "example.com"
pdf_bytes = create_pdf_report(results, domain)
with open(f"{domain}_report.pdf", "wb") as f:
	f.write(pdf_bytes)
```

---

## Requirements

Core dependencies are listed in `requirements.txt`:
- streamlit, requests, beautifulsoup4, pandas, pyopenssl
- httpx, nest_asyncio, wafw00f
- python-Wappalyzer, nvdlib, dnspython, pyjwt

Note: Some environment setups may require additional system packages for SSL, and `python-Wappalyzer` may need appropriate underlying dependencies depending on platform.

---

## Tips & Troubleshooting
- If WAF detection or tech stack fails, verify network access and SSL/HTTP connectivity to the target.
- Long scans can be constrained by timeouts; the code uses conservative timeouts to keep the UI responsive.
- For WAF use, confirm `TARGET_SERVER` is reachable and that port 8080 is free.
- DNS features require `dnspython`; ensure it’s installed and network DNS is accessible.
- JWT analysis expects tokens in cookies or `Authorization: Bearer` headers.

---

## Legal & Ethical Use
This project is for education and authorized testing only. Do not scan or attack systems without explicit permission.

---

## Project Structure
- `app.py`: Streamlit UI and tabbed visualization/export.
- `scanner.py`: Core scanner orchestrator.
- `advanced_checks.py`, `advanced_recon.py`, `content_discovery.py`, `specialized_checks.py`.
- `activeattackers.py`, `traffanomaly.py`, `defensegenerator.py`.
- `ironclad_waf.py`: reverse-proxy WAF.
- `pdf_report.py`: PDF builder.
- `config.py`: payloads, signatures, defaults, mitigations.
- `requirements.txt`: Python package list.

Change the directory
cd n_firewall

To Create a python environment
python -m venv venv

To Activate the Python Environment
.\venv\Scripts\activate 

Install the required packages: 
pip install -r requirements.txt


Run the app: 
python -m streamlit run app.py



How to Use the Complete Defense System
Start your real application (e.g., on port 5000).

Start the WAF: Open a terminal and run python ironclad_waf.py.

This starts the protection proxy on Port 8080.

Attacker connects to Port 8080 -> WAF filters -> Forwards to Port 5000.

Start the Scanner Dashboard: Open another terminal and run streamlit run app.py.

Monitor: Go to the "WAF Monitor" tab in the dashboard.

Test: Try to send an SQL injection like http://localhost:8080/?q=' OR 1=1.

Result: The browser will show "403 Malicious Request Blocked: SQL_INJECTION".

The Dashboard will instantly show the log entry in red.


How to Demo the AI Firewall
Start the Target App: Run your normal web app on port 5000.

Start the AI Firewall:

Open terminal: python ai_firewall.py

It will say: 📚 Waiting for 50 requests to learn normal behavior...

Training Phase (Normal Behavior):

Browse the site normally through the firewall (e.g., http://localhost:8081/).

Click around, submit normal forms.

You will see: 🧠 [LEARNING] Sample collected: 1/50...

Once it hits 50, it trains and says: ✅ Model Trained & Activated!

Attack Phase (Anomaly Detection):

Now send something "weird" that you didn't do during training.

Example: http://localhost:8081/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa (Huge URL)

Example: http://localhost:8081/?q=' OR 1=1 -- (High special char count)

Result: The AI will likely flag this as an anomaly (because it deviates from the "normal" clusters it learned) and block it with a 403 AI Firewall error.

Check the dashboard to see the log entry.