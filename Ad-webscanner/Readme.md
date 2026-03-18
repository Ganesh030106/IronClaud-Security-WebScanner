# N-Firewall: AI-Powered Web Security Scanner

An advanced Streamlit-based web application security scanner with AI-driven threat detection, firewall simulation, and comprehensive vulnerability reporting.

## Features

### 🔍 Reconnaissance Modules
- **DNS & IP Resolution** – Identify target IP address and perform reverse lookups
- **WHOIS Lookup** – Retrieve domain registration and ownership information
- **Port Scanning** – Concurrent scanning of common ports (21, 22, 80, 443, 3306, 5432, 8080)
- **Admin Page Discovery** – Find common administrative endpoints
- **Robots.txt Analysis** – Extract disallowed paths and sitemap references
- **Web Crawling** – Limited same-domain link discovery (cap at 50 links)
- **JavaScript File Detection** – Identify and catalog JS resources for deeper analysis
- **Sensitive File Discovery** – Probe for exposed config files, backups, and credentials

### 🚨 Vulnerability Checks (OWASP Top 10)
- **A01: Broken Access Control** – Detect exposed admin pages
- **A02: Cryptographic Failures** – Check HTTPS, HSTS, and cookie security flags
- **A03: Injection** – Test forms for SQL injection vulnerabilities
- **A05: Security Misconfiguration** – Validate security headers (CSP, X-Frame-Options, etc.)
- **A06: Vulnerable Components** – Identify exposed software versions
- **A07: Cross-Site Scripting (XSS)** – Probe for reflected XSS vulnerabilities
- **Hardcoded Secrets** – Scan JavaScript files for API keys and credentials

### 🛡️ Advanced Threat Detection
- **DDoS Pattern Detection** – Monitor packet volume and rate anomalies
- **Port Scanning Activity** – Identify sequential port probing behavior
- **Brute-Force Detection** – Track failed login attempts on sensitive paths
- **Malware C2 Communication** – Detect beaconing to known Command & Control servers
- **Data Exfiltration** – Monitor outbound data transfer volume

### 📊 AI Firewall Simulation
- **Threat Scoring** – Weighted Moving Average (WMA) threat calculation
- **Real-time Decision Engine** – Classify traffic as BLOCKED or CLEAN
- **Anomaly Detection** – ML-based predictions using configurable thresholds
- **Firewall Rules Generation** – Auto-generate iptables DROP rules for malicious IPs

### 📄 Reporting
- **Multi-tab Results** – Organized findings in Reconnaissance, Vulnerabilities, Crawl Data, and Raw JSON tabs
- **JSON Export** – Download full scan results for integration with other tools
- **Firewall Logs** – Timestamped event logs from each detection module
- **Metrics** – Access simulated packet counts and performance metrics

## Quick Start

### Prerequisites
- Python 3.9+
- pip or conda

### Installation

1. **Navigate to the folder:**
   ```bash
   cd n_firewall
   ```

2. **Create a virtual environment:**
   ```bash
   python -m venv venv
   ```

3. **Activate the environment:**
   ```bash
   # On Windows
   .\venv\Scripts\activate
   
   # On macOS/Linux
   source venv/bin/activate
   ```

4. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

5. **Run the application:**
   ```bash
   streamlit run app.py
   ```

The app will open at `http://localhost:8501` in your browser.

## Configuration

Edit `config.py` to customize:

- **ANOMALY_THRESHOLD** – Sensitivity for threat detection (0.0–1.0)
- **THREAT_WEIGHTS** – Impact scores for different attack types
- **WMA_DECAY** – Persistence of threat history in calculations
- **DDoS_THRESHOLD_PPS** – Packets-per-second threshold for DDoS detection
- **BRUTE_FORCE_LIMIT** – Failed attempts before blocking
- **SECRET_REGEX** – Patterns to detect hardcoded API keys and secrets
- **ADMIN_PATHS** – List of common admin endpoints to probe
- **SENSITIVE_PATHS** – Config files and backups to search for
- **SECURITY_HEADERS** – Headers to validate for misconfiguration

## File Structure

- **app.py** – Streamlit frontend and UI orchestration
- **scanner.py** – Core vulnerability scanning and threat detection engine
- **config.py** – Configuration constants and thresholds
- **firewall_detector.py** – Firewall simulation logic (optional)
- **pdf_report.py** – PDF report generation utilities
- **requirements.txt** – Python package dependencies

## How It Works

1. **Enter Target URL** – Provide a URL to scan
2. **Reconnaissance Phase** – Gather network info, DNS, WHOIS, ports, admin pages
3. **Vulnerability Scanning** – Test for OWASP flaws, crypto issues, injection, XSS
4. **Advanced Detection** – Run DDoS, brute-force, C2, and exfiltration checks
5. **Threat Scoring** – Calculate WMA-based threat level
6. **Report Generation** – Display findings in tabs; export JSON

## Safety & Legal

⚠️ **Authorization Required** – Only scan targets you own or have explicit written permission to test.

This tool is for:
- Security education and learning
- Authorized penetration testing
- Internal security assessments

Unauthorized scanning is illegal. Use responsibly.

## Dependencies

- **streamlit** – Interactive web UI
- **requests** – HTTP client for scanning
- **beautifulsoup4** – HTML parsing for crawling and form detection
- **python-whois** – WHOIS lookup
- **fpdf2** – PDF report generation

## Notes

- Network timeouts are short; some targets may not respond fully
- DDoS/packet checks are simulated; replace with real metrics for production
- All checks are intentionally basic for educational purposes
- For serious penetration testing, consult professional security tools and consultants