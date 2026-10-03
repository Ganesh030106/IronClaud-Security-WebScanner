# 🛡️ IronClad Security Command Center & WebScanner

[![Version](https://img.shields.io/badge/version-2.1.0-blue.svg)](https://github.com/Ganesh030106/IronClaud-Security-WebScanner)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Build Status](https://img.shields.io/badge/build-passing-brightgreen.svg)](https://github.com/Ganesh030106/IronClaud-Security-WebScanner)
[![Python](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/)
[![Node](https://img.shields.io/badge/node-18+-green.svg)](https://nodejs.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.100+-009688.svg)](https://fastapi.tiangolo.com/)
[![React](https://img.shields.io/badge/React-19-61DAFB.svg)](https://react.dev/)
[![Vite](https://img.shields.io/badge/Vite-6.0-646CFF.svg)](https://vitejs.dev/)
[![Deployment: Vercel](https://img.shields.io/badge/frontend-Vercel-black.svg)](https://ironclaudsecurity.vercel.app/)
[![Deployment: Render](https://img.shields.io/badge/backend-Render-46E3B7.svg)](https://ironclaud-security-webscanner.onrender.com/)

**IronClad Security Command Center** is an advanced, enterprise-grade web application vulnerability scanner and dynamic Web Application Firewall (WAF) suite. It bridges active offensive reconnaissance and real-time defensive mitigation by combining active OWASP vulnerability fuzzing, cloud asset discovery, passive DNS reconnaissance, machine learning anomaly detection, and automated virtual patch generation into a unified, cyberpunk-themed command center.

IronClad operates with a **stateless, database-free architecture** engineered for ultra-fast, lock-free concurrency and zero disk footprint.

---

### 🌐 Live Deployments & Interactive Links

| Service | Environment | URL |
| :--- | :--- | :--- |
| **Frontend Web Console** | Production (Vercel) | [https://ironclaudsecurity.vercel.app/](https://ironclaudsecurity.vercel.app/) |
| **Backend API Gateway** | Production (Render) | [https://ironclaud-security-webscanner.onrender.com/](https://ironclaud-security-webscanner.onrender.com/) |
| **Interactive API Documentation** | Swagger UI | [https://ironclaud-security-webscanner.onrender.com/docs](https://ironclaud-security-webscanner.onrender.com/docs) |
| **API Health Status** | Live Health Check | [https://ironclaud-security-webscanner.onrender.com/api/health](https://ironclaud-security-webscanner.onrender.com/api/health) |
| **GitHub Source Code** | Repository | [https://github.com/Ganesh030106/IronClaud-Security-WebScanner](https://github.com/Ganesh030106/IronClaud-Security-WebScanner) |

---

## 📑 Table of Contents

- [Features](#-features)
- [Architecture & Design](#-architecture--design)
- [Project Structure](#-project-structure)
- [Requirements & Dependencies](#-requirements--dependencies)
- [Installation Instructions](#-installation-instructions)
  - [Prerequisites](#prerequisites)
  - [1. Backend Setup](#1-backend-setup)
  - [2. Frontend Setup](#2-frontend-setup)
- [Usage Examples & Getting Started](#-usage-examples--getting-started)
  - [Web Command Center Walkthrough](#web-command-center-walkthrough)
  - [cURL & Automated API Usage](#curl--automated-api-usage)
  - [Preventing Cold Starts with Keep-Alive Cron Jobs](#preventing-cold-starts-with-keep-alive-cron-jobs)
- [Security Hardening & Protection](#-security-hardening--protection)
- [Troubleshooting & FAQ](#-troubleshooting--faq)
- [Contribution Guidelines](#-contribution-guidelines)
- [License Information](#-license-information)
- [Credits & Acknowledgments](#-credits--acknowledgments)
- [Contact & Support](#-contact--support)

---

## ✨ Features

### ⚡ 1. Dual Audit Scanning Modes
- **Quick Recon (Fast Surface Probe)**: Completes surface auditing in under 60 seconds. Performs rapid port scanning, SSL handshake analysis, OWASP Top 10 signature checks, active fuzzing, and machine learning threat evaluation.
- **Deep Audit (Exhaustive Forensic Scan)**: Performs deep recursive directory and API discovery, blind time-based SQL injection, full DNS zone transfer (AXFR), WHOIS lookup, and heavy fuzzing chains.

### 🛡️ 2. Comprehensive 33+ OWASP & CVE Vulnerability Matrix
- **Injection Attacks**: SQL Injection (SQLi), Blind Time-Based SQLi, NoSQL Operator Injection, OS Command Injection, XML External Entity (XXE) Injection, Server-Side Template Injection (SSTI).
- **Broken Access Control & Identity**: Insecure Direct Object References (IDOR), Open Redirection, JWT Algorithm Confusion (`none` alg & key confusion), CORS Wildcard & Credential Misconfigurations.
- **Client-Side & Web Vulnerabilities**: Cross-Site Scripting (Reflected XSS), Missing Subresource Integrity (SRI), Clickjacking (CSP `frame-ancestors` & `X-Frame-Options`), Host Header Injection, HTTP Response Splitting (CRLF).
- **Supply Chain & Deserialization**: Insecure Object Deserialization (`node-serialize`, Python pickle, Java gadgets), Server-Side Request Forgery (SSRF), Web Cache Poisoning & Cache Deception, Prototype Pollution.
- **Recon & Exposure**: AWS S3 Public Bucket Discovery, Git Repository Exposure (`.git/HEAD`), Sensitive Backup Files, PII/Regex Credential Miner, Subdomain Takeover vectors, Rate Limiting & Bot Protection Verification.

### 🧠 3. Interactive CVSS Threat Matrix & Cyber Dossiers
- Interactive vulnerability cards categorized by severity (**Critical**, **High**, **Medium**, **Low**, **Informational**).
- Full **CVSS 3.1 base scoring** with exploitability and impact vector breakdowns.
- One-click **Cyber Dossier Modals** displaying CWE identifiers, vulnerability mechanisms, recommended remediation steps, and dynamic ModSecurity rules.

### 🧱 4. Dual-Engine Firewall Protection
- **Rule-Based WAF (Port 8080)**: Reverse proxy inspecting incoming HTTP traffic against SQLi, XSS, and Path Traversal regular expressions.
- **AI Anomaly Blocker (Port 8081)**: Machine learning proxy powered by `scikit-learn`'s **IsolationForest** model, analyzing HTTP request length, entropy, and character distributions to isolate zero-day anomalies.
- Real-time IP Whitelist and Blacklist management with live traffic logs.

### ⚡ 5. Stateless Database-Free Architecture
- Pure in-memory scan state management eliminates SQLite database file locks, connection timeouts, and database maintenance overhead.
- Supports concurrent multi-threaded execution with instant JSON serialization.

### 📊 6. Multi-Format Forensic Reporting
- Instant **PDF Report** generation (powered by `fpdf2`) with categorized findings, severity badges, executive summary, and defense configs.
- Raw **JSON Cyber Dossier** export for SIEM, SOAR, and automated CI/CD pipeline consumption.
- Structured **CSV Export** for security audits and spreadsheet analysis.

---

## 🏗️ Architecture & Design

```text
                          ┌────────────────────────────────────────────────────────┐
                          │                React.js Frontend Console               │
                          │            (Port 5173 / Hosted on Vercel)              │
                          │   - Terminal Feed    - Threat Matrix   - WAF Manager   │
                          └───────────────────────────┬────────────────────────────┘
                                                      │
                                                      │ HTTPS / JSON API
                                                      ▼
                          ┌────────────────────────────────────────────────────────┐
                          │               FastAPI Production Gateway               │
                          │            (Port 8000 / Hosted on Render)              │
                          │   - SSRF Protection   - Rate Limiter   - CORS Handler  │
                          └──────┬────────────────────┬────────────────────┬───────┘
                                 │                    │                    │
                                 ▼                    ▼                    ▼
        ┌──────────────────────────────────┐ ┌─────────────────┐ ┌─────────────────┐
        │   Stateless In-Memory Engine     │ │  WAF Proxy      │ │  AI ML Firewall │
        │  (Lock-Free Results Cache)       │ │  (Port 8080)    │ │  (Port 8081)    │
        └────────────────┬─────────────────┘ └─────────────────┘ └─────────────────┘
                         │
                         ▼
        ┌──────────────────────────────────────────────────────────────────────────┐
        │                        OWASP Fuzzing & Recon Engine                      │
        │  ┌─────────────────────────┐  ┌────────────────────────┐  ┌────────────┐ │
        │  │ Active OWASP Fuzzers    │  │ Passive Reconnaissance │  │ ML Defense │ │
        │  │ (SQLi, XSS, XXE, SSRF)  │  │ (DNS, SSL, S3, Ports)  │  │ Simulation │ │
        │  └─────────────────────────┘  └────────────────────────┘  └────────────┘ │
        └──────────────────────────────────────────────────────────────────────────┘
```

---

## 📂 Project Structure

```text
WebScanner/
├── backend/                              # Python FastAPI Backend API
│   ├── main.py                           # Application controller, routes, middleware & SSRF guard
│   ├── scanner.py                        # Central scanner orchestrator & OWASPTester engine
│   ├── config.py                         # Fuzzing payloads, regex signatures & CVSS mappings
│   ├── test_endpoints.py                 # Automated API, SSRF, and module test suite
│   ├── requirements.txt                  # Python dependencies
│   ├── runtime.txt                       # Python version pinning for Render (python-3.11.9)
│   │
│   ├── modules/                          # Modular security scanning engines
│   │   ├── active_attackers.py           # SSTI, CRLF Injection, Blind SQLi
│   │   ├── advanced_checks.py            # Subdomain takeover, JWT algorithm checks, git exposure
│   │   ├── advanced_recon.py             # S3 bucket enumeration, API discovery, DNS AXFR
│   │   ├── content_discovery.py          # PII scanner, developer comment mining, backup fuzzing
│   │   ├── defense_generator.py          # Dynamic ModSecurity & Nginx virtual patch generator
│   │   ├── fuzzing_engine.py             # SSRF, XXE, NoSQLi, Deserialization, Cache Poisoning
│   │   ├── specialized_checks.py         # GraphQL, Host Header Injection, Prototype Pollution
│   │   └── traffic_anomaly.py            # Rate limiting validation & scanner bot detection
│   │
│   ├── firewall/                         # Standalone reverse-proxy defensive firewalls
│   │   ├── ironclad_waf.py               # Regex signature-based reverse proxy WAF (Port 8080)
│   │   └── ai_firewall.py                # Scikit-learn IsolationForest anomaly blocker (Port 8081)
│   │
│   └── utils/                            # System utilities
│       └── pdf_report.py                 # Enterprise PDF report generator using fpdf2
│
├── frontend/                             # React.js SPA (Vite)
│   ├── index.html                        # Application entry document with Share Tech Mono font
│   ├── vite.config.js                    # Vite bundler configuration
│   ├── package.json                      # Node packages & build scripts
│   ├── eslint.config.js                  # ESLint configuration
│   ├── .env                              # Production backend API URL configuration
│   │
│   └── src/
│       ├── main.jsx                      # React DOM bootstrap
│       ├── App.jsx                       # Main dashboard, CVSS Threat Matrix, WAF & AI tabs
│       ├── App.css                       # Component styling
│       ├── index.css                     # Cyberpunk design system, animations & utilities
│       └── api/
│           └── scanner.js                # Frontend API client helper
│
├── vercel.json                           # Vercel deployment routes & HTTP security headers
├── render.yaml                           # Render Web Service blueprint specification
├── LICENSE                               # MIT Open Source License
├── .gitignore                            # Sensitive file & environment exclusion rules
└── README.md                             # Comprehensive project documentation
```

---

## 📦 Requirements & Dependencies

### System Prerequisites
- **Python**: `3.10` or `3.11+`
- **Node.js**: `18.0.0` or higher
- **Git**: Distributed version control

### Backend Dependencies (`backend/requirements.txt`)
| Library | Purpose |
| :--- | :--- |
| **FastAPI** | Asynchronous, high-performance web framework for API routing |
| **Uvicorn [standard]** | Production ASGI server implementation |
| **Requests & HTTPX** | Synchronous and asynchronous HTTP clients for vulnerability probing |
| **Scikit-learn** | Machine learning engine for IsolationForest anomaly classification |
| **FPDF2** | Lightweight, high-speed PDF forensic report generation |
| **WAFW00F** | Automated Web Application Firewall fingerprinting |
| **python-Wappalyzer** | Deep technology stack and server profiling |
| **DNSPython** | DNS resolution, MX records, and AXFR zone transfer testing |
| **python-whois & PyOpenSSL**| Domain registration and TLS/SSL certificate inspection |
| **PyJWT** | JWT token decoding, signature testing, and `none` algorithm verification |
| **BeautifulSoup4** | HTML parsing for form analysis, SRI checks, and comment mining |
| **Pandas & NumPy** | Data manipulation and numerical operations for telemetry data |

### Frontend Dependencies (`frontend/package.json`)
| Library | Purpose |
| :--- | :--- |
| **React 19 & React DOM** | Modern declarative UI component architecture |
| **Vite 6 / 8** | Next-generation frontend tooling and fast HMR bundling |
| **Lucide React** | Cyberpunk and security iconography |
| **Recharts** | Interactive SVG threat distribution graphs |
| **React Router DOM** | Client-side routing management |

---

## 🚀 Installation Instructions

### Prerequisites
Make sure [Python 3.11+](https://www.python.org/downloads/) and [Node.js 18+](https://nodejs.org/) are installed on your machine.

---

### 1. Backend Setup

1. **Clone the Repository**:
   ```bash
   git clone https://github.com/Ganesh030106/IronClaud-Security-WebScanner.git
   cd IronClaud-Security-WebScanner/backend
   ```

2. **Create and Activate a Virtual Environment**:
   - **Linux / macOS**:
     ```bash
     python3 -m venv venv
     source venv/bin/activate
     ```
   - **Windows (PowerShell)**:
     ```powershell
     python -m venv venv
     .\venv\Scripts\Activate.ps1
     ```

3. **Install Dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

4. **Run the Automated Test Suite**:
   ```bash
   python test_endpoints.py
   ```
   *Verifies HTTP security headers, root and health endpoints, SSRF guards, WAF configs, and fuzzing engines.*

5. **Start the FastAPI Backend Server**:
   ```bash
   uvicorn main:app --host 0.0.0.0 --port 8000 --reload
   ```
   * The API gateway will be accessible at: `http://127.0.0.1:8000`
   * Interactive Swagger documentation: `http://127.0.0.1:8000/docs`
   * Background threads for WAF (port `8080`) and AI Firewall (port `8081`) spawn automatically on startup.

---

### 2. Frontend Setup

1. **Navigate to the Frontend Directory**:
   ```bash
   cd ../frontend
   ```

2. **Install Node Packages**:
   ```bash
   npm install
   ```

3. **Configure Environment Variables**:
   Create a `.env` file in the `frontend` folder (defaults to local backend if omitted):
   ```env
   VITE_API_BASE_URL=http://127.0.0.1:8000
   ```

4. **Run the Development Server**:
   ```bash
   npm run dev
   ```
   * Open `http://localhost:5173` in your browser to launch the Command Center.

5. **Build for Production**:
   ```bash
   npm run build
   ```

---

## 💡 Usage Examples & Getting Started

### Web Command Center Walkthrough

1. **Target Selection**: Navigate to `http://localhost:5173` or the [Live Deployment](https://ironclaudsecurity.vercel.app/).
2. **Select Audit Mode**:
   - **⚡ QUICK RECON**: Fast surface profiling and OWASP checks (recommended for general health checks, <60s).
   - **🔍 DEEP AUDIT**: Full recursive fuzzing, blind time-based SQLi, and exhaustive directory discovery.
3. **Execute Audit**: Enter a valid target (e.g., `https://example.com`) and click **INITIALIZE SECURITY AUDIT**.
4. **Live Terminal Feed**: Watch real-time streaming logs as the scanner probes ports, SSL handshakes, headers, and OWASP endpoints.
5. **Threat Matrix & Remediation**: Switch to the **Threat Matrix** tab to inspect CVSS scores, filter by category or severity, and click **Remediation Dossier** to view ModSecurity virtual patches.
6. **Export Reports**: Download forensic reports via **Export PDF**, **Export JSON**, or **Export CSV**.

---

### cURL & Automated API Usage

#### 1. Service Health Check
```bash
curl -X GET "https://ironclaud-security-webscanner.onrender.com/api/health"
```
*Response:*
```json
{"status": "ok", "service": "IronClad Backend"}
```

#### 2. Trigger a Scan (Quick Recon Mode)
```bash
curl -X POST "https://ironclaud-security-webscanner.onrender.com/api/scan" \
     -H "Content-Type: application/json" \
     -d '{"url": "https://example.com", "scan_mode": "quick"}'
```

#### 3. Poll Scan Progress & Results
```bash
curl -X GET "https://ironclaud-security-webscanner.onrender.com/api/scan/status"
```

#### 4. Download Forensic PDF Report
```bash
curl -X GET "https://ironclaud-security-webscanner.onrender.com/api/export/pdf" \
     --output ironclad_audit_report.pdf
```

#### 5. Manage WAF IP Rules
```bash
# Add an IP to blacklist
curl -X POST "https://ironclaud-security-webscanner.onrender.com/api/waf/config/blacklist" \
     -H "Content-Type: application/json" \
     -d '{"ip": "203.0.113.42"}'

# Fetch active WAF rules
curl -X GET "https://ironclaud-security-webscanner.onrender.com/api/waf/config"
```

---

### Preventing Cold Starts with Keep-Alive Cron Jobs

Render's free tier spins down inactive web services after **15 minutes** of no HTTP traffic. To keep your backend hot in memory and eliminate 30–50 second cold starts:

1. Create a free account at [cron-job.org](https://cron-job.org/) or [UptimeRobot](https://uptimerobot.com/).
2. Create a new cron job:
   - **URL**: `https://ironclaud-security-webscanner.onrender.com/api/health`
   - **Method**: `GET` (or `HEAD`)
   - **Schedule**: Every `10 minutes`
3. Save the job. This keeps the backend permanently warm without exceeding Render's 750 free monthly instance hours.

---

## 🔒 Security Hardening & Protection

IronClad is designed with defense-in-depth measures to protect both the host environment and target assets:

1. **Server-Side Request Forgery (SSRF) Guard**:
   The backend resolves target hostnames before scanning. Prohibits scanning loopback addresses (`127.0.0.1`, `localhost`, `::1`), private internal network ranges (RFC 1918: `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), and cloud provider metadata addresses (`169.254.169.254`).
2. **API Abuse Rate Limiting**:
   Employs a sliding-window rate limiter restricting IP addresses to a maximum of 10 scan dispatches per minute, mitigating denial-of-service risks against backend resources.
3. **Comprehensive HTTP Security Headers**:
   Both backend endpoints and frontend static assets enforce strict headers:
   - `Content-Security-Policy`: Restricts script and resource origins.
   - `Strict-Transport-Security`: Enforces TLS encryption for 2 years (`max-age=63072000`).
   - `X-Frame-Options: DENY`: Prevents UI redressing and clickjacking.
   - `X-Content-Type-Options: nosniff`: Mitigates MIME-type sniffing vulnerabilities.
   - `Referrer-Policy: strict-origin-when-cross-origin`: Protects sensitive referer URLs.
   - `Permissions-Policy`: Restricts access to device sensors and media devices.
4. **Reverse Tabnabbing Mitigation**:
   All external links and report download anchors include `rel="noopener noreferrer"`.

---

## 🛠️ Troubleshooting & FAQ

#### Q: cron-job.org or monitoring tool returned `{"detail":"Not Found"}` (404 Error).
**A:** In FastAPI, any unregistered path returns a 404. Ensure your monitor points to:
- `https://ironclaud-security-webscanner.onrender.com/api/health` or
- `https://ironclaud-security-webscanner.onrender.com/` (root endpoint)
Both endpoints support `GET` and lightweight `HEAD` methods and return `200 OK`.

#### Q: The first scan request to the live website takes 30-50 seconds to respond.
**A:** Render free tier puts idle instances to sleep after 15 minutes. The first incoming request triggers a cold-start spin-up; subsequent requests respond instantaneously. Set up a 10-minute keep-alive cron job as described above to keep it permanently awake.

#### Q: How can I scan internal/local sites during development?
**A:** Set the environment variable `ALLOW_PRIVATE_SCANS=true` in your local backend environment before launching `python main.py` to disable SSRF protection for local loopback testing.

#### Q: Why do I get a port binding error on ports 8080 or 8081?
**A:** The background WAF proxies listen on ports 8080 and 8081. If those ports are occupied by another program, stop the conflicting service or adjust the port numbers in `backend/main.py`.

#### Q: ESLint reports errors after modifying frontend components.
**A:** Run `npm run lint` in the `frontend` directory. All React 19 JSX components must comply with standard rules without unused imports or unescaped characters.

---

## 🤝 Contribution Guidelines

Contributions are welcome! Please follow these steps:

1. **Fork the Repository**: Click the `Fork` button at the top right of the GitHub page.
2. **Create a Feature Branch**:
   ```bash
   git checkout -b feature/awesome-new-checker
   ```
3. **Write Clean, Tested Code**:
   - For backend changes, ensure `python test_endpoints.py` passes cleanly.
   - For frontend changes, ensure `npm run lint` and `npm run build` pass without warnings or errors.
4. **Commit Your Changes**: Follow conventional commit guidelines:
   ```bash
   git commit -m "feat: add GraphQL introspection vulnerability check"
   ```
5. **Push and Open a Pull Request**:
   ```bash
   git push origin feature/awesome-new-checker
   ```
   Open a Pull Request describing your changes, motivation, and test validation.

---

## 📄 License Information

This project is licensed under the **MIT License** — see the [LICENSE](LICENSE) file for complete details.

> **⚠️ Ethical Use Disclaimer**: IronClad Security Scanner is intended strictly for authorized educational, research, and defensive penetration testing purposes. Scanning targets without prior explicit written permission from the asset owner is strictly prohibited and may violate local and international cybersecurity laws.

---

## 🎖️ Credits & Acknowledgments

- **[OWASP Foundation](https://owasp.org/)**: Foundational methodologies and vulnerability classification standards.
- **[WAFW00F](https://github.com/EnableSecurity/wafw00f)**: Web Application Firewall fingerprinting signatures.
- **[Scikit-learn](https://scikit-learn.org/)**: Machine learning anomaly detection algorithms.
- **[FastAPI](https://fastapi.tiangolo.com/)**: High-performance asynchronous Python API framework.
- **[FPDF2](https://py-pdf.github.io/fpdf2/)**: High-speed forensic PDF document generation.
- **[Lucide Icons](https://lucide.dev/)**: Streamlined cybersecurity visual iconography.
- **[React](https://react.dev/) & [Vite](https://vitejs.dev/)**: Modern frontend framework and bundling architecture.

---

## 📬 Contact & Support

- **Author**: Ganesh S ([@Ganesh030106](https://github.com/Ganesh030106))
- **Email**: [ganesh.s030106@gmail.com](mailto:ganesh.s030106@gmail.com)
- **Repository**: [https://github.com/Ganesh030106/IronClaud-Security-WebScanner](https://github.com/Ganesh030106/IronClaud-Security-WebScanner)
- **Issues & Bug Reports**: [Submit an Issue](https://github.com/Ganesh030106/IronClaud-Security-WebScanner/issues)
- **Feature Requests & Feedback**: [Start a Discussion](https://github.com/Ganesh030106/IronClaud-Security-WebScanner/discussions)
