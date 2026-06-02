# 🛡️ IronClad Security Scanner & WAF Command Center

IronClad is an advanced security scanner and dynamic Web Application Firewall (WAF) that integrates active OWASP vulnerability scanning, cloud bucket discovery, passive DNS reconnaissance, static JavaScript comment mining, and a dual-tier protection firewall (regular-expression WAF + machine learning IsolationForest anomaly blocker).

This repository is a clean, production-ready, merged consolidation of three legacy security scanner implementations, now unified under a React.js single-page application and a Python FastAPI backend.

---

## 🏗️ Architecture

```
                       ┌──────────────────────────────────────────┐
                       │          React.js Frontend SPA           │
                       │             (Port 5173 - Vite)           │
                       └────────────────────┬─────────────────────┘
                                            │
                                            │ HTTP / JSON
                                            ▼
                       ┌──────────────────────────────────────────┐
                       │          FastAPI Backend Server          │
                       │             (Port 8000 - Uvicorn)        │
                       └──────────────┬────────────────────┬──────┘
                                      │                    │
                                      ▼                    ▼
                        ┌───────────────────────────┐┌───────────┐
                        │   OWASP Fuzzing Engine    ││ WAF / AI  │
                        │    (Modules & Recon)      ││ Firewalls │
                        └───────────────────────────┘└───────────┘
```

---

## 📂 Project Structure

```
E:\Firewall-main\Web_scanner\
│
├── backend/                          # Python FastAPI Server
│   ├── main.py                       # API endpoints & controller
│   ├── scanner.py                    # Unified OWASP scanner orchestrator
│   ├── config.py                     # Payloads, regular expressions, and settings
│   ├── requirements.txt              # Backend dependencies
│   │
│   ├── modules/                      # Modular security scanning auditors
│   │   ├── advanced_checks.py        # Subdomain takeover, JWT algorithm checks, git exposure
│   │   ├── advanced_recon.py         # Cloud bucket checks, API discovery, email security, DNS AXFR
│   │   ├── content_discovery.py      # PII scanner, developer comment mining, backup file fuzzing
│   │   ├── specialized_checks.py     # GraphQL, Host Header Injection, Prototype Pollution
│   │   ├── active_attackers.py       # SSTI, CRLF Injection, Time-Based Blind SQLi
│   │   ├── traffic_anomaly.py        # Rate limiting, bot identification
│   │   └── defense_generator.py      # Automating Nginx/ModSecurity virtual patches
│   │
│   ├── firewall/                     # Standalone reverse-proxy traffic blocks
│   │   ├── ironclad_waf.py           # Signature-based reverse proxy WAF (Port 8080)
│   │   └── ai_firewall.py            # ML IsolationForest anomaly blocking proxy (Port 8081)
│   │
│   └── utils/                        # System utilities
│       └── pdf_report.py             # Exportable PDF generator using fpdf2
│
├── frontend/                         # React.js SPA (Vite)
│   ├── index.html                    # Entry document with Share Tech Mono font
│   ├── vite.config.js                # Build configuration
│   ├── package.json                  # Node dependency catalog
│   │
│   └── src/
│       ├── main.jsx                  # React virtual DOM bootstrap
│       ├── App.jsx                   # Central controller, routing tabs, and chart engines
│       ├── App.css                   # Component-level styles
│       ├── index.css                 # Global Cyberpunk styling & utility framework
│       └── api/
│           └── scanner.js            # Fetch client helper
│
├── .gitignore                        # Global VCS filter rules
└── README.md                         # Product documentation
```

---

## ⚡ Setup & Execution

### 1. Run the Backend API
Navigate to the `backend` folder, set up a virtual environment, install dependencies, and launch the API server using Uvicorn:

```bash
cd backend
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
python main.py
```
The FastAPI documentation will be available at `http://127.0.0.1:8000/docs` and the API itself at port `8000`.

### 2. Run the React.js Frontend
In a separate terminal, navigate to the `frontend` folder, install Node packages, and boot up the Vite server:

```bash
cd frontend
npm install
npm run dev
```
Open your browser and navigate to `http://localhost:5173` to access the Cyberpunk Command Center.

### 3. (Mandatory) Run the Firewalls
To demonstrate active inline protection, start either the traditional signature-based WAF or the AI-driven firewall. These run as independent reverse proxies protecting your upstream server:

* **Traditional Signature WAF** (Runs on port `8080`):
  ```bash
  cd backend/firewall
  python ironclad_waf.py
  ```
* **AI Firewall** (Runs on port `8081`):
  ```bash
  cd backend/firewall
  python ai_firewall.py
  ```

## Deployment

### Backend on Render
Deploy the `backend/` directory as a Python web service using the provided [render.yaml](render.yaml). Render should use `uvicorn main:app --host 0.0.0.0 --port $PORT` with `backend/` as the root directory.

### Frontend on Vercel
Deploy the `frontend/` app with the root [vercel.json](vercel.json). In the Vercel project settings, set `VITE_API_BASE_URL` to your Render backend URL, for example `https://webscanner-backend.onrender.com`.

The frontend reads that variable in [frontend/src/api/scanner.js](frontend/src/api/scanner.js), so the browser will send all API requests to Render instead of `localhost`.

---

## 🧠 Dynamic Simulated Threat Scoring

During scanning, the console uses a **Weighted Moving Average (WMA)** to calculate and render a visual chart of incoming threat profiles. This allows security operators to visualize exactly how malicious traffic behaviors trigger automated network blocks (`iptables INPUT DROP` rule recommendations).
