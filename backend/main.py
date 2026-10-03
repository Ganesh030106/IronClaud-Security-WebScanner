from fastapi import FastAPI, BackgroundTasks, HTTPException, Response, Request
from fastapi.encoders import jsonable_encoder
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, HttpUrl
from typing import Optional
import json
import csv
import io
import os
import logging
import math
import time
import socket
import ipaddress
from urllib.parse import urlparse
from scanner import OWASPTester
from utils.pdf_report import create_pdf_report

app = FastAPI(title="IronClad Security Scanner API")

logger = logging.getLogger("webscanner.api")

# HTTP Security Headers Middleware
@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    response.headers["X-Permitted-Cross-Domain-Policies"] = "none"
    return response

@app.on_event("startup")
def startup_event():
    """Start WAF and AI Firewall in background threads on startup."""
    import threading
    try:
        from firewall.ironclad_waf import run_waf
        from firewall.ai_firewall import run_ai_firewall
        
        logger.info("Starting WAF and AI Firewall background services...")
        
        # Start WAF (port 8080)
        waf_thread = threading.Thread(target=run_waf, args=(8080,), daemon=True)
        waf_thread.start()
        logger.info("WAF background thread spawned on port 8080.")
        
        # Start AI Firewall (port 8081)
        ai_thread = threading.Thread(target=run_ai_firewall, args=(8081,), daemon=True)
        ai_thread.start()
        logger.info("AI Firewall background thread spawned on port 8081.")
    except Exception as e:
        logger.error(f"Error starting background firewall services: {e}")


@app.get("/")
@app.head("/")
def root():
    """Root endpoint for pinging and service status."""
    return {
        "status": "online",
        "service": "IronClad Security Scanner API",
        "health": "/api/health"
    }


@app.get("/health")
@app.head("/health")
@app.get("/api/health")
@app.head("/api/health")
def health():
    """Simple health check endpoint."""
    return {"status": "ok", "service": "IronClad Backend"}

# Configure CORS from env for production deployment.
# Example: CORS_ORIGINS=https://iron-claud-security-webscanner.vercel.app,http://localhost:5173
default_origins = [
    "http://localhost:5173",
    "http://127.0.0.1:5173",
    "https://iron-claud-security-webscanner.vercel.app",
    "https://ironclaudsecurity.vercel.app",
]
cors_origins_env = os.getenv("CORS_ORIGINS", "")
env_origins = [o.strip() for o in cors_origins_env.split(",") if o.strip()]
allowed_origins = list(set(default_origins + env_origins))

# Enable CORS for React.js Frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

# In-Memory Scan State
CURRENT_SCAN = {
    "status": "idle",  # idle, scanning, completed, failed
    "url": None,
    "results": None,
    "error": None
}

class ScanRequest(BaseModel):
    url: str
    scan_mode: Optional[str] = "deep"  # "quick" or "deep"

# Security Hardening: SSRF Target Validator
BLOCKED_HOSTNAMES = {
    "localhost", "127.0.0.1", "0.0.0.0", "::1",
    "169.254.169.254", "metadata.google.internal", "instance-data"
}

def is_safe_target(url: str) -> tuple:
    """Validate target URL to prevent SSRF against internal/cloud infrastructure."""
    try:
        if len(url) > 2048:
            return False, "Target URL exceeds maximum allowed length (2048 characters)."
            
        parsed = urlparse(url)
        if parsed.scheme not in ["http", "https"]:
            return False, "Invalid protocol. Target URL must begin with http:// or https://"
        
        hostname = parsed.hostname
        if not hostname:
            return False, "Target URL does not contain a valid host name."

        if hostname.lower() in BLOCKED_HOSTNAMES:
            return False, f"Scanning loopback, internal, or cloud metadata endpoints ({hostname}) is restricted for server security."

        allow_private = os.getenv("ALLOW_PRIVATE_SCANS", "false").lower() in ("true", "1")
        if not allow_private:
            try:
                addr_info = socket.getaddrinfo(hostname, None)
                for item in addr_info:
                    ip_str = item[4][0]
                    ip = ipaddress.ip_address(ip_str)
                    if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved:
                        return False, f"Prohibited SSRF target: resolved IP {ip_str} belongs to private or cloud-internal space (RFC 1918 / 169.254.0.0/16)."
            except socket.gaierror:
                pass

        return True, ""
    except Exception as e:
        return False, f"URL validation error: {str(e)}"

# Sliding-window Rate Limiter (Max 10 scans / 60 seconds per IP)
SCAN_RATE_LIMIT = {}

def check_rate_limit(client_ip: str, max_requests: int = 10, window_seconds: int = 60) -> bool:
    now = time.time()
    history = SCAN_RATE_LIMIT.get(client_ip, [])
    history = [t for t in history if now - t < window_seconds]
    if len(history) >= max_requests:
        SCAN_RATE_LIMIT[client_ip] = history
        return False
    history.append(now)
    SCAN_RATE_LIMIT[client_ip] = history
    return True

def sanitize_for_json(value):
    if isinstance(value, dict):
        return {str(k): sanitize_for_json(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [sanitize_for_json(v) for v in value]
    if isinstance(value, float):
        if math.isnan(value) or math.isinf(value):
            return None
        return value
    return value

def run_scan_task(url: str, scan_mode: str = "deep"):
    global CURRENT_SCAN
    try:
        CURRENT_SCAN["status"] = "scanning"
        CURRENT_SCAN["url"] = url
        CURRENT_SCAN["scan_mode"] = scan_mode
        CURRENT_SCAN["error"] = None
        CURRENT_SCAN["results"] = None
        
        tester = OWASPTester(url, scan_mode=scan_mode)
        results = tester.run_all_checks()
        
        CURRENT_SCAN["results"] = results
        CURRENT_SCAN["status"] = "completed"
    except Exception as e:
        CURRENT_SCAN["status"] = "failed"
        CURRENT_SCAN["error"] = str(e)

@app.post("/api/scan")
def start_scan(request: ScanRequest, background_tasks: BackgroundTasks, req: Request):
    global CURRENT_SCAN
    
    url = request.url.strip()
    is_safe, error_msg = is_safe_target(url)
    if not is_safe:
        raise HTTPException(status_code=400, detail=error_msg)
        
    client_ip = req.client.host if req.client else "unknown"
    if not check_rate_limit(client_ip):
        raise HTTPException(status_code=429, detail="Rate limit exceeded. Maximum 10 scan requests per minute allowed.")
        
    if CURRENT_SCAN["status"] == "scanning":
        return {"status": "scanning", "message": "A scan is already in progress."}
        
    scan_mode = (request.scan_mode or "deep").lower().strip()
    if scan_mode not in ["quick", "deep"]:
        scan_mode = "deep"

    background_tasks.add_task(run_scan_task, url, scan_mode)
    return {"status": "scanning", "message": f"Scan started in background ({scan_mode} mode).", "scan_mode": scan_mode}

@app.get("/api/scan/status")
def get_scan_status():
    try:
        safe_payload = sanitize_for_json(jsonable_encoder(CURRENT_SCAN))
        return JSONResponse(content=safe_payload)
    except Exception as e:
        logger.exception("Failed to encode CURRENT_SCAN for /api/scan/status")
        return JSONResponse(content={
            "status": CURRENT_SCAN.get("status", "failed"),
            "url": CURRENT_SCAN.get("url"),
            "results": None,
            "error": CURRENT_SCAN.get("error") or f"Serialization error: {str(e)}",
        })

@app.get("/api/export/json")
def export_json():
    global CURRENT_SCAN
    if not CURRENT_SCAN["results"]:
        raise HTTPException(status_code=400, detail="No scan results available to export.")
        
    data = json.dumps(sanitize_for_json(CURRENT_SCAN["results"]), indent=4)
    return Response(
        content=data,
        media_type="application/json",
        headers={"Content-Disposition": "attachment; filename=scan_results.json"}
    )

@app.get("/api/export/csv")
def export_csv():
    global CURRENT_SCAN
    if not CURRENT_SCAN["results"]:
        raise HTTPException(status_code=400, detail="No scan results available to export.")
        
    output = io.StringIO()
    writer = csv.writer(output)
    
    # Header
    writer.writerow(["OWASP Category", "Finding / Vulnerability Details"])
    
    # Write Vulnerabilities
    vulns = CURRENT_SCAN["results"].get("vulnerabilities", {})
    for category, details in vulns.items():
        if isinstance(details, list):
            for detail in details:
                if isinstance(detail, dict):
                    writer.writerow([category, f"Type: {detail.get('type')} | File: {detail.get('file')} | Snippet: {detail.get('snippet')}"])
                else:
                    writer.writerow([category, detail])
        elif isinstance(details, dict):
            for k, v in details.items():
                writer.writerow([category, f"{k}: {v}"])
        else:
            writer.writerow([category, str(details)])
            
    return Response(
        content=output.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=scan_results.csv"}
    )

@app.get("/api/export/pdf")
def export_pdf():
    global CURRENT_SCAN
    if not CURRENT_SCAN["results"]:
        raise HTTPException(status_code=400, detail="No scan results available to export.")
        
    domain = urlparse(CURRENT_SCAN["url"]).hostname if CURRENT_SCAN["url"] else "unknown"
    pdf_bytes = create_pdf_report(CURRENT_SCAN["results"], domain)
    
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename=security_report_{domain}.pdf"}
    )

@app.get("/api/waf/logs")
def get_waf_logs():
    logs = []
    paths = ["waf_events.log", "firewall/waf_events.log"]
    for p in paths:
        if os.path.exists(p):
            try:
                with open(p, "r") as f:
                    lines = f.readlines()
                logs = [line.strip() for line in lines[-100:] if line.strip()]
                break
            except:
                pass
    payload = {
        "logs": logs,
        "is_running": is_port_open(8080)
    }
    return JSONResponse(content=sanitize_for_json(payload))

@app.get("/api/ai/status")
def get_ai_status():
    logs = []
    paths = ["ai_firewall_events.log", "firewall/ai_firewall_events.log"]
    for p in paths:
        if os.path.exists(p):
            try:
                with open(p, "r") as f:
                    lines = f.readlines()
                logs = [line.strip() for line in lines[-100:] if line.strip()]
                break
            except:
                pass
            
    # Try finding model in backend or firewall directory
    ai_model_exists = os.path.exists("ai_model.pkl") or os.path.exists("firewall/ai_model.pkl")
    
    payload = {
        "is_trained": ai_model_exists,
        "model_path": "ai_model.pkl" if ai_model_exists else None,
        "logs": logs,
        "is_running": is_port_open(8081)
    }
    return JSONResponse(content=sanitize_for_json(payload))

def is_port_open(port: int) -> bool:
    import socket
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.2)
            return s.connect_ex(("127.0.0.1", port)) == 0
    except:
        return False

CONFIG_FILE = "firewall_config.json"

def load_firewall_config():
    # Keep config in a location accessible to both main.py and firewall proxies
    # We will use firewall_config.json in backend directory, or look for it in both parent and current dirs
    config_paths = [CONFIG_FILE, f"firewall/{CONFIG_FILE}"]
    for cp in config_paths:
        if os.path.exists(cp):
            try:
                with open(cp, "r") as f:
                    return json.load(f)
            except:
                pass
    
    # If not found, write to default CONFIG_FILE (backend root)
    config = {"whitelist": [], "blacklist": []}
    try:
        with open(CONFIG_FILE, "w") as f:
            json.dump(config, f, indent=4)
    except:
        pass
    return config

def save_firewall_config(config):
    config_paths = [CONFIG_FILE, f"firewall/{CONFIG_FILE}"]
    for cp in config_paths:
        try:
            with open(cp, "w") as f:
                json.dump(config, f, indent=4)
        except:
            pass

class IPRequest(BaseModel):
    ip: str

@app.get("/api/waf/config")
def get_waf_config():
    safe_payload = sanitize_for_json(load_firewall_config())
    return JSONResponse(content=safe_payload)

@app.post("/api/waf/config/blacklist")
def add_blacklist(req: IPRequest):
    config = load_firewall_config()
    ip = req.ip.strip()
    if ip and ip not in config["blacklist"]:
        config["blacklist"].append(ip)
        save_firewall_config(config)
    return config

@app.post("/api/waf/config/whitelist")
def add_whitelist(req: IPRequest):
    config = load_firewall_config()
    ip = req.ip.strip()
    if ip and ip not in config["whitelist"]:
        config["whitelist"].append(ip)
        save_firewall_config(config)
    return config

@app.delete("/api/waf/config/blacklist/{ip}")
def remove_blacklist(ip: str):
    config = load_firewall_config()
    if ip in config["blacklist"]:
        config["blacklist"].remove(ip)
        save_firewall_config(config)
    return config

@app.delete("/api/waf/config/whitelist/{ip}")
def remove_whitelist(ip: str):
    config = load_firewall_config()
    if ip in config["whitelist"]:
        config["whitelist"].remove(ip)
        save_firewall_config(config)
    return config

@app.post("/api/ai/config/reset")
def reset_ai_model():
    model_paths = ["ai_model.pkl", "firewall/ai_model.pkl"]
    for p in model_paths:
        if os.path.exists(p):
            try:
                os.remove(p)
            except Exception as e:
                pass
    log_paths = ["ai_firewall_events.log", "firewall/ai_firewall_events.log"]
    for lp in log_paths:
        if os.path.exists(lp):
            try:
                with open(lp, "w") as f:
                    f.write("")
            except:
                pass
    return {"status": "reset", "message": "AI model deleted and logs cleared."}

if __name__ == "__main__":
    import uvicorn
    # Initialize config file on startup
    load_firewall_config()
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)

