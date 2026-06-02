from fastapi import FastAPI, BackgroundTasks, HTTPException, Response
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, HttpUrl
import json
import csv
import io
import os
from urllib.parse import urlparse
from scanner import OWASPTester
from utils.pdf_report import create_pdf_report

app = FastAPI(title="IronClad Security Scanner API")

# Enable CORS for React.js Frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allows all origins in development
    allow_credentials=True,
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

def run_scan_task(url: str):
    global CURRENT_SCAN
    try:
        CURRENT_SCAN["status"] = "scanning"
        CURRENT_SCAN["url"] = url
        CURRENT_SCAN["error"] = None
        CURRENT_SCAN["results"] = None
        
        tester = OWASPTester(url)
        results = tester.run_all_checks()
        
        CURRENT_SCAN["results"] = results
        CURRENT_SCAN["status"] = "completed"
    except Exception as e:
        CURRENT_SCAN["status"] = "failed"
        CURRENT_SCAN["error"] = str(e)

@app.post("/api/scan")
def start_scan(request: ScanRequest, background_tasks: BackgroundTasks):
    global CURRENT_SCAN
    
    url = request.url.strip()
    if not (url.startswith("http://") or url.startswith("https://")):
        raise HTTPException(status_code=400, detail="Invalid protocol. URL must start with http:// or https://")
        
    if CURRENT_SCAN["status"] == "scanning":
        return {"status": "scanning", "message": "A scan is already in progress."}
        
    background_tasks.add_task(run_scan_task, url)
    return {"status": "scanning", "message": "Scan started in background."}

@app.get("/api/scan/status")
def get_scan_status():
    return CURRENT_SCAN

@app.get("/api/export/json")
def export_json():
    global CURRENT_SCAN
    if not CURRENT_SCAN["results"]:
        raise HTTPException(status_code=400, detail="No scan results available to export.")
        
    data = json.dumps(CURRENT_SCAN["results"], indent=4)
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
        
    domain = urlparse(CURRENT_SCAN["url"]).hostname
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
    return {
        "logs": logs,
        "is_running": is_port_open(8080)
    }

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
    
    return {
        "is_trained": ai_model_exists,
        "model_path": "ai_model.pkl" if ai_model_exists else None,
        "logs": logs,
        "is_running": is_port_open(8081)
    }

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
    return load_firewall_config()

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

