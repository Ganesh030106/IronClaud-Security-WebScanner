import http.server
import socketserver
import requests
import pandas as pd
import numpy as np
import logging
import pickle
import os
import sys
from pathlib import Path
from sklearn.ensemble import IsolationForest
from urllib.parse import urlparse, parse_qs

# Add backend directory to path so imports work standalone
sys.path.append(str(Path(__file__).resolve().parent.parent))
from config import AI_FEATURES, AI_MODEL_CONTAMINATION, AI_TRAINING_SIZE, AI_SAVE_PATH

# Logging
logging.basicConfig(filename='ai_firewall_events.log', level=logging.INFO, format='%(asctime)s - %(message)s')

# State
TRAINING_DATA = []
MODEL = None
IS_TRAINED = False
TARGET_SERVER = "http://localhost:5000"

class AIFirewallHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        self.handle_request("GET")

    def do_POST(self):
        self.handle_request("POST")

    def handle_request(self, method):
        global MODEL, IS_TRAINED
        client_ip = self.client_address[0]
        
        # Load Whitelist & Blacklist config dynamically
        import json
        import os
        whitelist = []
        blacklist = []
        config_paths = ["../firewall_config.json", "firewall_config.json"]
        for cp in config_paths:
            if os.path.exists(cp):
                try:
                    with open(cp, "r") as f:
                        config = json.load(f)
                        whitelist = config.get("whitelist", [])
                        blacklist = config.get("blacklist", [])
                        break
                except:
                    pass

        # 0. CHECK BLACKLIST
        if client_ip in blacklist:
            logging.warning(f"BLACKLIST BLOCKED: IP {client_ip} attempted request but is permanently blacklisted")
            self.send_error(403, "Access Denied: IP is Blacklisted by AI Firewall Configuration")
            return

        # 0. CHECK WHITELIST (Bypass anomaly detection)
        if client_ip in whitelist:
            logging.info(f"WHITELIST BYPASS: Allowing whitelisted IP: {client_ip}")
            self.forward_request(method)
            return
        
        # 1. Capture & Extract Features
        features = self.extract_features(method)
        
        # 2. Learning Phase
        if not IS_TRAINED:
            TRAINING_DATA.append(list(features.values()))
            print(f"🧠 [LEARNING] Sample collected: {len(TRAINING_DATA)}/{AI_TRAINING_SIZE}")
            
            if len(TRAINING_DATA) >= AI_TRAINING_SIZE:
                self.train_model()
            
            self.forward_request(method)
            return

        # 3. Prediction Phase (Protection)
        if IS_TRAINED and MODEL:
            df = pd.DataFrame([features])
            prediction = MODEL.predict(df)[0] # 1 = Normal, -1 = Anomaly
            
            if prediction == -1:
                print(f"🔴 [BLOCK] Anomaly Detected! Features: {features}")
                logging.warning(f"ANOMALY BLOCKED: {features}")
                self.send_error(403, "AI Firewall: Traffic Anomaly Detected")
                return
            else:
                print(f"🟢 [PASS] Normal Traffic")
        
        # 4. Forward Safe Traffic
        self.forward_request(method)

    def extract_features(self, method):
        """ Converts HTTP request into numerical features for the AI """
        path = self.path
        headers = self.headers
        content_len = int(headers.get('Content-Length', 0))
        
        body_length = content_len
        header_count = len(headers.keys())
        uri_length = len(path)
        param_count = len(parse_qs(urlparse(path).query))
        
        special_chars = sum(path.count(c) for c in ["'", "\"", "<", ">", ";", "(", ")"])
        
        return {
            "body_length": body_length,
            "header_count": header_count,
            "uri_length": uri_length,
            "param_count": param_count,
            "special_char_count": special_chars
        }

    def train_model(self):
        global MODEL, IS_TRAINED
        print("⚡ Training AI Model...")
        try:
            df = pd.DataFrame(TRAINING_DATA, columns=AI_FEATURES)
            model = IsolationForest(contamination=AI_MODEL_CONTAMINATION, random_state=42)
            model.fit(df)
            
            MODEL = model
            IS_TRAINED = True
            
            with open(AI_SAVE_PATH, 'wb') as f:
                pickle.dump(model, f)
            
            print("✅ Model Trained & Activated! AI is now protecting the server.")
            logging.info("AI Model Trained Successfully")
        except Exception as e:
            print(f"❌ Training Failed: {e}")

    def forward_request(self, method):
        target_url = f"{TARGET_SERVER}{self.path}"
        try:
            headers = {k: v for k, v in self.headers.items() if k.lower() != 'host'}
            content_len = int(self.headers.get('Content-Length', 0))
            body = self.rfile.read(content_len) if content_len > 0 else None

            resp = requests.request(
                method=method,
                url=target_url,
                headers=headers,
                data=body,
                timeout=5
            )
            self.send_response(resp.status_code)
            for k, v in resp.headers.items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(resp.content)
        except Exception as e:
            self.send_error(502, f"Upstream Error: {e}")

def run_ai_firewall(port=8081):
    print(f"🤖 AI Firewall running on port {port}")
    print(f"📚 Waiting for {AI_TRAINING_SIZE} requests to learn normal behavior...")
    
    # Try to load existing model
    global MODEL, IS_TRAINED
    if os.path.exists(AI_SAVE_PATH):
        try:
            with open(AI_SAVE_PATH, 'rb') as f:
                MODEL = pickle.load(f)
            IS_TRAINED = True
            print("✅ Loaded existing AI Model.")
        except:
            pass

    with socketserver.TCPServer(("", port), AIFirewallHandler) as httpd:
        httpd.serve_forever()

if __name__ == "__main__":
    run_ai_firewall()
