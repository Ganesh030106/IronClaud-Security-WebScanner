import http.server
import socketserver
import requests
import pandas as pd
import numpy as np
import logging
import pickle
import os
from sklearn.ensemble import IsolationForest
from urllib.parse import urlparse, parse_qs
from config import AI_FEATURES, AI_MODEL_CONTAMINATION, AI_TRAINING_SIZE, AI_SAVE_PATH

# Logging
logging.basicConfig(filename='ai_firewall_events.log', level=logging.INFO, format='%(asctime)s - %(message)s')

# State
TRAINING_DATA = []
MODEL = None
IS_TRAINED = False
TARGET_SERVER = "http://localhost:5000" # URL of the app you are protecting

class AIFirewallHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        self.handle_request("GET")

    def do_POST(self):
        self.handle_request("POST")

    def handle_request(self, method):
        global MODEL, IS_TRAINED
        
        # 1. Capture & Extract Features
        features = self.extract_features(method)
        
        # 2. Learning Phase
        if not IS_TRAINED:
            TRAINING_DATA.append(list(features.values()))
            print(f"🧠 [LEARNING] Sample collected: {len(TRAINING_DATA)}/{AI_TRAINING_SIZE}")
            
            # Check if ready to train
            if len(TRAINING_DATA) >= AI_TRAINING_SIZE:
                self.train_model()
            
            self.forward_request(method)
            return

        # 3. Prediction Phase (Protection)
        if IS_TRAINED and MODEL:
            # Convert features to dataframe for prediction
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
        
        # Feature 1: Body Length
        body_length = content_len
        
        # Feature 2: Header Count
        header_count = len(headers.keys())
        
        # Feature 3: URI Length
        uri_length = len(path)
        
        # Feature 4: Param Count
        param_count = len(parse_qs(urlparse(path).query))
        
        # Feature 5: Special Char Count (Heuristic for attacks)
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
            # Train Isolation Forest
            df = pd.DataFrame(TRAINING_DATA, columns=AI_FEATURES)
            model = IsolationForest(contamination=AI_MODEL_CONTAMINATION, random_state=42)
            model.fit(df)
            
            MODEL = model
            IS_TRAINED = True
            
            # Save model
            with open(AI_SAVE_PATH, 'wb') as f:
                pickle.dump(model, f)
            
            print("✅ Model Trained & Activated! AI is now protecting the server.")
            logging.info("AI Model Trained Successfully")
        except Exception as e:
            print(f"❌ Training Failed: {e}")

    def forward_request(self, method):
        # ... (Same forwarding logic as previous WAF) ...
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
    with socketserver.TCPServer(("", port), AIFirewallHandler) as httpd:
        httpd.serve_forever()

if __name__ == "__main__":
    run_ai_firewall()