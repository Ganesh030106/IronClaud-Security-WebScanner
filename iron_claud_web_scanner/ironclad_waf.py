import http.server
import socketserver
import requests
import re
import time
import logging
from urllib.parse import urlparse
from config import WAF_RULES, RATE_LIMIT_THRESHOLD, BAN_DURATION, HONEYPOT_FIELD_NAME

# Setup Logging
logging.basicConfig(filename='waf_events.log', level=logging.INFO, format='%(asctime)s - %(message)s')

# In-Memory State
IP_TRACKER = {}  # {ip: [timestamp1, timestamp2]}
BANNED_IPS = {}  # {ip: unban_time}

# Target Application (The URL you are protecting)
TARGET_SERVER = "http://localhost:5000" # Change this to your real app URL

class WAFHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        self.handle_request("GET")

    def do_POST(self):
        self.handle_request("POST")

    def handle_request(self, method):
        client_ip = self.client_address[0]
        
        # 1. CHECK IF BANNED
        if client_ip in BANNED_IPS:
            if time.time() < BANNED_IPS[client_ip]:
                self.send_error(403, "Access Denied: IP Banned by IronClad WAF")
                return
            else:
                del BANNED_IPS[client_ip] # Unban after time expires

        # 2. RATE LIMITING (Anomaly Traffic)
        if not self.check_rate_limit(client_ip):
            self.ban_ip(client_ip, "Rate Limit Exceeded (DoS Attempt)")
            self.send_error(429, "Too Many Requests - Slow Down")
            return

        # 3. PAYLOAD INSPECTION
        # Get Headers, Path, and Body
        path = self.path
        headers = self.headers
        content_len = int(headers.get('Content-Length', 0))
        body = self.rfile.read(content_len).decode('utf-8', errors='ignore') if content_len > 0 else ""

        # Check Signatures
        violation = self.inspect_traffic(path, body, headers)
        if violation:
            self.ban_ip(client_ip, f"Attack Detected: {violation}")
            self.send_error(403, f"Malicious Request Blocked: {violation}")
            return

        # 4. HONEYPOT CHECK (POST only)
        if method == "POST" and HONEYPOT_FIELD_NAME in body:
            self.ban_ip(client_ip, "Honeypot Triggered (Bot Activity)")
            self.send_error(403, "Bot Detected")
            return

        # 5. FORWARD REQUEST (If Safe)
        self.forward_request(method, path, headers, body)

    def check_rate_limit(self, ip):
        current_time = time.time()
        if ip not in IP_TRACKER:
            IP_TRACKER[ip] = []
        
        # Keep only timestamps from the last 60 seconds
        IP_TRACKER[ip] = [t for t in IP_TRACKER[ip] if current_time - t < 60]
        IP_TRACKER[ip].append(current_time)
        
        return len(IP_TRACKER[ip]) <= RATE_LIMIT_THRESHOLD

    def inspect_traffic(self, path, body, headers):
        """ Checks URI, Body, and User-Agent against WAF Rules """
        combined_payload = f"{path} {body} {headers.get('User-Agent', '')}"
        
        for attack_name, pattern in WAF_RULES.items():
            if re.search(pattern, combined_payload):
                return attack_name
        return None

    def ban_ip(self, ip, reason):
        BANNED_IPS[ip] = time.time() + BAN_DURATION
        logging.warning(f"BANNED IP: {ip} | Reason: {reason}")
        print(f"🚫 [BLOCKED] IP: {ip} | Reason: {reason}")

    def forward_request(self, method, path, headers, body):
        target_url = f"{TARGET_SERVER}{path}"
        try:
            # Filter headers to avoid Hop-by-Hop issues
            forward_headers = {k: v for k, v in headers.items() if k.lower() != 'host'}
            
            resp = requests.request(
                method=method,
                url=target_url,
                headers=forward_headers,
                data=body,
                timeout=5
            )
            
            # Send response back to client
            self.send_response(resp.status_code)
            for k, v in resp.headers.items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(resp.content)
            
        except Exception as e:
            self.send_error(502, f"Upstream Server Error: {e}")

def run_waf(port=8080):
    print(f"🛡️ IronClad WAF running on port {port}")
    print(f"🔗 Protecting Upstream: {TARGET_SERVER}")
    print("logs being written to waf_events.log...")
    with socketserver.TCPServer(("", port), WAFHandler) as httpd:
        httpd.serve_forever()

if __name__ == "__main__":
    run_waf()