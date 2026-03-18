import streamlit as st
import requests
import socket
import whois
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup
import re
import concurrent.futures
from config import THREAT_WEIGHTS, ANOMALY_THRESHOLD, WMA_DECAY, THRESHOLD_CRITICAL, THRESHOLD_WARNING, THREAT_IMPACT
import time
from collections import defaultdict
from scapy.all import sniff, TCP, IP
import time
import pandas as pd


# Import configurations from config.py
from config import (ADMIN_PATHS, SQLI_PAYLOADS, XSS_PAYLOAD, SECURITY_HEADERS, SENSITIVE_PATHS, SECRET_REGEX)

MAX_SCAN_THREADS = 50

class OWASPTester:
    def __init__(self, base_url, oast_url=None):
        self.base_url = base_url.rstrip('/')
        self.domain = urlparse(self.base_url).hostname
        self.oast_url = oast_url  # Store the Canary Token URL
        self.session = requests.Session()
        
        # --- OAST INJECTION (HEADERS) ---
        user_agent = "EducationalSecurityScanner/1.0"
        if self.oast_url:
            user_agent = f"{user_agent} (OAST-Check: {self.oast_url})"
        
        self.session.headers.update({
            "User-Agent": user_agent,
            "Referer": self.oast_url if self.oast_url else "http://google.com"
        })
        self.results = {
            "info": {},
            "recon": {},
            "vulnerabilities": {}
        }
        self.visited_links = set()
        self.js_files = set() # Set to store JS file URLs 
        
        # Store initial response
        try:
            self.initial_response = self.session.get(self.base_url, timeout=3)
            self.results["info"]["target"] = self.base_url
            self.results["info"]["status_code"] = self.initial_response.status_code
        except requests.RequestException as e:
            st.error(f"Could not connect to {self.base_url}. Error: {e}")
            self.initial_response = None
            raise
        self.logs = [] # Initialize the log list
        self.log_event("SYSTEM", "AI Firewall Engine Initialized. Monitoring started.")

    def run_all_checks(self):
        # ... (Call your other checks) ...
        
        # Add logs to specific attack detections:
        if self.results["vulnerabilities"].get("DDoS_Detection"):
            self.log_event("ALERT", "DDoS Pattern Detected! Triggering IP Rate-Limit.")
            
        if self.results["vulnerabilities"].get("A03_Injection"):
            self.log_event("CRITICAL", "SQL Injection attempt identified. Generating DROP rule.")
            
        self.results["firewall_logs"] = self.logs
        return self.results
    
    def run_all_checks(self):
        """Orchestrator to run all scan modules."""
        if not self.initial_response:
            return self.results

        with st.spinner("Running all scans..."):
            self.log_event("RECON", f"Starting DNS and Port Discovery on {self.domain}")
            self.get_dns_ip()

            # After each check, add a log entry:
            self.log_event("RECON", f"IP Identified: {self.results['recon'].get('ip_address')}")
            
            # Reconnaissance
            self.get_dns_ip()
            self.get_whois()
            self.scan_ports([21, 22, 80, 443, 3306, 5432, 8080])
            self.find_admin_pages()
            self.check_robots_txt()
            self.crawl_links()

            # Vulnerability Checks
            self.scan_js_files()
            self.check_security_headers()
            self.check_crypto_failures()
            self.check_vulnerable_components()
            self.check_broken_access_control()
            self.check_injection_forms()
            self.check_xss_reflection()
            self.simulate_ai_firewall_reaction()
            # --- NEW: Specific Attack Detection Modules ---
            self.detect_ddos_patterns()
            self.detect_port_scanning_activity()
            self.detect_brute_force_attempts()
            self.detect_malware_beaconing()
            self.detect_data_exfiltration()

            # Final Decision Engine
            self.calculate_wma_threat()
            # Add logs to specific attack detections:
            if self.results["vulnerabilities"].get("DDoS_Detection"):
                self.log_event("ALERT", "DDoS Pattern Detected! Triggering IP Rate-Limit.")
                
            if self.results["vulnerabilities"].get("A03_Injection"):
                self.log_event("CRITICAL", "SQL Injection attempt identified. Generating DROP rule.")
                
            self.results["firewall_logs"] = self.logs
        return self.results
    

    # --- Reconnaissance Modules ---

    def get_dns_ip(self):
        try:
            ip = socket.gethostbyname(self.domain)
            self.results["recon"]["ip_address"] = ip
        except socket.error as e:
            self.results["recon"]["ip_address"] = f"Error: {e}"

    
    def get_whois(self):
        try:
            w = whois.whois(self.domain)
            self.results["recon"]["whois"] = w.text if hasattr(w, 'text') else str(w)
        except Exception as e:
            self.results["recon"]["whois"] = f"Error: {e}"

    # --- Faster Port Scan ---
    def scan_ports(self, ports):
        open_ports = []
        
        def _check_port(port):
            try:
                # Lowered timeout
                with socket.create_connection((self.domain, port), timeout=0.3):
                    return port
            except (socket.timeout, socket.error):
                return None

        with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_SCAN_THREADS) as executor:
            results = executor.map(_check_port, ports)
            open_ports = [port for port in results if port is not None]
            
        self.results["recon"]["open_ports"] = open_ports

    
    def find_admin_pages(self):
        self.failed_admin_attempts = 0
        found_pages = []

        def _check_path(path):
            url = urljoin(self.base_url, path)
            try:
                resp = self.session.get(url, timeout=1.0, allow_redirects=False)

                if resp.status_code in [401, 403]:
                    self.failed_admin_attempts += 1

                if resp.status_code == 200:
                    return url
            except requests.RequestException:
                return None

        with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_SCAN_THREADS) as executor:
            results = executor.map(_check_path, ADMIN_PATHS)
            found_pages = [url for url in results if url is not None]
            
        self.results["recon"]["admin_pages_found"] = found_pages
    
   # --- Faster Sensitive File Scan ---
    def find_sensitive_files(self):
        found_files = []

        def _check_path(path):
            url = urljoin(self.base_url, path)
            try:
                # Lowered timeout
                resp = self.session.head(url, timeout=1.0, allow_redirects=False)
                if 200 <= resp.status_code < 300:
                    return url
            except requests.RequestException:
                return None

        with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_SCAN_THREADS) as executor:
            results = executor.map(_check_path, SENSITIVE_PATHS)
            found_files = [url for url in results if url is not None]
            
        self.results["recon"]["sensitive_files_found"] = found_files

        
    def check_robots_txt(self):
        url = urljoin(self.base_url, "/robots.txt")
        try:
            resp = self.session.get(url, timeout=3)
            if resp.status_code == 200:
                disallowed = re.findall(r"Disallow: (.*)", resp.text)
                self.results["recon"]["robots_txt_disallowed"] = disallowed
            else:
                self.results["recon"]["robots_txt_disallowed"] = "Not found"
        except requests.RequestException as e:
            self.results["recon"]["robots_txt_disallowed"] = f"Error: {e}"
            
    def crawl_links(self):
        to_visit = [self.base_url]
        all_links = set()
        
        while to_visit and len(all_links) < 50: # Limit crawl to 50 links
            url = to_visit.pop()
            if url in self.visited_links:
                continue
                
            self.visited_links.add(url)
            try:
                resp = self.session.get(url, timeout=3)
                soup = BeautifulSoup(resp.text, "html.parser")
                for link_tag in soup.find_all("a", href=True):
                    href = link_tag['href']
                    full_url = urljoin(self.base_url, href)
                    
                    # Stay on the same domain
                    if self.domain in full_url and full_url not in self.visited_links:
                        to_visit.append(full_url)
                        all_links.add(full_url)
                
                # --- Find <script> tags ---
                for script_tag in soup.find_all("script", src=True):
                    src = script_tag['src']
                    full_js_url = urljoin(self.base_url, src)
                    
                    # Add if it's on the same domain and we haven't seen it
                    if self.domain in full_js_url and full_js_url not in self.js_files:
                        self.js_files.add(full_js_url)

            except requests.RequestException:
                continue
        self.results["recon"]["crawled_links"] = list(all_links)
        self.results["recon"]["js_files_found"] = list(self.js_files)

    #NEW: Functions to scan JS files for Secrets --
    def scan_js_files(self):
        found_secrets = []

        def _scan_file(url):
            try:
                # --- MODIFIED: Lowered timeout ---
                resp = self.session.get(url, timeout=2.0)
                # --- END MODIFIED ---
                content = resp.text
                
                for name, pattern in SECRET_REGEX.items():
                    matches = re.finditer(pattern, content)
                    for match in matches:
                        return {
                            "type": name,
                            "file": url,
                            "snippet": match.group(0) 
                        }
            except requests.RequestException:
                return None
            return None

        with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_SCAN_THREADS) as executor:
            results = executor.map(_scan_file, self.js_files)
            found_secrets = [res for res in results if res is not None]
        
        self.results["vulnerabilities"]["CRITICAL_Hardcoded_Secrets"] = found_secrets

    # --- OWASP Vulnerability Modules ---

    def check_security_headers(self):
        headers = self.initial_response.headers
        missing = [h for h in SECURITY_HEADERS if h not in headers]
        self.results["vulnerabilities"]["A05_Security_Misconfig_Headers"] = {
            "present": [h for h in SECURITY_HEADERS if h in headers],
            "missing": missing
        }

    def check_crypto_failures(self):
        issues = []
        if not self.base_url.startswith("https:"):
            issues.append("Site is not served over HTTPS.")
        
        if self.initial_response and "Strict-Transport-Security" not in self.initial_response.headers:
            issues.append("Missing 'Strict-Transport-Security' (HSTS) header.")

        # Check for insecure cookies by inspecting cookie objects in the cookie jar.
        # requests' RequestsCookieJar stores Cookie objects in the internal _cookies mapping.
        insecure_cookies = []
        jar = self.session.cookies
        if hasattr(jar, "_cookies"):
            for domain, path_dict in jar._cookies.items():
                for path, cookies in path_dict.items():
                    for name, cookie in cookies.items():
                        # cookie is a http.cookiejar.Cookie object
                        if not getattr(cookie, "secure", False):
                            insecure_cookies.append(f"Cookie '{name}' missing 'Secure' flag.")

                        # HttpOnly may be present in cookie.rest or cookie._rest; check both
                        rest = getattr(cookie, "rest", None) or getattr(cookie, "_rest", {})
                        has_httponly = False
                        if isinstance(rest, dict):
                            # keys might be 'HttpOnly' or 'httponly'
                            if any(k.lower() == "httponly" for k in rest.keys()):
                                has_httponly = True
                            if rest.get("httponly") or rest.get("HttpOnly"):
                                has_httponly = True

                        # Some cookie objects expose an attribute directly
                        if not has_httponly and getattr(cookie, "httponly", False):
                            has_httponly = True

                        if not has_httponly:
                            insecure_cookies.append(f"Cookie '{name}' missing 'HttpOnly' flag.")
        else:
            # Fallback: items() yields name->value pairs and we can't inspect flags
            for name, _value in jar.items():
                insecure_cookies.append(f"Cookie '{name}' present but cookie flags could not be inspected.")

        if insecure_cookies:
            issues.extend(insecure_cookies)

        self.results["vulnerabilities"]["A02_Cryptographic_Failures"] = issues

    def check_vulnerable_components(self):
        headers = self.initial_response.headers
        components = {}
        if "Server" in headers:
            components["Server"] = headers["Server"]
        if "X-Powered-By" in headers:
            components["X-Powered-By"] = headers["X-Powered-By"]
        
        self.results["vulnerabilities"]["A06_Vulnerable_Components"] = components

    def check_broken_access_control(self):
        # This is a very basic check. Real-world tests are more complex.
        if "/admin" in self.results["recon"]["admin_pages_found"]:
            self.results["vulnerabilities"]["A01_Broken_Access_Control"] = "Found '/admin' page. Manual review required to check if it's properly secured."
        else:
            self.results["vulnerabilities"]["A01_Broken_Access_Control"] = "No simple '/admin' path found. (This does not mean BAC is secure)."

    def check_injection_forms(self):
        # Basic check for SQLi on login forms
        soup = BeautifulSoup(self.initial_response.text, "html.parser")
        forms = soup.find_all("form")
        injection_detected = []
        
        for form in forms:
            action = form.get("action", self.base_url)
            action_url = urljoin(self.base_url, action)
            method = form.get("method", "get").lower()
            
            inputs = form.find_all("input")
            data = {}
            for i in inputs:
                name = i.get("name")
                if not name:
                    continue
                if i.get("type") == "password":
                    data[name] = "password"
                else:
                    data[name] = "test"
            
            # Try SQLi payload in first non-password field
            for key, payload in SQLI_PAYLOADS.items():
                for field in data:
                    if data[field] != "password":
                        test_data = data.copy()
                        test_data[field] = payload
                        
                        try:
                            if method == "post":
                                resp = self.session.post(action_url, data=test_data, timeout=1.5)
                            else:
                                resp = self.session.get(action_url, params=test_data, timeout=1.5)
                            
                            if re.search(r"(sql|syntax|database|error|unclosed)", resp.text, re.IGNORECASE):
                                injection_detected.append(f"A03_Injection: Potential {key} SQLi on {action_url} in field '{field}'")
                        except requests.RequestException:
                            continue
                            
        self.results["vulnerabilities"]["A03_Injection"] = injection_detected or ["No simple SQLi detected."]


    def check_xss_reflection(self):
        # Basic check for reflected XSS
        test_url = f"{self.base_url}/?q={XSS_PAYLOAD}"
        
        # --- NEW OAST INJECTION (URL PARAM) ---
        if self.oast_url:
            # Add a second request to check for blind XSS / SSRF via URL param
            try:
                oast_test_url = f"{self.base_url}/?page={self.oast_url}&file={self.oast_url}"
                self.session.get(oast_test_url, timeout=1.5)
                self.results["info"]["oast_param_test"] = f"Sent payload to {oast_test_url}"
            except requests.RequestException:
                pass # We don't care if it fails, we just want to send it
        # --- END NEW ---

        try:
            resp = self.session.get(test_url, timeout=3)
            if XSS_PAYLOAD in resp.text:
                self.results["vulnerabilities"]["A07_XSS"] = [f"Potential Reflected XSS on param 'q'. Payload {XSS_PAYLOAD} was reflected in response."]
            else:
                self.results["vulnerabilities"]["A07_XSS"] = ["No simple reflected XSS detected."]
        except requests.RequestException as e:
            self.results["vulnerabilities"]["A07_XSS"] = [f"Error during XSS check: {e}"]
    
    def simulate_ai_firewall_reaction(self):
        """Simulates how an AI Firewall would perceive this scan."""
        score = 0.0
        actions_taken = []
        
        # 1. Check Port Scanning activity
        if len(self.results["recon"].get("open_ports", [])) > 0:
            score += THREAT_WEIGHTS["port_scan"]
            actions_taken.append("Multiple Port Connection Attempts")

        # 2. Check Directory Brute-forcing
        if len(self.results["recon"].get("admin_pages_found", [])) > 2:
            score += THREAT_WEIGHTS["directory_bruteforce"]
            actions_taken.append("High-frequency Directory Enumeration")

        # 3. Check Injection Payloads
        if self.results["vulnerabilities"].get("A03_Injection"):
            score += THREAT_WEIGHTS["injection_attempt"]
            actions_taken.append("Malicious Payload Injection (SQLi/XSS)")

        # Decision Logic
        is_blocked = score > ANOMALY_THRESHOLD
        
        self.results["defense_sim"] = {
            "threat_score": min(score, 1.0),
            "is_blocked": is_blocked,
            "detected_patterns": actions_taken,
            "firewall_rule": f"iptables -A INPUT -s {self.results['recon'].get('ip_address')} -j DROP" if is_blocked else "None"
        }

    def calculate_wma_threat(self):
        current_score = 0.0
        history = [0.0] # Start at zero
        
        # Simulate the sequence of checks
        # Each 'append' represents a point on the line chart
        check_results = [
            ("DNS Lookup", 0.05),
            ("Port Scan", 0.2 if self.results["recon"].get("open_ports") else 0.0),
            ("Admin Search", 0.4 if self.results["recon"].get("admin_pages_found") else 0.0),
            ("Vulnerability Scan", 0.8 if self.results["vulnerabilities"].get("A03_Injection") else 0.0)
        ]

        for label, weight in check_results:
            # The WMA Formula:
            current_score = (weight * 0.7) + (current_score * 0.3)
            
            # Clamp score to valid range to prevent infinity
            current_score = max(0.0, min(1.0, current_score))
            
            history.append(round(current_score, 2))

        # Sanitize history values to prevent infinity in Streamlit display
        history = [max(0.0, min(1.0, float(val))) for val in history]
        
        # Determine if blocked based on final score
        is_blocked = current_score >= 0.7
        
        # Update or create defense_sim with all fields
        self.results["defense_sim"] = {
            "final_score": round(current_score, 2),
            "status": "BLOCKED" if is_blocked else "CLEAN",
            "ml_prediction": -1 if current_score > THRESHOLD_WARNING else 1,
            "is_blocked": is_blocked,
            "threat_history": history,
            "firewall_rule": f"iptables -A INPUT -s {self.results['recon'].get('ip_address', '0.0.0.0')} -j DROP" if is_blocked else "None"
        }

    # 1. DDoS Attack Detection (Volume-based)
    def detect_ddos_patterns(self):
        pps, unique_ips, syn_rate = self.capture_live_traffic()
        if pps > 10000 and unique_ips > 100:
            self.results["vulnerabilities"]["DDoS_Detection"] = {
                "status": "Critical",
                "pps": pps,
                "unique_ips": unique_ips,
                "attack_type": "SYN Flood",
                "action": "Rate limit + IP reputation block"
            }


    def capture_live_traffic(self, duration=5):
        """
        Capture live packets and extract DDoS metrics
        """
        packet_count = 0
        syn_count = 0
        src_ips = set()
        start_time = time.time()

        def process_packet(pkt):
            nonlocal packet_count, syn_count
            if IP in pkt:
                packet_count += 1
                src_ips.add(pkt[IP].src)

                if TCP in pkt and pkt[TCP].flags == "S":
                    syn_count += 1

        sniff(prn=process_packet, timeout=duration, store=False)
        elapsed = time.time() - start_time

        # Prevent division by zero
        if elapsed <= 0:
            elapsed = 0.001
        
        pps = int(packet_count / elapsed)
        unique_ips = len(src_ips)
        syn_rate = int(syn_count / elapsed)

        return pps, unique_ips, syn_rate


    # 2. Port Scanning Detection (Horizontal/Vertical)
    def detect_port_scanning_activity(self):
        open_ports = self.results["recon"].get("open_ports", [])
        # If more than 10 ports were probed in a short window
        if len(open_ports) > 5:
            self.results["vulnerabilities"]["Port_Scan_Detected"] = {
                "status": "High",
                "reason": f"Sequential connection attempts to {len(open_ports)} different ports.",
                "rule": "Block IP for 3600s"
            }


    def detect_brute_force_attempts(self):
        if getattr(self, "failed_admin_attempts", 0) > 5:
            self.results["vulnerabilities"]["Brute_Force_Attack"] = {
                "status": "High",
                "failed_attempts": self.failed_admin_attempts,
                "reason": "Multiple unauthorized access attempts detected"
            }


    # 4. Malware Communication (C2 Beaconing)
    def detect_malware_beaconing(self):
        # Looks for consistent, small heartbeat packets to a specific IP

        suspicious_domains = self.detect_malware_beaconing
        found = [d for d in suspicious_domains if d in str(self.results["recon"].get("crawled_links"))]
        if found:
            self.results["vulnerabilities"]["Malware_C2_Communication"] = {
                "status": "Critical",
                "target": found,
                "reason": "Outbound traffic to known Command & Control (C2) infrastructure."
            }
    
    def detect_malware_beaconing(self, duration=10):
        timestamps = defaultdict(list)

        def process_packet(pkt):
            if IP in pkt:
                dst = pkt[IP].dst
                timestamps[dst].append(time.time())

        sniff(prn=process_packet, timeout=duration, store=False)

        for dst, times in timestamps.items():
            if len(times) >= 5:
                intervals = [times[i+1] - times[i] for i in range(len(times)-1)]
                if intervals:  # Only calculate average if intervals exist
                    avg_interval = sum(intervals) / len(intervals)
                    
                    # Prevent infinity values from display
                    if avg_interval == float('inf') or avg_interval == float('-inf'):
                        avg_interval = 0.0

                    if 1 <= avg_interval <= 5:  # beacon-like pattern
                        self.results["vulnerabilities"]["Malware_C2_Communication"] = {
                            "status": "Critical",
                            "destination_ip": dst,
                            "avg_interval_sec": round(avg_interval, 2),
                            "reason": "Periodic beaconing traffic detected"
                        }


    # 5. Data Exfiltration (Outbound Payload Size)
    def detect_data_exfiltration(self):
        # Detects large POST requests or unusual DNS tunneling
        simulated_outbound_size = self._analyze_exfiltration_traffic()  # MB
        if simulated_outbound_size > 100:
            self.results["vulnerabilities"]["Data_Exfiltration"] = {
                "status": "Critical",
                "reason": f"Unusual outbound data transfer ({simulated_outbound_size}MB) detected.",
                "method": "DNS Tunneling / Large POST"
            }

    def _analyze_exfiltration_traffic(self, duration=5):
        outbound_bytes = 0
        start_time = time.time()

        def process_packet(pkt):
            nonlocal outbound_bytes
            if IP in pkt:
                # outbound traffic (from local machine)
                if pkt[IP].src == socket.gethostbyname(socket.gethostname()):
                    outbound_bytes += len(pkt)

        sniff(prn=process_packet, timeout=duration, store=False)
        elapsed = time.time() - start_time
        
        # Prevent division by zero
        if elapsed <= 0:
            elapsed = 0.001
            
        outbound_mb = outbound_bytes / (1024 * 1024)

        if outbound_mb > 50:  # realistic threshold
            self.results["vulnerabilities"]["Data_Exfiltration"] = {
                "status": "Critical",
                "outbound_MB": round(outbound_mb, 2),
                "reason": "Unusual outbound traffic volume detected",
                "method": "Packet volume analysis"
            }
        
        return outbound_mb

        
    def log_event(self, category, message):
        timestamp = time.strftime("%H:%M:%S")
        self.logs.append(f"[{timestamp}] [{category}] {message}")
