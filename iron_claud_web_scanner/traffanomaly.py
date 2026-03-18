import requests
import time
import concurrent.futures
from config import BAD_USER_AGENTS

class AnomalyTester:
    def __init__(self, session):
        self.session = session

    # --- Feature 1: Rate Limit / Flood Test ---
    def check_rate_limiting(self, base_url):
        """
        Sends a burst of 30 requests in rapid succession.
        Checks if the server returns 429 (Too Many Requests) or blocks the IP.
        """
        results = {"status": "Unknown", "details": []}
        req_count = 30
        blocked_count = 0
        success_count = 0
        
        def send_req(i):
            try:
                # Use a lightweight HEAD request
                resp = requests.head(base_url, timeout=2)
                return resp.status_code
            except:
                return 0

        start_time = time.time()
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            # Fire 30 requests immediately
            futures = [executor.submit(send_req, i) for i in range(req_count)]
            for future in concurrent.futures.as_completed(futures):
                code = future.result()
                if code == 429 or code == 403: # 429 = Rate Limit, 403 = WAF Block
                    blocked_count += 1
                elif code == 200:
                    success_count += 1
        
        duration = time.time() - start_time
        
        if blocked_count > 0:
            results["status"] = "Protected"
            results["details"] = f"Server blocked {blocked_count}/{req_count} requests during flood ({round(duration, 2)}s)."
        else:
            results["status"] = "Vulnerable"
            results["details"] = f"Server accepted all {req_count} requests in {round(duration, 2)}s. No Rate Limiting detected."
            
        return results

    # --- Feature 2: Bad Bot Signature Test ---
    def check_bot_blocking(self, base_url):
        """
        Checks if the server blocks known bad User-Agents.
        """
        allowed_bots = []
        for agent in BAD_USER_AGENTS:
            try:
                headers = {"User-Agent": agent}
                resp = requests.get(base_url, headers=headers, timeout=2)
                if resp.status_code == 200:
                    allowed_bots.append(agent)
            except: pass
            
        if allowed_bots:
            return {
                "status": "Vulnerable", 
                "details": f"Server allowed known scanning tools: {', '.join(allowed_bots)}"
            }
        else:
            return {
                "status": "Protected", 
                "details": "Server correctly blocked or dropped known bad User-Agents."
            }