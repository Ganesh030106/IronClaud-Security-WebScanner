import requests
import time
import concurrent.futures
from config import BAD_USER_AGENTS

class AnomalyTester:
    def __init__(self, session):
        self.session = session

    # --- Feature 1: Rate Limit / Flood Test ---
    def check_rate_limiting(self, base_url, req_count=12):
        """
        Sends a burst of rapid requests to test rate limiting.
        Checks if the server returns 429 (Too Many Requests) or blocks the IP.
        """
        results = {"status": "Unknown", "details": []}
        blocked_count = 0
        success_count = 0
        
        def send_req(i):
            try:
                resp = requests.head(base_url, timeout=1.0)
                return resp.status_code
            except:
                return 0

        start_time = time.time()
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(send_req, i) for i in range(req_count)]
            for future in concurrent.futures.as_completed(futures):
                code = future.result()
                if code == 429 or code == 403:
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
        Checks if the server blocks known bad User-Agents concurrently.
        """
        allowed_bots = []
        def test_bot(agent):
            try:
                headers = {"User-Agent": agent}
                resp = requests.get(base_url, headers=headers, timeout=1.0)
                if resp.status_code == 200:
                    return agent
            except:
                pass
            return None

        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            results = list(executor.map(test_bot, BAD_USER_AGENTS[:5]))
            allowed_bots = [r for r in results if r]
            
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
