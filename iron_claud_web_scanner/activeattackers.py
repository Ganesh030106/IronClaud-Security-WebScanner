import requests
import time
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse
from config import SSTI_PAYLOADS, CRLF_PAYLOADS, TIME_BASED_SQLI

class ActiveAttacker:
    def __init__(self, session):
        self.session = session

    # --- Feature 1: SSTI Scanner ---
    def check_ssti(self, base_url):
        """
        Fuzzes URL parameters with template math (e.g., {{7*7}}).
        If the response contains '49', SSTI is likely present.
        """
        issues = []
        parsed = urlparse(base_url)
        params = dict(parse_qsl(parsed.query))
        
        # If no params, nothing to test (SSTI usually needs input)
        if not params:
            return []

        for key in params.keys():
            for engine, (payload, expected_result) in SSTI_PAYLOADS.items():
                fuzzed = params.copy()
                fuzzed[key] = payload
                
                # Rebuild URL
                query = urlencode(fuzzed)
                target = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, query, parsed.fragment))
                
                try:
                    resp = self.session.get(target, timeout=2)
                    if expected_result in resp.text:
                        issues.append(f"SSTI ({engine}) confirmed in param '{key}': '{payload}' rendered as '{expected_result}'")
                        break # Stop checking other engines for this param if one works
                except: pass
        return issues

    # --- Feature 2: CRLF Injection ---
    def check_crlf(self, base_url):
        """
        Attempts to inject a Set-Cookie header via the URL path.
        """
        issues = []
        base_clean = base_url.rstrip('/')
        
        for payload in CRLF_PAYLOADS:
            target = f"{base_clean}{payload}"
            try:
                resp = self.session.get(target, timeout=2)
                # Check if the injected cookie header exists in the response
                # Note: Requests library handles headers case-insensitively usually, 
                # but we check the raw Set-Cookie values.
                cookies = resp.headers.get('Set-Cookie', '')
                if 'crlf=injection' in cookies:
                    issues.append(f"CRLF Injection successful: Server accepted fake Set-Cookie header.")
                    break
            except: pass
        return issues

    # --- Feature 3: Time-Based Blind SQLi ---
    def check_time_based_sqli(self, base_url):
        """
        Injects SLEEP commands and measures response time.
        """
        issues = []
        parsed = urlparse(base_url)
        params = dict(parse_qsl(parsed.query))
        
        if not params: 
            return []

        for key in params.keys():
            for db_type, payload in TIME_BASED_SQLI.items():
                fuzzed = params.copy()
                fuzzed[key] = payload
                
                query = urlencode(fuzzed)
                target = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, query, parsed.fragment))
                
                try:
                    start_time = time.time()
                    self.session.get(target, timeout=5)
                    end_time = time.time()
                    
                    duration = end_time - start_time
                    
                    # If duration is > 3 seconds (our sleep time), it's suspicious
                    # We use > 2.8 to account for slight network variances, but typically it should be sharp.
                    if duration > 2.8:
                        issues.append(f"Time-Based SQLi ({db_type}) in param '{key}': Response delayed by {round(duration, 2)}s")
                        break
                except requests.exceptions.ReadTimeout:
                     # If it timed out, it might also be a success (if sleep was longer than timeout)
                     issues.append(f"Time-Based SQLi ({db_type}) in param '{key}': Request timed out (Potential Sleep).")
                except: pass
        return issues