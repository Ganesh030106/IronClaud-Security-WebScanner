import requests
import re
from urllib.parse import urljoin
from config import GRAPHQL_INTROSPECTION_PAYLOAD, HOST_HEADER_PAYLOADS, PROTO_POLLUTION_REGEX

class SpecializedAuditor:
    def __init__(self, session):
        self.session = session

    # --- Feature 1: GraphQL Introspection ---
    def check_graphql(self, api_endpoints, base_url):
        """
        Checks identified API endpoints to see if they are vulnerable GraphQL instances.
        """
        vulnerabilities = []
        graphql_candidates = [api for api in api_endpoints if "graphql" in api.lower()]
        
        if not graphql_candidates:
             graphql_candidates = ["/graphql"]

        for endpoint in graphql_candidates:
            if "Found API" in endpoint:
                continue

            target_url = urljoin(base_url, "/graphql")
            try:
                resp = self.session.post(target_url, json=GRAPHQL_INTROSPECTION_PAYLOAD, timeout=2)
                if resp.status_code == 200 and "__schema" in resp.text:
                    vulnerabilities.append(f"GraphQL Introspection Enabled at: {target_url} (Schema Leak)")
            except: pass
            
        return vulnerabilities

    # --- Feature 2: Host Header Injection ---
    def check_host_header_injection(self, base_url):
        """
        Checks if the server blindly trusts the Host header for redirects or links.
        """
        issues = []
        try:
            for payload in HOST_HEADER_PAYLOADS:
                headers = {"Host": payload}
                resp = self.session.get(base_url, headers=headers, timeout=2, allow_redirects=False)
                
                # Check 1: Reflected in Location header (Redirect Poisoning)
                if resp.status_code in [301, 302] and payload in resp.headers.get("Location", ""):
                    issues.append(f"Host Header Injection (Redirect): Server redirects to {payload}")
                
                # Check 2: Reflected in Body (e.g. Password Reset Poisoning)
                if payload in resp.text:
                    if f'href="http://{payload}' in resp.text or f'href="https://{payload}' in resp.text:
                         issues.append(f"Host Header Injection (Content): Server generates links using fake Host '{payload}'")
        except: pass
        return issues

    # --- Feature 3: Prototype Pollution (Static) ---
    def check_prototype_pollution(self, js_files):
        """
        Scans fetched JS files for patterns indicating client-side prototype pollution.
        """
        issues = []
        for js_url in list(js_files)[:5]:
            try:
                resp = self.session.get(js_url, timeout=2)
                if re.search(PROTO_POLLUTION_REGEX, resp.text):
                     issues.append(f"Potential Prototype Pollution code found in: {js_url}")
            except: pass
        return issues
