import requests
import re
import time
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse, urljoin
from bs4 import BeautifulSoup
from config import (
    SSRF_PAYLOADS, NOSQL_PAYLOADS, PATH_TRAVERSAL_PAYLOADS, 
    XXE_PAYLOADS, CACHE_POISONING_HEADERS, SERIALIZATION_SIGNATURES
)

class FuzzingEngine:
    """
    Advanced Next-Gen Fuzzing & Vulnerability Engine:
    - Server-Side Request Forgery (SSRF)
    - Path Traversal / Local File Inclusion (LFI)
    - NoSQL Operator Injection
    - XML External Entity (XXE) Injection
    - Web Cache Poisoning & Deception
    - Insecure Deserialization Detection
    """
    def __init__(self, session, base_url):
        self.session = session
        self.base_url = base_url.rstrip('/')
        self.domain = urlparse(self.base_url).hostname

    # --- 1. SSRF (Server-Side Request Forgery) Scanner ---
    def check_ssrf(self, crawled_links=None):
        """
        Tests URL parameters against internal cloud metadata and loopback targets.
        """
        findings = []
        ssrf_param_names = [
            'url', 'dest', 'redirect', 'uri', 'path', 'feed', 'host', 
            'domain', 'callback', 'webhook', 'src', 'source', 'load', 'api', 
            'endpoint', 'target', 'page', 'proxy', 'fetch'
        ]

        targets_to_test = [self.base_url]
        if crawled_links:
            targets_to_test.extend(crawled_links[:10])

        tested_params = set()

        for link in targets_to_test:
            parsed = urlparse(link)
            params = dict(parse_qsl(parsed.query))

            # Test existing query parameters
            candidate_keys = [k for k in params.keys() if k.lower() in ssrf_param_names]
            if not candidate_keys and link == self.base_url:
                # Fuzz top SSRF candidate params on base URL if none found
                candidate_keys = ['url', 'redirect', 'dest', 'target']
                for k in candidate_keys:
                    params[k] = "test"

            for param in candidate_keys:
                param_id = f"{parsed.path}?{param}"
                if param_id in tested_params:
                    continue
                tested_params.add(param_id)

                for name, payload in SSRF_PAYLOADS.items():
                    fuzzed = params.copy()
                    fuzzed[param] = payload
                    query = urlencode(fuzzed)
                    test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, query, parsed.fragment))

                    try:
                        resp = self.session.get(test_url, timeout=2.5, allow_redirects=False)
                        resp_text = resp.text.lower()
                        # Cloud metadata signatures
                        if any(sig in resp_text for sig in ["ami-id", "instance-id", "computemetadata", "security-credentials", "local-ipv4"]):
                            findings.append({
                                "severity": "CRITICAL",
                                "target": test_url,
                                "param": param,
                                "type": f"Confirmed SSRF ({name})",
                                "evidence": f"Reflected cloud instance metadata signature in response"
                            })
                            break
                        # Loopback service reflection
                        elif ("nginx" in resp_text or "apache" in resp_text or "fastapi" in resp_text) and resp.status_code == 200 and len(resp_text) > 50:
                            if name in ["Localhost Loopback IPv4", "IPv6 Loopback"]:
                                findings.append({
                                    "severity": "HIGH",
                                    "target": test_url,
                                    "param": param,
                                    "type": f"Potential SSRF ({name})",
                                    "evidence": f"Response returned local service content on loopback target"
                                })
                                break
                    except Exception:
                        continue

        return findings if findings else ["No SSRF vectors detected via standard parameters."]

    # --- 2. Path Traversal / LFI Scanner ---
    def check_path_traversal(self, crawled_links=None):
        """
        Fuzzes URL parameters with encoded and raw directory traversal payloads.
        """
        findings = []
        traversal_param_names = [
            'file', 'page', 'doc', 'folder', 'path', 'template', 
            'include', 'view', 'read', 'cat', 'dir', 'action', 'item', 'layout'
        ]

        targets_to_test = [self.base_url]
        if crawled_links:
            targets_to_test.extend(crawled_links[:10])

        tested_params = set()

        for link in targets_to_test:
            parsed = urlparse(link)
            params = dict(parse_qsl(parsed.query))

            candidate_keys = [k for k in params.keys() if k.lower() in traversal_param_names]
            if not candidate_keys and link == self.base_url:
                candidate_keys = ['file', 'page', 'include']
                for k in candidate_keys:
                    params[k] = "default"

            for param in candidate_keys:
                param_id = f"{parsed.path}?{param}"
                if param_id in tested_params:
                    continue
                tested_params.add(param_id)

                for payload in PATH_TRAVERSAL_PAYLOADS:
                    fuzzed = params.copy()
                    fuzzed[param] = payload
                    query = urlencode(fuzzed)
                    test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, query, parsed.fragment))

                    try:
                        resp = self.session.get(test_url, timeout=2.0)
                        content = resp.text

                        # Linux /etc/passwd signature
                        if re.search(r"root:x:0:0:", content) or re.search(r"/bin/(bash|sh)", content):
                            findings.append(f"Confirmed LFI/Path Traversal on '{param}' with payload '{payload}' (Disclosed /etc/passwd)")
                            break
                        # Windows win.ini signature
                        elif "[extensions]" in content.lower() or "[mci extensions]" in content.lower() or "[fonts]" in content.lower():
                            findings.append(f"Confirmed Windows Path Traversal on '{param}' with payload '{payload}' (Disclosed win.ini)")
                            break
                    except Exception:
                        continue

        return findings if findings else ["No simple Path Traversal / LFI vectors detected."]

    # --- 3. NoSQL Injection Scanner ---
    def check_nosql_injection(self, base_url):
        """
        Fuzzes endpoints with NoSQL operator injection payloads (MongoDB/CouchDB).
        """
        findings = []
        test_url = f"{base_url}/"
        nosql_test_params = ['username', 'user', 'id', 'search', 'query', 'filter']

        nosql_error_patterns = [
            r"MongoError", r"MongoDB\.Driver", r"BSONError", 
            r"Cast to ObjectId failed", r"SyntaxError: Unexpected token",
            r"TopologyDescription", r"CouchDB"
        ]

        for param in nosql_test_params:
            for payload in NOSQL_PAYLOADS:
                try:
                    if isinstance(payload, dict):
                        # Test JSON body
                        target = f"{test_url}"
                        resp = self.session.post(target, json={param: payload}, timeout=1.5)
                    else:
                        target = f"{test_url}?{param}={payload}"
                        resp = self.session.get(target, timeout=1.5)

                    for pattern in nosql_error_patterns:
                        if re.search(pattern, resp.text, re.IGNORECASE):
                            findings.append(f"Potential NoSQL Injection on param '{param}': Triggered database error pattern '{pattern}'")
                            break
                    if findings:
                        break
                except Exception:
                    continue
            if findings:
                break

        return findings if findings else ["No NoSQL operator injection anomalies detected."]

    # --- 4. XXE (XML External Entity) Injection ---
    def check_xxe(self, api_endpoints=None):
        """
        Tests XML-accepting and API endpoints with external entity references.
        """
        findings = []
        candidate_urls = [self.base_url]
        if api_endpoints:
            for ep in api_endpoints:
                if any(x in ep.lower() for x in ['api', 'xml', 'soap', 'service', 'graphql']):
                    candidate_urls.append(urljoin(self.base_url, ep.split()[0]))

        headers = {'Content-Type': 'application/xml', 'Accept': 'application/xml, text/xml, */*'}

        for target in candidate_urls[:4]:
            for payload in XXE_PAYLOADS:
                try:
                    resp = self.session.post(target, data=payload, headers=headers, timeout=2.0)
                    if "root:x:0:0:" in resp.text or "[extensions]" in resp.text.lower():
                        findings.append(f"Confirmed XXE Injection on {target}: Disclosed file content.")
                        break
                    elif any(err in resp.text for err in ["XMLSyntaxError", "SAXParseException", "DOMDocument::loadXML"]):
                        findings.append(f"Potential XXE Parser Disclosure on {target}: Server exposed verbose XML parser errors.")
                        break
                except Exception:
                    continue

        return findings if findings else ["No XML External Entity (XXE) vulnerabilities detected."]

    # --- 5. Web Cache Poisoning & Deception ---
    def check_cache_poisoning(self):
        """
        Inspects unkeyed host header reflections and potential cache deception.
        """
        findings = []
        try:
            # Test unkeyed headers
            resp = self.session.get(self.base_url, headers=CACHE_POISONING_HEADERS, timeout=2.0)
            
            # Check reflection
            if "attacker-cache-poison.evil.com" in resp.text:
                cache_headers = [h for h in resp.headers.keys() if 'cache' in h.lower() or h.lower() in ['age', 'via', 'x-varnish']]
                if cache_headers:
                    findings.append(f"Cache Poisoning Vulnerability: Unkeyed host reflected in cached response (Headers: {', '.join(cache_headers)})")
                else:
                    findings.append("Unkeyed Host Header Reflected: Host header reflected in response (Verify caching reverse proxy configurations)")

            # Path delimiter cache deception test
            deception_url = f"{self.base_url}/test_deception_nonexistent.css"
            dec_resp = self.session.get(deception_url, timeout=2.0)
            if dec_resp.status_code == 200 and 'text/html' in dec_resp.headers.get('Content-Type', ''):
                if any(h in dec_resp.headers for h in ['X-Cache', 'CF-Cache-Status']):
                    findings.append(f"Web Cache Deception Potential: HTML page served and cached under static extension (.css)")
        except Exception:
            pass

        return findings if findings else ["No Web Cache Poisoning / Deception vulnerabilities detected."]

    # --- 6. Insecure Deserialization Auditor ---
    def check_insecure_deserialization(self, cookies=None, response_text=""):
        """
        Audits session cookies and response tokens for serialized object patterns.
        """
        findings = []

        # Audit cookies
        if cookies:
            for cookie in cookies:
                c_val = cookie.get('Value', '')
                for proto_name, sigs in SERIALIZATION_SIGNATURES.items():
                    for sig in sigs:
                        if isinstance(sig, bytes):
                            try:
                                if sig in c_val.encode('utf-8', errors='ignore'):
                                    findings.append(f"Insecure Deserialization Risk: Cookie '{cookie.get('Name')}' contains {proto_name} pattern")
                            except Exception:
                                pass
                        elif isinstance(sig, str):
                            if re.search(sig, c_val):
                                findings.append(f"Insecure Deserialization Risk: Cookie '{cookie.get('Name')}' contains {proto_name} pattern")

        # Audit response body tokens
        if response_text:
            for proto_name, sigs in SERIALIZATION_SIGNATURES.items():
                for sig in sigs:
                    if isinstance(sig, str) and re.search(sig, response_text):
                        findings.append(f"Serialized Object Found in Response: {proto_name} signature detected in page source")
                        break

        return findings if findings else ["No insecure serialized object signatures detected."]
