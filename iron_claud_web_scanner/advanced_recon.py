import requests
import dns.resolver
import dns.zone
import dns.query
import socket
from urllib.parse import urljoin
from config import CLOUD_BUCKET_PATTERNS, API_ENDPOINTS, CMS_SENSITIVE_FILES, BYPASS_HEADERS

class InfrastructureAuditor:
    def __init__(self, session, domain):
        self.session = session
        self.domain = domain
        self.domain_keyword = domain.split('.')[0] 

    # --- Feature 1: Cloud Bucket Enumeration ---
    def check_cloud_buckets(self):
        found_buckets = []
        for provider, pattern in CLOUD_BUCKET_PATTERNS.items():
            names_to_test = [self.domain_keyword, self.domain, f"{self.domain_keyword}-backup"]
            for name in names_to_test:
                bucket_url = pattern % name
                try:
                    resp = requests.get(bucket_url, timeout=2)
                    if resp.status_code == 200:
                        if "ListBucketResult" in resp.text or "<Contents>" in resp.text:
                            found_buckets.append(f"OPEN {provider} Bucket found: {bucket_url}")
                        else:
                            found_buckets.append(f"Exists (but protected) {provider}: {bucket_url}")
                    elif resp.status_code == 403:
                         found_buckets.append(f"Protected {provider} Bucket exists: {bucket_url}")
                except: pass
        return found_buckets

    # --- Feature 2: API Discovery ---
    def discover_apis(self, base_url):
        found_apis = []
        for endpoint in API_ENDPOINTS:
            url = f"{base_url.rstrip('/')}{endpoint}"
            try:
                resp = self.session.get(url, timeout=1.5)
                if resp.status_code in [200, 401]: 
                    content_type = resp.headers.get("Content-Type", "")
                    if "json" in content_type or "xml" in content_type:
                        found_apis.append(f"Found API Endpoint: {endpoint} (Status: {resp.status_code})")
            except: pass
        return found_apis

    # --- Feature 3: Email Spoofing Check (DNS) ---
    def check_email_security(self):
        issues = []
        try:
            answers = dns.resolver.resolve(self.domain, 'TXT')
            spf_found = False
            for rdata in answers:
                if "v=spf1" in str(rdata):
                    spf_found = True
                    if "-all" not in str(rdata) and "~all" not in str(rdata):
                        issues.append("SPF Record exists but is too permissive (missing -all or ~all)")
                    break
            if not spf_found:
                issues.append("Missing SPF Record (Vulnerable to email spoofing)")
        except:
            issues.append("Could not retrieve TXT records for SPF check")

        try:
            dmarc_domain = f"_dmarc.{self.domain}"
            answers = dns.resolver.resolve(dmarc_domain, 'TXT')
            dmarc_found = False
            for rdata in answers:
                if "v=DMARC1" in str(rdata):
                    dmarc_found = True
                    if "p=none" in str(rdata):
                        issues.append("DMARC Policy is set to 'none' (Monitoring only, no protection)")
                    break
            if not dmarc_found:
                issues.append("Missing DMARC Record")
        except:
            issues.append("Missing DMARC Record")

        return issues

    # --- Feature 4: CMS Specific Audit ---
    def check_cms_files(self, base_url, tech_stack):
        issues = []
        for cms, files in CMS_SENSITIVE_FILES.items():
            if cms in tech_stack:
                for file_path in files:
                    try:
                        url = f"{base_url.rstrip('/')}{file_path}"
                        resp = self.session.head(url, timeout=1.5)
                        if resp.status_code == 200:
                            issues.append(f"Exposed {cms} File: {file_path}")
                    except: pass
        return issues

    # --- NEW Feature 5: DNS Zone Transfer (AXFR) ---
    def check_zone_transfer(self):
        """
        Attempts a Zone Transfer (AXFR) against the domain's nameservers.
        """
        results = []
        try:
            ns_answers = dns.resolver.resolve(self.domain, 'NS')
            for ns in ns_answers:
                ns_target = str(ns.target)
                try:
                    ns_ip = socket.gethostbyname(ns_target)
                    # Attempt AXFR
                    zone = dns.zone.from_xfr(dns.query.xfr(ns_ip, self.domain, timeout=2))
                    if zone:
                        results.append(f"SUCCESS: Zone Transfer allowed on {ns_target} ({ns_ip})")
                        # We could list all nodes here, but just flagging it is enough for high-level scan
                except:
                    continue # Transfer failed or timed out (Normal)
        except:
            pass
        return results

    # --- NEW Feature 6: WAF/403 Bypass Fuzzing ---
    def attempt_bypass(self, base_url):
        """
        Tries to access the base URL using headers that spoof local origin
        to bypass 403 Forbidden errors.
        """
        successes = []
        # First, check if the baseline is actually 403/401
        try:
            initial = self.session.get(base_url, timeout=2)
            if initial.status_code not in [401, 403]:
                return [] # No restriction to bypass
        except: return []

        # If restricted, try headers
        for header, val in BYPASS_HEADERS.items():
            try:
                # Create a temporary session or headers dict
                headers = {header: val}
                resp = requests.get(base_url, headers=headers, timeout=2, verify=False)
                if resp.status_code == 200:
                    successes.append(f"Bypass Possible? Header '{header}: {val}' returned 200 OK")
            except: pass
        return successes

    # --- NEW Feature 7: Reverse DNS (PTR) ---
    def reverse_dns_lookup(self):
        """
        Resolves the IP to a hostname to identify cloud provider or shared hosting.
        """
        try:
            ip = socket.gethostbyname(self.domain)
            hostname, _, _ = socket.gethostbyaddr(ip)
            return f"{ip} resolves to {hostname}"
        except:
            return "Reverse DNS lookup failed or no record found."

    # --- NEW Feature 8: Active Robots.txt Scan ---
    def active_robots_scan(self, base_url, robots_content):
        """
        Takes the disallowed paths found in robots.txt and actively visits them.
        """
        accessible_hidden_paths = []
        if isinstance(robots_content, list):
            # If robots_content is a list of strings "Disallow: /path"
            paths = [p.replace("Disallow: ", "").strip() for p in robots_content if "Disallow" in p]
        elif isinstance(robots_content, str):
             # Simple regex extract if it came as a raw string block
             import re
             paths = re.findall(r"Disallow: (.*)", robots_content)
        else:
            paths = []

        for path in paths:
            # Clean path
            path = path.strip()
            if not path or path == "/": continue
            
            full_url = urljoin(base_url, path)
            try:
                resp = self.session.get(full_url, timeout=1.5)
                if resp.status_code == 200:
                    accessible_hidden_paths.append(f"{path} (Status: 200 OK)")
                elif resp.status_code == 403:
                    accessible_hidden_paths.append(f"{path} (Status: 403 Forbidden - Exists)")
            except: pass
            
        return accessible_hidden_paths