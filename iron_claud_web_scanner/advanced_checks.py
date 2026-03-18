import requests
import dns.resolver  # Requires: pip install dnspython
import jwt           # Requires: pip install pyjwt
import re
from urllib.parse import urlparse
from config import TAKEOVER_SIGNATURES

class AdvancedAuditor:
    def __init__(self, session):
        self.session = session

    # --- Feature 1: Subdomain Takeover ---
    def check_subdomain_takeover(self, subdomains):
        """
        Checks CNAME records of subdomains against known vulnerable provider signatures.
        """
        vulnerable_hosts = []
        for sub in subdomains:
            try:
                # 1. DNS Check: Get CNAME
                answers = dns.resolver.resolve(sub, 'CNAME')
                for rdata in answers:
                    cname = str(rdata.target)
                    
                    # 2. HTTP Check: If CNAME looks interesting, check content
                    try:
                        resp = self.session.get(f"http://{sub}", timeout=2)
                        for provider, error_msg in TAKEOVER_SIGNATURES.items():
                            if error_msg in resp.text:
                                vulnerable_hosts.append({
                                    "subdomain": sub,
                                    "provider": provider,
                                    "cname": cname,
                                    "status": "VULNERABLE (Fingerprint match)"
                                })
                    except: pass
            except: pass # DNS lookup failed or no CNAME
        return vulnerable_hosts

    # --- Feature 2: JWT Analysis ---
    def analyze_jwts(self, cookies, headers):
        """
        Finds, decodes, and audits JWTs for common flaws (Alg: None).
        """
        found_jwts = []
        
        # Helper to process a token string
        def process_token(token, source):
            try:
                # Basic Regex to identify a JWT format (header.payload.signature)
                if re.match(r'^[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]*$', token):
                    # Decode without verification just to inspect
                    header = jwt.get_unverified_header(token)
                    payload = jwt.decode(token, options={"verify_signature": False})
                    
                    issues = []
                    if header.get('alg', '').lower() == 'none':
                        issues.append("CRITICAL: 'alg': 'none' allowed (Signature Bypass)")
                    
                    found_jwts.append({
                        "source": source,
                        "header": header,
                        "payload": payload,
                        "issues": issues
                    })
            except: pass

        # Check Cookies
        for cookie in cookies:
            process_token(cookie.get('Value', ''), f"Cookie: {cookie.get('Name')}")
            
        # Check Auth Header
        auth_header = headers.get('Authorization', '')
        if 'Bearer' in auth_header:
            process_token(auth_header.split(' ')[1], "Header: Authorization")

        return found_jwts

    # --- Feature 3: Git Repository Verification ---
    def verify_git_exposure(self, base_url):
        """
        Verifies if a .git folder is actually exploitable by reading internal structure.
        """
        git_head_url = f"{base_url}/.git/HEAD"
        git_config_url = f"{base_url}/.git/config"
        
        try:
            # Check HEAD file
            resp = self.session.get(git_head_url, timeout=2)
            if resp.status_code == 200 and "refs/heads" in resp.text:
                return {
                    "status": "CONFIRMED",
                    "details": "Found valid .git/HEAD pointing to refs.",
                    "url": git_head_url
                }
            
            # Fallback: Check config file
            resp = self.session.get(git_config_url, timeout=2)
            if resp.status_code == 200 and "[core]" in resp.text:
                return {
                    "status": "CONFIRMED",
                    "details": "Found valid .git/config file.",
                    "url": git_config_url
                }
        except: pass
        return None

    # --- Feature 4: Broken Link Hijacking (BLH) ---
    def check_broken_links(self, base_url, crawled_links):
        """
        Checks external links to see if the domain is expired (NXDOMAIN).
        """
        hijackable = []
        target_domain = urlparse(base_url).netloc
        
        # Extract unique external domains from crawled links
        external_links = set()
        for link in crawled_links:
            parsed = urlparse(link)
            if parsed.netloc and parsed.netloc != target_domain:
                external_links.add(f"{parsed.scheme}://{parsed.netloc}")
        
        for ext_link in list(external_links)[:10]: # Limit to 10 to be polite/fast
            try:
                domain = urlparse(ext_link).netloc
                # Try to resolve IP
                try:
                    dns.resolver.resolve(domain, 'A')
                except dns.resolver.NXDOMAIN:
                    # Domain doesn't exist!
                    hijackable.append(ext_link)
            except: pass
            
        return hijackable