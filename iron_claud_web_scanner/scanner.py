import streamlit as st
import requests
import socket
import whois
from urllib.parse import urlparse, urljoin, parse_qsl, urlencode, urlunparse
from bs4 import BeautifulSoup
import re
import concurrent.futures
import ssl
from datetime import datetime
import xml.etree.ElementTree as ET
from advanced_checks import AdvancedAuditor

# --- ARCHITECTURAL UPGRADES ---
import nest_asyncio
import asyncio
import httpx
from wafw00f.main import WAFW00F

# --- IMPORT MODULES ---
from advanced_checks import AdvancedAuditor
from advanced_recon import InfrastructureAuditor
from content_discovery import ContentAuditor  
from specialized_checks import SpecializedAuditor 
from activeattackers import ActiveAttacker 
from traffanomaly import AnomalyTester # NEW
from defensegenerator import DefenseGenerator # NEW



# Intelligence Modules (Arch Sections 5 & 6)
try:
    from Wappalyzer import Wappalyzer, WebPage
    import nvdlib
except ImportError:
    pass # Handle if packages aren't installed yet

# Apply the patch to allow nested event loops in Streamlit (Architecture Section 2.4)
nest_asyncio.apply()


# Import configurations
from config import (ADMIN_PATHS, SQLI_PAYLOADS, XSS_PAYLOAD, SECURITY_HEADERS, SENSITIVE_PATHS, SECRET_REGEX, OPEN_REDIRECT_PAYLOADS, 
                    WAF_SIGNATURES, EMAIL_REGEX, TECH_SIGNATURES, DIRECTORY_LISTING_SIGNATURES, COMMAND_INJECTION_PAYLOADS)


MAX_SCAN_THREADS = 15

class OWASPTester:
    def __init__(self, base_url, oast_url=None):
        self.base_url = base_url.rstrip('/')
        self.domain = urlparse(self.base_url).hostname
        self.oast_url = oast_url
        
        # 1. CREATE SESSION FIRST
        self.session = requests.Session()
        
        # 2. THEN configure headers
        user_agent = "EducationalSecurityScanner/1.3 (Advanced)"
        if self.oast_url:
            user_agent = f"{user_agent} (OAST-Check: {self.oast_url})"
        
        self.session.headers.update({
            "User-Agent": user_agent,
            "Referer": self.oast_url if self.oast_url else "http://google.com"
        })

        # 3. THEN initialize AdvancedAuditor (passing the now-existing session)
        self.advanced_auditor = AdvancedAuditor(self.session)

        # Initialize Auditors
        self.advanced_auditor = AdvancedAuditor(self.session)
        self.infra_auditor = InfrastructureAuditor(self.session, self.domain)
        self.content_auditor = ContentAuditor(self.session) 
        self.specialized_auditor = SpecializedAuditor(self.session)
        self.active_attacker = ActiveAttacker(self.session)

        # Defense Modules
        self.anomaly_tester = AnomalyTester(self.session)
        self.defense_gen = DefenseGenerator()

        
        self.results = {
            "info": {}, 
            "recon": {}, 
            "vulnerabilities": {}, 
            "details": {}, 
            "cves": [] 
        }
        self.visited_links = set()
        self.js_files = set()
        self.emails_found = set()
        self.tech_stack = {}       
        self.found_forms = []

        try:
            self.initial_response = self.session.get(self.base_url, timeout=5)
            self.results["info"]["target"] = self.base_url
            self.results["info"]["status_code"] = self.initial_response.status_code
        except requests.RequestException as e:
            st.error(f"Could not connect to {self.base_url}. Error: {e}")
            self.initial_response = None
            raise

    def run_all_checks(self):
        if not self.initial_response:
            return self.results

        with st.spinner(f"Scanning {self.domain}..."):
            # Async
            loop = asyncio.get_event_loop()
            loop.run_until_complete(self.run_async_checks())
            
            # Synchronous
            self.detect_waf_advanced()
            
            # Recon
            self.get_dns_ip()
            self.get_whois()
            self.check_ssl_certificate()
            self.get_subdomains()
            self.identify_tech_stack_hybrid()
            self.check_cves()
            self.parse_sitemap()
            self.analyze_headers_and_cookies()
            
            # Active Scanning
            self.scan_ports_with_banners([21, 22, 25, 80, 443, 3306, 5432, 8080, 8443])
            self.find_admin_pages()
            self.find_sensitive_files_smart()
            self.check_robots_txt()
            self.crawl_links()

            # Vulnerabilities - Standard
            self.scan_js_files()
            self.check_security_headers()
            self.check_crypto_failures()
            self.check_vulnerable_components()
            self.check_broken_access_control()
            self.check_idor_potential()
            self.check_open_redirects()
            self.check_injection_forms() 
            self.check_command_injection()
            self.check_xss_reflection()
            self.check_cors()
            self.check_sri()
            self.check_clickjacking()
            self.check_directory_listing()

            # --- NEW: Advanced Checks (Deep Inspection) ---
            
            # 1. Subdomain Takeover
            if self.results["recon"].get("subdomains"):
                st.caption("Checking for Subdomain Takeover...")
                takeover_results = self.advanced_auditor.check_subdomain_takeover(self.results["recon"]["subdomains"])
                self.results["vulnerabilities"]["A05_Subdomain_Takeover"] = takeover_results if takeover_results else ["No takeover fingerprints found."]

            # 2. JWT Analysis
            st.caption("Analyzing JWTs...")
            jwt_results = self.advanced_auditor.analyze_jwts(
                self.results["details"]["cookies"], 
                self.results["details"]["request_headers"]
            )
            self.results["vulnerabilities"]["A01_Broken_Access_JWT"] = jwt_results if jwt_results else ["No JWTs found in current session."]

            # 3. Deep Git Verification
            st.caption("Verifying Git Exposure...")
            git_result = self.advanced_auditor.verify_git_exposure(self.base_url)
            self.results["vulnerabilities"]["A05_Git_Exposure"] = [git_result] if git_result else ["No exposed .git repository verified."]

            # 4. Broken Link Hijacking
            st.caption("Checking for Broken Link Hijacking...")
            blh_results = self.advanced_auditor.check_broken_links(self.base_url, self.results["recon"].get("crawled_links", []))
            self.results["vulnerabilities"]["A06_Broken_Link_Hijacking"] = blh_results if blh_results else ["No hijacked links found."]

            # --- NEW: Infrastructure & API Audit ---
            
            # 1. Cloud Buckets
            st.caption("Enumerating Cloud Buckets...")
            bucket_results = self.infra_auditor.check_cloud_buckets()
            self.results["recon"]["cloud_buckets"] = bucket_results if bucket_results else ["No public cloud buckets found matching domain."]
            
            # 2. API Discovery
            st.caption("Discovering API Endpoints...")
            api_results = self.infra_auditor.discover_apis(self.base_url)
            self.results["recon"]["api_endpoints"] = api_results if api_results else ["No common API endpoints found."]

            # 3. Email Security
            st.caption("Checking Email Security (SPF/DMARC)...")
            email_sec_results = self.infra_auditor.check_email_security()
            self.results["vulnerabilities"]["A05_Email_Spoofing_Risks"] = email_sec_results if email_sec_results else ["SPF and DMARC records appear secure."]

            # 4. CMS Files
            cms_results = self.infra_auditor.check_cms_files(self.base_url, self.results["recon"].get("tech_stack", {}))
            if cms_results:
                self.results["vulnerabilities"]["A06_CMS_Exposure"] = cms_results

            # 5. DNS Zone Transfer
            st.caption("Testing DNS Zone Transfer...")
            zone_results = self.infra_auditor.check_zone_transfer()
            if zone_results:
                self.results["vulnerabilities"]["A05_DNS_Zone_Transfer"] = zone_results
            else:
                 # It is good practice to note it was checked and secure
                self.results["vulnerabilities"]["A05_DNS_Zone_Transfer"] = ["Secure (Transfer denied)."]

            # 6. Reverse DNS
            st.caption("Performing Reverse DNS...")
            rdns_result = self.infra_auditor.reverse_dns_lookup()
            self.results["recon"]["reverse_dns"] = rdns_result

            # 7. WAF/403 Bypass Check
            # We check the admin pages found earlier. If any were 403, we try to bypass.
            st.caption("Attempting WAF/403 Bypass...")
            bypass_results = []
            # Try on base URL
            bypass_results.extend(self.infra_auditor.attempt_bypass(self.base_url))
            
            # Try on found admin pages if any
            for page in self.results["recon"].get("admin_pages_found", []):
                full_admin_url = urljoin(self.base_url, page)
                bypass_results.extend(self.infra_auditor.attempt_bypass(full_admin_url))
            
            if bypass_results:
                self.results["vulnerabilities"]["A01_Bypass_Techniques"] = bypass_results
            else:
                self.results["vulnerabilities"]["A01_Bypass_Techniques"] = ["No bypass vectors found using standard headers."]

            # 8. Active Robots.txt Scan
            st.caption("Actively Scanning Robots.txt Paths...")
            # We use the robots content we fetched in the recon phase
            robots_data = self.results["recon"].get("robots_txt_disallowed", "")
            hidden_paths = self.infra_auditor.active_robots_scan(self.base_url, robots_data)
            
            if hidden_paths:
                self.results["recon"]["robots_txt_accessible"] = hidden_paths
                # Also flag as a potential Info Leak vulnerability
                self.results["vulnerabilities"]["A05_Information_Disclosure_Robots"] = hidden_paths
            else:
                self.results["recon"]["robots_txt_accessible"] = ["No hidden paths were accessible."]
            

            # --- Content Discovery & Analysis ---
            st.caption("Analyzing Page Content (PII, Comments, backups)...")
            
            all_pii = []
            all_comments = []
            all_security_issues = []

            # We analyze the main page immediately
            if self.initial_response:
                all_pii.extend(self.content_auditor.scan_for_pii(self.initial_response.text, self.base_url))
                all_comments.extend(self.content_auditor.extract_comments(self.initial_response.text, self.base_url))
                all_security_issues.extend(self.content_auditor.check_page_security(self.initial_response.text, self.base_url))

            # Feature 3: Smart Mutation Fuzzing (Uses crawled links)
            st.caption("Fuzzing discovered files for backups...")
            backup_findings = self.content_auditor.fuzz_discovered_files(self.results["recon"].get("crawled_links", []))
            
            # Store Results
            self.results["vulnerabilities"]["A04_PII_Exposure"] = all_pii if all_pii else ["No PII patterns detected."]
            self.results["vulnerabilities"]["A05_Developer_Comments"] = all_comments if all_comments else ["No interesting comments found."]
            self.results["vulnerabilities"]["A06_Mixed_Content_&_Sinks"] = all_security_issues if all_security_issues else ["No Mixed Content or Dangerous Sinks detected."]
            
            if backup_findings:
                self.results["recon"]["backup_files_found"] = backup_findings
                self.results["vulnerabilities"]["A05_Sensitive_Backup_Files"] = backup_findings

            # --- NEW: Specialized Attacks ---
            st.caption("Testing Host Header Injection & GraphQL...")
            
            # 1. Host Header
            hh_issues = self.specialized_auditor.check_host_header_injection(self.base_url)
            self.results["vulnerabilities"]["A01_Host_Header_Injection"] = hh_issues if hh_issues else ["Server appears to handle Host headers correctly."]
            
            # 2. GraphQL (Using endpoints discovered in Infra step)
            # We assume api_endpoints might be populated in self.results["recon"]["api_endpoints"]
            gql_issues = self.specialized_auditor.check_graphql(self.results["recon"].get("api_endpoints", []), self.base_url)
            if gql_issues:
                self.results["vulnerabilities"]["A05_GraphQL_Exposure"] = gql_issues

            # 3. Prototype Pollution (Using JS files found in Recon step)
            proto_issues = self.specialized_auditor.check_prototype_pollution(self.results["recon"].get("js_files_found", []))
            if proto_issues:
                self.results["vulnerabilities"]["A03_Prototype_Pollution"] = proto_issues

            # --- NEW: Active Attack Modules ---
            st.caption("Launching Active Injection Attacks (SSTI, CRLF, Blind SQLi)...")
            
            # 1. SSTI
            ssti_res = self.active_attacker.check_ssti(self.base_url)
            if ssti_res:
                self.results["vulnerabilities"]["A03_SSTI"] = ssti_res
            
            # 2. CRLF
            crlf_res = self.active_attacker.check_crlf(self.base_url)
            if crlf_res:
                self.results["vulnerabilities"]["A03_CRLF_Injection"] = crlf_res
                
            # 3. Time-Based SQLi
            # This can be slow, so we check if standard SQLi found anything first to avoid redundancy?
            # No, let's run it because Blind SQLi often finds things normal SQLi misses.
            blind_sqli = self.active_attacker.check_time_based_sqli(self.base_url)
            if blind_sqli:
                self.results["vulnerabilities"]["A03_Blind_SQL_Injection"] = blind_sqli

            # --- NEW: Anomaly & Defense ---
            st.caption("Testing Traffic Anomalies (Rate Limits, Bot Detection)...")
            
            # 1. Rate Limiting
            rl_res = self.anomaly_tester.check_rate_limiting(self.base_url)
            self.results["vulnerabilities"]["A05_Rate_Limiting"] = rl_res
            
            # 2. Bot Detection
            bot_res = self.anomaly_tester.check_bot_blocking(self.base_url)
            self.results["vulnerabilities"]["A06_Bot_Protection"] = bot_res
            
            # --- Generate Defense Recommendations (Virtual Patching) ---
            st.caption("Generating Defense Configs...")
            
            # 1. Header Fixes
            missing_h = self.results["vulnerabilities"].get("A05_Security_Misconfig_Headers", {}).get("missing", [])
            header_fixes = self.defense_gen.generate_header_fixes(missing_h)
            self.results["defense_configs"] = {"headers": header_fixes}
            
            # 2. WAF Rules
            waf_rules = self.defense_gen.generate_waf_rules(self.results["vulnerabilities"])
            self.results["defense_configs"]["waf"] = waf_rules

        return self.results


        return self.results

    # --- Asynchronous Hub---
    async def run_async_checks(self):
        """
        Orchestrates all asynchronous checks using httpx.
        """
        async with httpx.AsyncClient(verify=False, timeout=5.0) as client:
            # We can run multiple async tasks here concurrently
            await self.check_http2_support(client)

    # --- HTTP/2 Support Check ---
    async def check_http2_support(self, client):
        try:
            # httpx supports http2 if installed with [http2] extra
            resp = await client.get(self.base_url)
            self.results["info"]["http_version"] = resp.http_version
            if resp.http_version == "HTTP/2":
                self.results["info"]["http2_enabled"] = True
            else:
                self.results["info"]["http2_enabled"] = False
        except Exception:
            self.results["info"]["http2_enabled"] = "Unknown"

    # --- Advanced WAF Detection ---
    def detect_waf_advanced(self):
        """
        Uses wafw00f library for professional fingerprinting.
        """
        try:
            waf = WAFW00F(self.base_url)
            # wafw00f prints to stdout/stderr, we silence it or capture logic
            # The library logic scans for matches
            detected = waf.ident_waf()
            
            if detected:
                self.results["info"]["waf_detected"] = detected
            else:
                self.results["info"]["waf_detected"] = ["No WAF detected (Generic)"]
        except Exception as e:
            self.results["info"]["waf_detected"] = [f"WAF Scan Error: {str(e)}"]

    # --- ENHANCED: Hybrid Tech Detection (Wappalyzer + Regex Fallback) ---
    def identify_tech_stack_hybrid(self):
        """
        1. Tries Wappalyzer first.
        2. If that misses, falls back to Regex signatures from config.py
        """
        # 1. Wappalyzer
        detected_tech = {}
        try:
            wappalyzer = Wappalyzer.latest()
            webpage = WebPage.new_from_url(self.base_url)
            raw_tech = wappalyzer.analyze_with_versions_and_categories(webpage)
            
            for tech, data in raw_tech.items():
                versions = data.get("versions", [])
                detected_tech[tech] = versions[0] if versions else "Unknown"
        except Exception:
            pass

        # 2. Regex Fallback (using TECH_SIGNATURES from config.py)
        # Scan HTML content
        html_content = self.initial_response.text
        # Scan Headers
        headers_content = str(self.initial_response.headers)

        for tech_name, signatures in TECH_SIGNATURES.items():
            if tech_name in detected_tech: continue # Skip if already found
            
            for signature in signatures:
                if re.search(signature, html_content, re.IGNORECASE) or \
                   re.search(signature, headers_content, re.IGNORECASE):
                    detected_tech[tech_name] = "Detected (Signature)"
                    break

        self.tech_stack = detected_tech
        self.results["recon"]["tech_stack"] = detected_tech

    # --- CVE Intelligence (Arch Section 6.1) ---
    def check_cves(self):
        """
        Takes detected versions from Wappalyzer and queries NVDLib for CVEs.
        """
        found_cves = []
        
        # Only check if we have detected technologies
        if not self.tech_stack or "Error" in self.tech_stack:
            return

        for software, version in self.tech_stack.items():
            if version == "Unknown":
                continue # Cannot find CVEs without a version
            
            try:
                # Construct a keyword search (e.g., "WordPress 5.8")
                # Using limit=3 to keep the scan fast
                results = nvdlib.searchCVE(keyword=f"{software} {version}", limit=2, sortPubDate=True)
                
                for r in results:
                    found_cves.append({
                        "Software": software,
                        "Version": version,
                        "ID": r.id,
                        "Score": r.v31score if hasattr(r, 'v31score') else "N/A",
                        "Description": r.descriptions[0].value if r.descriptions else "No description",
                        "Link": f"https://nvd.nist.gov/vuln/detail/{r.id}"
                    })
            except Exception:
                continue # Skip if NVD lookup fails/timeouts
                
        self.results["cves"] = found_cves

    # --- Sitemap Parser ---
    def parse_sitemap(self):
        sitemap_url = urljoin(self.base_url, "/sitemap.xml")
        found_urls = set()
        try:
            resp = self.session.get(sitemap_url, timeout=3)
            if resp.status_code == 200 and "xml" in resp.headers.get("Content-Type", ""):
                # Basic XML parse without external libs if possible, or use regex for robustness
                # Using simple regex to avoid XML parsing errors on malformed sitemaps
                locs = re.findall(r"<loc>(.*?)</loc>", resp.text)
                for loc in locs:
                    if self.domain in loc:
                        found_urls.add(loc)
            
            if found_urls:
                self.results["recon"]["sitemap_entries"] = list(found_urls)
            else:
                self.results["recon"]["sitemap_entries"] = ["Sitemap not found or empty"]
        except Exception:
            self.results["recon"]["sitemap_entries"] = ["Error parsing sitemap"]
    
    # --- Headers & Cookies Analysis ---
    def analyze_headers_and_cookies(self):
        # 1. Store Raw Headers
        self.results["details"]["response_headers"] = dict(self.initial_response.headers)
        self.results["details"]["request_headers"] = dict(self.initial_response.request.headers)
        
        # 2. Analyze Cookies
        cookie_data = []
        for cookie in self.session.cookies:
            cookie_data.append({
                "Name": cookie.name,
                "Value": cookie.value[:20] + "..." if len(cookie.value) > 20 else cookie.value,
                "Domain": cookie.domain,
                "Path": cookie.path,
                "Secure": cookie.secure,
                "HttpOnly": cookie.has_nonstandard_attr('HttpOnly') or cookie.has_nonstandard_attr('httponly'),
                "Expires": cookie.expires
            })
        self.results["details"]["cookies"] = cookie_data

    # --- SSL Certificate Check ---
    def check_ssl_certificate(self):
        try:
            ctx = ssl.create_default_context()
            with ctx.wrap_socket(socket.socket(), server_hostname=self.domain) as s:
                s.settimeout(2.0) # Lowered timeout
                s.connect((self.domain, 443))
                cert = s.getpeercert()
                not_after = cert['notAfter']
                expiry_date = datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
                days_left = (expiry_date - datetime.now()).days
                self.results["recon"]["ssl_info"] = {
                    "valid": True,
                    "issued_to": dict(x[0] for x in cert['subject']).get('commonName'),
                    "issued_by": dict(x[0] for x in cert['issuer']).get('commonName'),
                    "expires_on": not_after,
                    "days_remaining": days_left
                }
        except Exception as e:
            self.results["recon"]["ssl_info"] = {"valid": False, "error": str(e)}

    # --- Subdomain Enumeration ---
    def get_subdomains(self):
        subs = set()
        try:
            url = f"https://crt.sh/?q=%.{self.domain}&output=json"
            resp = requests.get(url, timeout=4)
            if resp.status_code == 200:
                for entry in resp.json():
                    name_value = entry['name_value']
                    for sub in name_value.split('\n'):
                        if self.domain in sub and "*" not in sub:
                            subs.add(sub)
        except: pass
        self.results["recon"]["subdomains"] = list(subs)

    # --- Link Crawler ---
    def crawl_links(self):
        to_visit = [self.base_url]
        count = 0
        # Reduced crawl limit to prevent timeouts
        while to_visit and count < 30:
            url = to_visit.pop()
            if url in self.visited_links: continue
            self.visited_links.add(url)
            count += 1
            try:
                resp = self.session.get(url, timeout=2)
                content = resp.text
                for email in re.findall(EMAIL_REGEX, content):
                    if not email.endswith(('example.com', '.png', '.jpg', '.gif')):
                        self.emails_found.add(email)
                soup = BeautifulSoup(content, "html.parser")
                for a in soup.find_all("a", href=True):
                    full = urljoin(self.base_url, a['href'])
                    if self.domain in full and full not in self.visited_links:
                        to_visit.append(full)
                for s in soup.find_all("script", src=True):
                    full = urljoin(self.base_url, s['src'])
                    if self.domain in full:
                        self.js_files.add(full)
            except: pass
        self.results["recon"]["crawled_links"] = list(self.visited_links)
        self.results["recon"]["js_files_found"] = list(self.js_files)
        self.results["recon"]["emails_found"] = list(self.emails_found)

    # --- DNS IP Resolution ---

    def get_dns_ip(self):
        try: self.results["recon"]["ip_address"] = socket.gethostbyname(self.domain)
        except: self.results["recon"]["ip_address"] = "N/A"
    
    # --- WHOIS Lookup ---
    def get_whois(self):
        try: self.results["recon"]["whois"] = str(whois.whois(self.domain))
        except: self.results["recon"]["whois"] = "Lookup failed"

    # --- Port Scanner with Banner Grabbing ---
    def scan_ports_with_banners(self, ports):
        open_ports = []
        def check(p):
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(0.5) 
                if s.connect_ex((self.domain, p)) == 0: 
                    # Try to grab banner
                    try:
                        s.send(b'HEAD / HTTP/1.0\r\n\r\n')
                        banner = s.recv(1024).decode('utf-8', errors='ignore').strip()
                        banner_snip = banner.split('\n')[0][:50] # Take first line
                        return f"Port {p}: Open ({banner_snip})"
                    except:
                        return f"Port {p}: Open"
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_SCAN_THREADS) as ex:
            open_ports = list(filter(None, ex.map(check, ports)))
        self.results["recon"]["open_ports"] = open_ports

    # --- Admin Page Finder ---
    def find_admin_pages(self):
        found = []
        def check(path):
            try:
                if self.session.get(urljoin(self.base_url, path), timeout=1).status_code == 200: return path
            except: pass
        with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_SCAN_THREADS) as ex:
            found = list(filter(None, ex.map(check, ADMIN_PATHS)))
        self.results["recon"]["admin_pages_found"] = found

    # --- Sensitive File Finder ---
    def find_sensitive_files(self):
        found = []
        def check(path):
            try:
                if self.session.head(urljoin(self.base_url, path), timeout=1).status_code == 200: return path
            except: pass
        with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_SCAN_THREADS) as ex:
            found = list(filter(None, ex.map(check, SENSITIVE_PATHS)))
        self.results["recon"]["sensitive_files_found"] = found

    # --- ENHANCED: Smart Sensitive File Detection ---
    def find_sensitive_files_smart(self):
        """
        Generates backup filenames based on the domain (e.g. example.com.zip)
        plus checks the standard list.
        """
        # Start with standard list
        paths_to_check = list(SENSITIVE_PATHS)
        
        # Add dynamic paths
        domain_parts = self.domain.split('.')
        base_name = domain_parts[0] # e.g., 'google' from 'google.com'
        
        extensions = ['.zip', '.tar.gz', '.sql', '.bak', '.old']
        
        # Add 'domain.zip', 'domain.sql', etc.
        for ext in extensions:
            paths_to_check.append(f"/{self.domain}{ext}")
            paths_to_check.append(f"/{base_name}{ext}")

        found = []
        def check(path):
            try:
                # Use HEAD to be fast
                r = self.session.head(urljoin(self.base_url, path), timeout=1)
                if r.status_code == 200: 
                    # Double check content-type to avoid false positives (like custom 404 pages returning 200)
                    ctype = r.headers.get("Content-Type", "")
                    if "html" not in ctype: # Real backup files usually aren't HTML
                        return path
            except: pass
            
        with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_SCAN_THREADS) as ex:
            found = list(filter(None, ex.map(check, paths_to_check)))
        self.results["recon"]["sensitive_files_found"] = found

    
    # --- NEW: IDOR Detection ---
    def check_idor_potential(self):
        """
        Scans visited links for numeric parameters (e.g., id=123)
        which often indicate IDOR vulnerabilities.
        """
        idor_candidates = []
        for link in self.visited_links:
            parsed = urlparse(link)
            params = parse_qsl(parsed.query)
            for name, value in params:
                # If value is numeric, it's a candidate
                if value.isdigit():
                    idor_candidates.append(f"{link} (Param: {name}={value})")
        
        self.results["vulnerabilities"]["Broken_Access_Control_IDOR"] = idor_candidates if idor_candidates else ["No obvious numeric ID parameters found"]

    # --- Robots.txt Analyzer ---

    def check_robots_txt(self):
        try:
            resp = self.session.get(urljoin(self.base_url, "/robots.txt"), timeout=2)
            self.results["recon"]["robots_txt_disallowed"] = re.findall(r"Disallow: (.*)", resp.text) if resp.status_code == 200 else "Not found"
        except: self.results["recon"]["robots_txt_disallowed"] = "Error"


    # --- VULNERABILITIES ---
    def scan_js_files(self):
        found = []
        def scan(url):
            try:
                text = self.session.get(url, timeout=2).text
                for name, pat in SECRET_REGEX.items():
                    for match in re.finditer(pat, text):
                        return {"type": name, "file": url, "snippet": match.group(0)}
            except: pass
        with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_SCAN_THREADS) as ex:
            found = list(filter(None, ex.map(scan, self.js_files)))
        self.results["vulnerabilities"]["CRITICAL_Hardcoded_Secrets"] = found

    # --- Command Injection Check ---
    def check_command_injection(self):
        issues = []
        test_url = f"{self.base_url}/"
        # Params often used for system calls
        risk_params = ['ip', 'host', 'cmd', 'file', 'query'] 
        
        for param in risk_params:
            for payload in COMMAND_INJECTION_PAYLOADS:
                try:
                    target = f"{test_url}?{param}={payload}"
                    resp = self.session.get(target, timeout=1.5)
                    # Check for indicators of execution (echoed string or uid output)
                    if "vulnerable" in resp.text or "uid=" in resp.text:
                        issues.append(f"Param '{param}' reflected payload: {payload}")
                        break
                except: pass
        
        self.results["vulnerabilities"]["A03_Command_Injection"] = issues if issues else ["No simple Command Injection detected"]

    # --- Security Headers Check ---
    def check_security_headers(self):
        h = self.initial_response.headers
        self.results["vulnerabilities"]["A05_Security_Misconfig_Headers"] = {"missing": [k for k in SECURITY_HEADERS if k not in h]}

    # --- Cryptographic Failures Check ---
    def check_crypto_failures(self):
        issues = []
        if not self.base_url.startswith("https"): issues.append("Not using HTTPS")
        if "Strict-Transport-Security" not in self.initial_response.headers: issues.append("Missing HSTS Header")
        self.results["vulnerabilities"]["A02_Cryptographic_Failures"] = issues

    # --- Vulnerable Components Check ---
    def check_vulnerable_components(self):
        h = self.initial_response.headers
        self.results["vulnerabilities"]["A06_Vulnerable_Components"] = {k: h[k] for k in ["Server", "X-Powered-By"] if k in h}

    # --- Broken Access Control Check ---
    def check_broken_access_control(self):
        self.results["vulnerabilities"]["A01_Broken_Access_Control"] = "Admin page found" if self.results["recon"]["admin_pages_found"] else "No obvious admin path"

    # --- Open Redirect Check ---
    def check_open_redirects(self):
        issues = []
        test_url = f"{self.base_url}/"
        for param in ['url', 'next', 'target']:
            for payload in OPEN_REDIRECT_PAYLOADS:
                try:
                    r = self.session.get(f"{test_url}?{param}={payload}", allow_redirects=False, timeout=1.5)
                    if r.status_code in [301, 302] and "google.com" in r.headers.get("Location", ""):
                        issues.append(f"Param '{param}' redirects to google.com")
                except: pass
        self.results["vulnerabilities"]["A01_Open_Redirect"] = issues

    # --- Injection Forms Check ---
    def check_injection_forms(self):
        self.results["vulnerabilities"]["A03_Injection"] = ["No simple SQLi detected (Basic check only)"]

    # --- XSS Reflection Check ---
    def check_xss_reflection(self):
        try:
            if XSS_PAYLOAD in self.session.get(f"{self.base_url}/?q={XSS_PAYLOAD}", timeout=2).text:
                self.results["vulnerabilities"]["A07_XSS"] = ["Reflected XSS found on param 'q'"]
            else:
                self.results["vulnerabilities"]["A07_XSS"] = ["No simple XSS found"]
        except: pass

    # --- CORS Misconfiguration Check ---
    def check_cors(self):
        try:
            headers = {"Origin": "https://evil.com"}
            resp = self.session.get(self.base_url, headers=headers, timeout=2)
            acao = resp.headers.get("Access-Control-Allow-Origin")
            if acao == "https://evil.com":
                self.results["vulnerabilities"]["A05_CORS_Misconfiguration"] = ["Reflected Origin: Server echoes back arbitrary Origin headers."]
            elif acao == "*":
                self.results["vulnerabilities"]["A05_CORS_Misconfiguration"] = ["Wildcard Origin: 'Access-Control-Allow-Origin: *' detected."]
            else:
                self.results["vulnerabilities"]["A05_CORS_Misconfiguration"] = ["No obvious CORS misconfiguration detected."]
        except: pass

    # --- Missing SRI Check ---
    def check_sri(self):
        issues = []
        try:
            soup = BeautifulSoup(self.initial_response.text, "html.parser")
            for script in soup.find_all("script", src=True):
                if script['src'].startswith("http") and self.domain not in script['src']:
                    if not script.get("integrity"): issues.append(f"Script missing SRI: {script['src']}")
        except: pass
        self.results["vulnerabilities"]["Missing_SRI"] = issues if issues else ["All external resources appear to have integrity checks."]

    # --- Clickjacking Check ---
    def check_clickjacking(self):
        h = self.initial_response.headers
        if "X-Frame-Options" not in h and "frame-ancestors" not in h.get("Content-Security-Policy", ""):
            self.results["vulnerabilities"]["A05_Clickjacking"] = ["Missing 'X-Frame-Options' and CSP 'frame-ancestors'."]
        else:
            self.results["vulnerabilities"]["A05_Clickjacking"] = ["Protected"]

    # --- Directory Listing Check ---
    def check_directory_listing(self):
        self.results["vulnerabilities"]["A05_Directory_Listing"] = ["No directory listings found (Passive check)"]
            