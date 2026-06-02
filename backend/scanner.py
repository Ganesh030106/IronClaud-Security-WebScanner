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
import nest_asyncio
import asyncio
import httpx
from wafw00f.main import WAFW00F

# Apply the patch to allow nested event loops
nest_asyncio.apply()

# --- IMPORT MODULES ---
from modules.advanced_checks import AdvancedAuditor
from modules.advanced_recon import InfrastructureAuditor
from modules.content_discovery import ContentAuditor  
from modules.specialized_checks import SpecializedAuditor 
from modules.active_attackers import ActiveAttacker 
from modules.traffic_anomaly import AnomalyTester
from modules.defense_generator import DefenseGenerator

# Intelligence Modules
try:
    from Wappalyzer import Wappalyzer, WebPage
    import nvdlib
except ImportError:
    pass

# Import configurations
from config import (ADMIN_PATHS, SQLI_PAYLOADS, XSS_PAYLOAD, SECURITY_HEADERS, SENSITIVE_PATHS, SECRET_REGEX, OPEN_REDIRECT_PAYLOADS, 
                    WAF_SIGNATURES, EMAIL_REGEX, TECH_SIGNATURES, DIRECTORY_LISTING_SIGNATURES, COMMAND_INJECTION_PAYLOADS,
                    THREAT_WEIGHTS, ANOMALY_THRESHOLD, WMA_DECAY, THRESHOLD_CRITICAL, THRESHOLD_WARNING, THREAT_IMPACT)

MAX_SCAN_THREADS = 15

class OWASPTester:
    def __init__(self, base_url, oast_url=None):
        self.base_url = base_url.rstrip('/')
        self.domain = urlparse(self.base_url).hostname
        self.oast_url = oast_url
        
        self.session = requests.Session()
        
        user_agent = "EducationalSecurityScanner/1.3 (Advanced)"
        if self.oast_url:
            user_agent = f"{user_agent} (OAST-Check: {self.oast_url})"
        
        self.session.headers.update({
            "User-Agent": user_agent,
            "Referer": self.oast_url if self.oast_url else "http://google.com"
        })

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
            self.initial_response = None
            raise Exception(f"Could not connect to {self.base_url}. Error: {e}")

    def run_all_checks(self):
        if not self.initial_response:
            return self.results

        # Async
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
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

        # --- Advanced Checks (Deep Inspection) ---
        
        # 1. Subdomain Takeover
        if self.results["recon"].get("subdomains"):
            takeover_results = self.advanced_auditor.check_subdomain_takeover(self.results["recon"]["subdomains"])
            self.results["vulnerabilities"]["A05_Subdomain_Takeover"] = takeover_results if takeover_results else ["No takeover fingerprints found."]

        # 2. JWT Analysis
        jwt_results = self.advanced_auditor.analyze_jwts(
            self.results["details"]["cookies"], 
            self.results["details"]["request_headers"]
        )
        self.results["vulnerabilities"]["A01_Broken_Access_JWT"] = jwt_results if jwt_results else ["No JWTs found in current session."]

        # 3. Deep Git Verification
        git_result = self.advanced_auditor.verify_git_exposure(self.base_url)
        self.results["vulnerabilities"]["A05_Git_Exposure"] = [git_result] if git_result else ["No exposed .git repository verified."]

        # 4. Broken Link Hijacking
        blh_results = self.advanced_auditor.check_broken_links(self.base_url, self.results["recon"].get("crawled_links", []))
        self.results["vulnerabilities"]["A06_Broken_Link_Hijacking"] = blh_results if blh_results else ["No hijacked links found."]

        # --- Infrastructure & API Audit ---
        
        # 1. Cloud Buckets
        bucket_results = self.infra_auditor.check_cloud_buckets()
        self.results["recon"]["cloud_buckets"] = bucket_results if bucket_results else ["No public cloud buckets found matching domain."]
        
        # 2. API Discovery
        api_results = self.infra_auditor.discover_apis(self.base_url)
        self.results["recon"]["api_endpoints"] = api_results if api_results else ["No common API endpoints found."]

        # 3. Email Security
        email_sec_results = self.infra_auditor.check_email_security()
        self.results["vulnerabilities"]["A05_Email_Spoofing_Risks"] = email_sec_results if email_sec_results else ["SPF and DMARC records appear secure."]

        # 4. CMS Files
        cms_results = self.infra_auditor.check_cms_files(self.base_url, self.results["recon"].get("tech_stack", {}))
        if cms_results:
            self.results["vulnerabilities"]["A06_CMS_Exposure"] = cms_results

        # 5. DNS Zone Transfer
        zone_results = self.infra_auditor.check_zone_transfer()
        if zone_results:
            self.results["vulnerabilities"]["A05_DNS_Zone_Transfer"] = zone_results
        else:
            self.results["vulnerabilities"]["A05_DNS_Zone_Transfer"] = ["Secure (Transfer denied)."]

        # 6. Reverse DNS
        rdns_result = self.infra_auditor.reverse_dns_lookup()
        self.results["recon"]["reverse_dns"] = rdns_result

        # 7. WAF/403 Bypass Check
        bypass_results = []
        bypass_results.extend(self.infra_auditor.attempt_bypass(self.base_url))
        for page in self.results["recon"].get("admin_pages_found", []):
            full_admin_url = urljoin(self.base_url, page)
            bypass_results.extend(self.infra_auditor.attempt_bypass(full_admin_url))
        
        if bypass_results:
            self.results["vulnerabilities"]["A01_Bypass_Techniques"] = bypass_results
        else:
            self.results["vulnerabilities"]["A01_Bypass_Techniques"] = ["No bypass vectors found using standard headers."]

        # 8. Active Robots.txt Scan
        robots_data = self.results["recon"].get("robots_txt_disallowed", "")
        hidden_paths = self.infra_auditor.active_robots_scan(self.base_url, robots_data)
        
        if hidden_paths:
            self.results["recon"]["robots_txt_accessible"] = hidden_paths
            self.results["vulnerabilities"]["A05_Information_Disclosure_Robots"] = hidden_paths
        else:
            self.results["recon"]["robots_txt_accessible"] = ["No hidden paths were accessible."]

        # --- Content Discovery & Analysis ---
        all_pii = []
        all_comments = []
        all_security_issues = []

        if self.initial_response:
            all_pii.extend(self.content_auditor.scan_for_pii(self.initial_response.text, self.base_url))
            all_comments.extend(self.content_auditor.extract_comments(self.initial_response.text, self.base_url))
            all_security_issues.extend(self.content_auditor.check_page_security(self.initial_response.text, self.base_url))

        # Backup fuzzing
        backup_findings = self.content_auditor.fuzz_discovered_files(self.results["recon"].get("crawled_links", []))
        
        self.results["vulnerabilities"]["A04_PII_Exposure"] = all_pii if all_pii else ["No PII patterns detected."]
        self.results["vulnerabilities"]["A05_Developer_Comments"] = all_comments if all_comments else ["No interesting comments found."]
        self.results["vulnerabilities"]["A06_Mixed_Content_&_Sinks"] = all_security_issues if all_security_issues else ["No Mixed Content or Dangerous Sinks detected."]
        
        if backup_findings:
            self.results["recon"]["backup_files_found"] = backup_findings
            self.results["vulnerabilities"]["A05_Sensitive_Backup_Files"] = backup_findings

        # --- Specialized Attacks ---
        # 1. Host Header
        hh_issues = self.specialized_auditor.check_host_header_injection(self.base_url)
        self.results["vulnerabilities"]["A01_Host_Header_Injection"] = hh_issues if hh_issues else ["Server appears to handle Host headers correctly."]
        
        # 2. GraphQL
        gql_issues = self.specialized_auditor.check_graphql(self.results["recon"].get("api_endpoints", []), self.base_url)
        if gql_issues:
            self.results["vulnerabilities"]["A05_GraphQL_Exposure"] = gql_issues

        # 3. Prototype Pollution
        proto_issues = self.specialized_auditor.check_prototype_pollution(self.results["recon"].get("js_files_found", []))
        if proto_issues:
            self.results["vulnerabilities"]["A03_Prototype_Pollution"] = proto_issues

        # --- Active Attack Modules ---
        # 1. SSTI
        ssti_res = self.active_attacker.check_ssti(self.base_url)
        if ssti_res:
            self.results["vulnerabilities"]["A03_SSTI"] = ssti_res
        
        # 2. CRLF
        crlf_res = self.active_attacker.check_crlf(self.base_url)
        if crlf_res:
            self.results["vulnerabilities"]["A03_CRLF_Injection"] = crlf_res
            
        # 3. Time-Based SQLi
        blind_sqli = self.active_attacker.check_time_based_sqli(self.base_url)
        if blind_sqli:
            self.results["vulnerabilities"]["A03_Blind_SQL_Injection"] = blind_sqli

        # --- Anomaly & Defense (Simulated) ---
        # 1. Rate Limiting
        rl_res = self.anomaly_tester.check_rate_limiting(self.base_url)
        self.results["vulnerabilities"]["A05_Rate_Limiting"] = rl_res
        
        # 2. Bot Detection
        bot_res = self.anomaly_tester.check_bot_blocking(self.base_url)
        self.results["vulnerabilities"]["A06_Bot_Protection"] = bot_res
        
        # 3. WMA Threat Score Calculation
        self.calculate_wma_threat()

        # --- Generate Defense Recommendations (Virtual Patching) ---
        missing_h = self.results["vulnerabilities"].get("A05_Security_Misconfig_Headers", {}).get("missing", [])
        header_fixes = self.defense_gen.generate_header_fixes(missing_h)
        self.results["defense_configs"] = {"headers": header_fixes}
        
        waf_rules = self.defense_gen.generate_waf_rules(self.results["vulnerabilities"])
        self.results["defense_configs"]["waf"] = waf_rules

        return self.results

    async def run_async_checks(self):
        async with httpx.AsyncClient(verify=False, timeout=5.0) as client:
            await self.check_http2_support(client)

    async def check_http2_support(self, client):
        try:
            resp = await client.get(self.base_url)
            self.results["info"]["http_version"] = resp.http_version
            if resp.http_version == "HTTP/2":
                self.results["info"]["http2_enabled"] = True
            else:
                self.results["info"]["http2_enabled"] = False
        except Exception:
            self.results["info"]["http2_enabled"] = "Unknown"

    def detect_waf_advanced(self):
        try:
            waf = WAFW00F(self.base_url)
            detected = waf.ident_waf()
            if detected:
                self.results["info"]["waf_detected"] = detected
            else:
                self.results["info"]["waf_detected"] = ["No WAF detected (Generic)"]
        except Exception as e:
            self.results["info"]["waf_detected"] = [f"WAF Scan Error: {str(e)}"]

    def identify_tech_stack_hybrid(self):
        detected_tech = {}
        try:
            wappalyzer = Wappalyzer.latest()
            webpage = WebPage(
                url=self.base_url,
                html=self.initial_response.text,
                headers=dict(self.initial_response.headers)
            )
            raw_tech = wappalyzer.analyze_with_versions_and_categories(webpage)
            for tech, data in raw_tech.items():
                versions = data.get("versions", [])
                detected_tech[tech] = versions[0] if versions else "Unknown"
        except Exception:
            pass

        html_content = self.initial_response.text
        headers_content = str(self.initial_response.headers)

        for tech_name, signatures in TECH_SIGNATURES.items():
            if tech_name in detected_tech: continue
            
            for signature in signatures:
                if re.search(signature, html_content, re.IGNORECASE) or \
                   re.search(signature, headers_content, re.IGNORECASE):
                    detected_tech[tech_name] = "Detected (Signature)"
                    break

        self.tech_stack = detected_tech
        self.results["recon"]["tech_stack"] = detected_tech

    def check_cves(self):
        found_cves = []
        if not self.tech_stack or "Error" in self.tech_stack:
            return

        for software, version in list(self.tech_stack.items())[:2]:
            if version == "Unknown":
                continue
            try:
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
                continue
                
        self.results["cves"] = found_cves

    def parse_sitemap(self):
        sitemap_url = urljoin(self.base_url, "/sitemap.xml")
        found_urls = set()
        try:
            resp = self.session.get(sitemap_url, timeout=3)
            if resp.status_code == 200 and "xml" in resp.headers.get("Content-Type", ""):
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
    
    def analyze_headers_and_cookies(self):
        self.results["details"]["response_headers"] = dict(self.initial_response.headers)
        self.results["details"]["request_headers"] = dict(self.initial_response.request.headers)
        
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

    def check_ssl_certificate(self):
        try:
            ctx = ssl.create_default_context()
            with ctx.wrap_socket(socket.socket(), server_hostname=self.domain) as s:
                s.settimeout(2.0)
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

    def get_subdomains(self):
        subs = set()
        try:
            url = f"https://crt.sh/?q=%.{self.domain}&output=json"
            resp = requests.get(url, timeout=1.5)
            if resp.status_code == 200:
                for entry in resp.json():
                    name_value = entry['name_value']
                    for sub in name_value.split('\n'):
                        if self.domain in sub and "*" not in sub:
                            subs.add(sub)
        except: pass
        self.results["recon"]["subdomains"] = list(subs)

    def crawl_links(self):
        to_visit = [self.base_url]
        all_links = set()
        
        while to_visit and len(all_links) < 15:
            url = to_visit.pop()
            if url in self.visited_links: continue
            self.visited_links.add(url)
            try:
                resp = self.session.get(url, timeout=1.5)
                content = resp.text
                for email in re.findall(EMAIL_REGEX, content):
                    if not email.endswith(('example.com', '.png', '.jpg', '.gif')):
                        self.emails_found.add(email)
                soup = BeautifulSoup(content, "html.parser")
                for a in soup.find_all("a", href=True):
                    full = urljoin(self.base_url, a['href'])
                    if self.domain in full and full not in self.visited_links:
                        to_visit.append(full)
                        all_links.add(full)
                for s in soup.find_all("script", src=True):
                    full = urljoin(self.base_url, s['src'])
                    if self.domain in full:
                        self.js_files.add(full)
            except: pass
        self.results["recon"]["crawled_links"] = list(all_links)
        self.results["recon"]["js_files_found"] = list(self.js_files)
        self.results["recon"]["emails_found"] = list(self.emails_found)

    def get_dns_ip(self):
        try: self.results["recon"]["ip_address"] = socket.gethostbyname(self.domain)
        except: self.results["recon"]["ip_address"] = "N/A"
    
    def get_whois(self):
        try: self.results["recon"]["whois"] = str(whois.whois(self.domain))
        except: self.results["recon"]["whois"] = "Lookup failed"

    def scan_ports_with_banners(self, ports):
        open_ports = []
        def check(p):
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(0.5) 
                if s.connect_ex((self.domain, p)) == 0: 
                    try:
                        s.send(b'HEAD / HTTP/1.0\r\n\r\n')
                        banner = s.recv(1024).decode('utf-8', errors='ignore').strip()
                        banner_snip = banner.split('\n')[0][:50]
                        return f"Port {p}: Open ({banner_snip})"
                    except:
                        return f"Port {p}: Open"
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_SCAN_THREADS) as ex:
            open_ports = list(filter(None, ex.map(check, ports)))
        self.results["recon"]["open_ports"] = open_ports

    def find_admin_pages(self):
        self.failed_admin_attempts = 0
        found = []
        def check(path):
            try:
                resp = self.session.get(urljoin(self.base_url, path), timeout=1.0, allow_redirects=False)
                if resp.status_code in [401, 403]:
                    self.failed_admin_attempts += 1
                if resp.status_code == 200: 
                    return path
            except: pass
        with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_SCAN_THREADS) as ex:
            found = list(filter(None, ex.map(check, ADMIN_PATHS)))
        self.results["recon"]["admin_pages_found"] = found

    def find_sensitive_files_smart(self):
        paths_to_check = list(SENSITIVE_PATHS)
        domain_parts = self.domain.split('.')
        base_name = domain_parts[0]
        
        extensions = ['.zip', '.tar.gz', '.sql', '.bak', '.old']
        for ext in extensions:
            paths_to_check.append(f"/{self.domain}{ext}")
            paths_to_check.append(f"/{base_name}{ext}")

        found = []
        def check(path):
            try:
                r = self.session.head(urljoin(self.base_url, path), timeout=1)
                if r.status_code == 200: 
                    ctype = r.headers.get("Content-Type", "")
                    if "html" not in ctype:
                        return path
            except: pass
            
        with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_SCAN_THREADS) as ex:
            found = list(filter(None, ex.map(check, paths_to_check)))
        self.results["recon"]["sensitive_files_found"] = found

    def check_idor_potential(self):
        idor_candidates = []
        for link in self.results["recon"].get("crawled_links", []):
            parsed = urlparse(link)
            params = parse_qsl(parsed.query)
            for name, value in params:
                if value.isdigit():
                    idor_candidates.append(f"{link} (Param: {name}={value})")
        
        self.results["vulnerabilities"]["Broken_Access_Control_IDOR"] = idor_candidates if idor_candidates else ["No obvious numeric ID parameters found"]

    def check_robots_txt(self):
        try:
            resp = self.session.get(urljoin(self.base_url, "/robots.txt"), timeout=2)
            self.results["recon"]["robots_txt_disallowed"] = re.findall(r"Disallow: (.*)", resp.text) if resp.status_code == 200 else ["Not found"]
        except: 
            self.results["recon"]["robots_txt_disallowed"] = ["Error retrieving robots.txt"]

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

    def check_command_injection(self):
        issues = []
        test_url = f"{self.base_url}/"
        risk_params = ['ip', 'host', 'cmd', 'file', 'query'] 
        
        for param in risk_params:
            for payload in COMMAND_INJECTION_PAYLOADS:
                try:
                    target = f"{test_url}?{param}={payload}"
                    resp = self.session.get(target, timeout=1.5)
                    if "vulnerable" in resp.text or "uid=" in resp.text:
                        issues.append(f"Param '{param}' reflected payload: {payload}")
                        break
                except: pass
        
        self.results["vulnerabilities"]["A03_Command_Injection"] = issues if issues else ["No simple Command Injection detected"]

    def check_security_headers(self):
        h = self.initial_response.headers
        missing = [k for k in SECURITY_HEADERS if k not in h]
        self.results["vulnerabilities"]["A05_Security_Misconfig_Headers"] = {
            "present": [k for k in SECURITY_HEADERS if k in h],
            "missing": missing
        }

    def check_crypto_failures(self):
        issues = []
        if not self.base_url.startswith("https"):
            issues.append("Site is not served over HTTPS.")
        
        if "Strict-Transport-Security" not in self.initial_response.headers:
            issues.append("Missing 'Strict-Transport-Security' (HSTS) header.")

        insecure_cookies = []
        jar = self.session.cookies
        if hasattr(jar, "_cookies"):
            for domain, path_dict in jar._cookies.items():
                for path, cookies in path_dict.items():
                    for name, cookie in cookies.items():
                        if not getattr(cookie, "secure", False):
                            insecure_cookies.append(f"Cookie '{name}' missing 'Secure' flag.")

                        rest = getattr(cookie, "rest", None) or getattr(cookie, "_rest", {})
                        has_httponly = False
                        if isinstance(rest, dict):
                            if any(k.lower() == "httponly" for k in rest.keys()):
                                has_httponly = True
                            if rest.get("httponly") or rest.get("HttpOnly"):
                                has_httponly = True

                        if not has_httponly and getattr(cookie, "httponly", False):
                            has_httponly = True

                        if not has_httponly:
                            insecure_cookies.append(f"Cookie '{name}' missing 'HttpOnly' flag.")
        else:
            for name, _value in jar.items():
                insecure_cookies.append(f"Cookie '{name}' present but cookie flags could not be inspected.")

        if insecure_cookies:
            issues.extend(insecure_cookies)

        self.results["vulnerabilities"]["A02_Cryptographic_Failures"] = issues

    def check_vulnerable_components(self):
        h = self.initial_response.headers
        components = {}
        if "Server" in h:
            components["Server"] = h["Server"]
        if "X-Powered-By" in h:
            components["X-Powered-By"] = h["X-Powered-By"]
        self.results["vulnerabilities"]["A06_Vulnerable_Components"] = components

    def check_broken_access_control(self):
        if self.results["recon"].get("admin_pages_found"):
            self.results["vulnerabilities"]["A01_Broken_Access_Control"] = "Found administrative page paths. Manual review required to check if access control is enforced."
        else:
            self.results["vulnerabilities"]["A01_Broken_Access_Control"] = "No obvious admin path found."

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
        self.results["vulnerabilities"]["A01_Open_Redirect"] = issues if issues else ["No simple Open Redirect found."]

    def check_injection_forms(self):
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
                                injection_detected.append(f"Potential {key} SQLi on {action_url} in field '{field}'")
                        except requests.RequestException:
                            continue
                            
        self.results["vulnerabilities"]["A03_Injection"] = injection_detected if injection_detected else ["No simple SQLi detected."]

    def check_xss_reflection(self):
        test_url = f"{self.base_url}/?q={XSS_PAYLOAD}"
        
        if self.oast_url:
            try:
                oast_test_url = f"{self.base_url}/?page={self.oast_url}&file={self.oast_url}"
                self.session.get(oast_test_url, timeout=1.5)
                self.results["info"]["oast_param_test"] = f"Sent payload to {oast_test_url}"
            except requests.RequestException:
                pass

        try:
            resp = self.session.get(test_url, timeout=3)
            if XSS_PAYLOAD in resp.text:
                self.results["vulnerabilities"]["A07_XSS"] = [f"Reflected XSS on param 'q'. Payload reflected in response."]
            else:
                self.results["vulnerabilities"]["A07_XSS"] = ["No simple reflected XSS detected."]
        except requests.RequestException as e:
            self.results["vulnerabilities"]["A07_XSS"] = [f"Error during XSS check: {e}"]

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

    def check_sri(self):
        issues = []
        try:
            soup = BeautifulSoup(self.initial_response.text, "html.parser")
            for script in soup.find_all("script", src=True):
                if script['src'].startswith("http") and self.domain not in script['src']:
                    if not script.get("integrity"): 
                        issues.append(f"Script missing SRI: {script['src']}")
        except: pass
        self.results["vulnerabilities"]["A06_Missing_SRI"] = issues if issues else ["All external resources appear to have integrity checks."]

    def check_clickjacking(self):
        h = self.initial_response.headers
        if "X-Frame-Options" not in h and "frame-ancestors" not in h.get("Content-Security-Policy", ""):
            self.results["vulnerabilities"]["A05_Clickjacking"] = ["Missing 'X-Frame-Options' and CSP 'frame-ancestors'."]
        else:
            self.results["vulnerabilities"]["A05_Clickjacking"] = ["Protected"]

    def check_directory_listing(self):
        self.results["vulnerabilities"]["A05_Directory_Listing"] = ["No directory listings found (Passive check)"]

    def calculate_wma_threat(self):
        current_score = 0.0
        history = [0.0]
        
        check_results = [
            ("DNS Lookup", 0.05),
            ("Port Scan", 0.2 if self.results["recon"].get("open_ports") else 0.0),
            ("Admin Search", 0.4 if self.results["recon"].get("admin_pages_found") else 0.0),
            ("Vulnerability Scan", 0.8 if self.results["vulnerabilities"].get("A03_Injection") else 0.0)
        ]

        for label, weight in check_results:
            current_score = (weight * (1.0 - WMA_DECAY)) + (current_score * WMA_DECAY)
            current_score = max(0.0, min(1.0, current_score))
            history.append(round(current_score, 2))

        history = [max(0.0, min(1.0, float(val))) for val in history]
        is_blocked = current_score >= THRESHOLD_CRITICAL
        
        self.results["defense_sim"] = {
            "final_score": round(current_score, 2),
            "status": "BLOCKED" if is_blocked else "CLEAN",
            "ml_prediction": -1 if current_score > THRESHOLD_WARNING else 1,
            "is_blocked": is_blocked,
            "threat_history": history,
            "firewall_rule": f"iptables -A INPUT -s {self.results['recon'].get('ip_address', '0.0.0.0')} -j DROP" if is_blocked else "None"
        }
