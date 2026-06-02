import re
import requests
from bs4 import BeautifulSoup, Comment
from urllib.parse import urljoin, urlparse
from config import PII_REGEX, JS_DANGEROUS_SINKS, MUTATION_EXTENSIONS

class ContentAuditor:
    def __init__(self, session):
        self.session = session

    # --- Feature 1: PII Scanner ---
    def scan_for_pii(self, text, url):
        """
        Scans page content for Credit Cards, SSNs, etc.
        """
        findings = []
        for pii_type, pattern in PII_REGEX.items():
            matches = re.findall(pattern, text)
            for match in matches:
                # Basic Luhn check for Credit Cards to reduce false positives
                if pii_type == "Credit Card":
                    if not self._luhn_check(match.replace('-', '').replace(' ', '')):
                        continue 
                
                # Obfuscate the result for the report
                safe_match = match[:4] + "*" * (len(match) - 4)
                findings.append(f"{pii_type} found on {url}: {safe_match}")
        return findings

    def _luhn_check(self, card_number):
        """Validates credit card numbers using Luhn algorithm."""
        if not card_number.isdigit(): return False
        sum_val = 0
        num_digits = len(card_number)
        oddeven = num_digits & 1
        for count in range(0, num_digits):
            digit = int(card_number[count])
            if not ((count & 1) ^ oddeven):
                digit = digit * 2
            if digit > 9:
                digit = digit - 9
            sum_val = sum_val + digit
        return (sum_val % 10) == 0

    # --- Feature 2: Developer Comment Miner ---
    def extract_comments(self, html, url):
        """
        Extracts HTML comments that might contain 'TODO', 'FIXME', or sensitive info.
        """
        findings = []
        soup = BeautifulSoup(html, "html.parser")
        comments = soup.find_all(string=lambda text: isinstance(text, Comment))
        
        interesting_keywords = ["todo", "fixme", "bug", "password", "auth", "key", "db", "test"]
        
        for c in comments:
            comment_text = c.strip().lower()
            # If comment contains interesting keywords or is long
            if any(k in comment_text for k in interesting_keywords) or len(comment_text) > 10:
                snippet = c.strip()[:60] + "..." if len(c.strip()) > 60 else c.strip()
                findings.append(f"Interesting Comment on {url}: {snippet}")
        return findings

    # --- Feature 3: Smart Mutation Fuzzer ---
    def fuzz_discovered_files(self, discovered_links):
        """
        Takes links found by the crawler (e.g., /admin/login.php) 
        and checks for backup versions (e.g., /admin/login.php.bak).
        """
        findings = []
        files_to_fuzz = [link for link in discovered_links if "." in urlparse(link).path and not urlparse(link).path.endswith("/")]
        
        for file_url in files_to_fuzz[:10]:
            for ext in MUTATION_EXTENSIONS:
                fuzz_url = f"{file_url}{ext}"
                try:
                    resp = self.session.head(fuzz_url, timeout=1.5)
                    if resp.status_code == 200:
                        if "html" not in resp.headers.get("Content-Type", ""):
                            findings.append(f"Backup File Found: {fuzz_url}")
                except: pass
        return findings

    # --- Feature 4: Mixed Content & Dangerous JS ---
    def check_page_security(self, html, url):
        """
        Checks for Mixed Content (HTTP on HTTPS) and Dangerous JS Sinks.
        """
        findings = []
        soup = BeautifulSoup(html, "html.parser")
        
        # 1. Mixed Content
        if url.startswith("https"):
            for tag in soup.find_all(['script', 'img', 'iframe', 'link'], src=True):
                if tag['src'].startswith("http://"):
                    findings.append(f"Mixed Content (Insecure Resource): {tag['src']}")
            for tag in soup.find_all('link', href=True):
                 if tag['href'].startswith("http://"):
                    findings.append(f"Mixed Content (Insecure CSS/Link): {tag['href']}")

        # 2. Dangerous JS Sinks (Static Analysis)
        scripts = soup.find_all('script')
        for script in scripts:
            if script.string: # Inline script
                for sink in JS_DANGEROUS_SINKS:
                    if sink in script.string:
                        findings.append(f"Dangerous JS Sink '{sink}' found in inline script.")
                
        return findings
