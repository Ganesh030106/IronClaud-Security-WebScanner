import streamlit as st
from fpdf import FPDF

class PDF(FPDF):
    def header(self):
        self.set_font('Arial', 'B', 16)
        self.cell(0, 10, 'Web Application Security Scan Report', border=False, align='C')
        self.ln(15)
    
    def footer(self):
        self.set_y(-15)
        self.set_font('Arial', 'I', 8)
        self.cell(0, 10, f'Page {self.page_no()}', align='C')

    def chapter_title(self, title):
        self.set_font('Arial', 'B', 12)
        self.set_fill_color(200, 220, 255) # Light blue background
        # Use 'epw' (effective page width) to ensure we stay within margins
        self.cell(self.epw, 6, self.safe_text(title), 0, 1, align='L', fill=True)
        self.ln(4)

    def safe_text(self, text):
        """
        Sanitize text to Latin-1 to avoid FPDF Unicode errors.
        """
        if text is None:
            return ""
        # Replace complex characters with ? to prevent crashes
        return str(text).encode('latin-1', 'replace').decode('latin-1')

    def add_result_section(self, title, data):
        self.set_font('Arial', 'B', 10)
        # Use self.epw instead of 0 or hardcoded numbers
        self.multi_cell(self.epw, 5, self.safe_text(title), border=0, align='L')
        
        self.set_font('Arial', '', 9)
        
        if isinstance(data, list):
            if not data:
                self.multi_cell(self.epw, 5, "  - None found.")
            else:
                for item in data:
                    clean_item = self.safe_text(item)
                    self.multi_cell(self.epw, 5, f"  - {clean_item}")
        
        elif isinstance(data, dict):
            if not data:
                self.multi_cell(self.epw, 5, "  - None found.")
            else:
                for k, v in data.items():
                    clean_k = self.safe_text(k)
                    clean_v = self.safe_text(v)
                    self.multi_cell(self.epw, 5, f"  - {clean_k}: {clean_v}")
        
        else:
            self.multi_cell(self.epw, 5, f"  {self.safe_text(data)}")
        
        self.ln(3)

def create_pdf_report(results, domain):
    # Standard A4 page
    pdf = PDF(orientation='P', unit='mm', format='A4')
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()
    
    # --- Summary ---
    pdf.chapter_title('Scan Summary')
    pdf.add_result_section("Target Domain", domain)
    pdf.add_result_section("Target IP", results['recon'].get('ip_address', 'N/A'))
    pdf.add_result_section("Initial Status Code", str(results['info'].get('status_code', 'N/A')))
    
    # WAF Info
    waf = results['info'].get('waf_detected', 'N/A')
    if isinstance(waf, list):
        waf = ", ".join(waf)
    pdf.add_result_section("WAF Detected", waf)
    pdf.ln(5)

    # --- Reconnaissance ---
    pdf.chapter_title('Reconnaissance Results')
    pdf.add_result_section("Open Ports", results['recon'].get('open_ports', []))
    pdf.add_result_section("Admin Pages Found", results['recon'].get('admin_pages_found', []))
    pdf.add_result_section("Sensitive Files Found", results['recon'].get('sensitive_files_found', []))
    pdf.add_result_section("Subdomains (Passive)", results['recon'].get('subdomains', []))
    
    robots = results['recon'].get('robots_txt_disallowed', [])
    if isinstance(robots, str):
        robots = [robots]
    pdf.add_result_section("Robots.txt Disallowed", robots)
    
    js_files = results['recon'].get('js_files_found', [])
    pdf.add_result_section(f"JS Files Found ({len(js_files)})", js_files)
    pdf.ln(5)

    # --- Vulnerabilities ---
    pdf.chapter_title('Vulnerability Report')

    # Hardcoded Secrets
    secrets = results['vulnerabilities'].get('CRITICAL_Hardcoded_Secrets', [])
    if secrets:
        pdf.set_font('Arial', 'B', 10)
        pdf.set_text_color(200, 50, 50)
        pdf.multi_cell(pdf.epw, 5, "CRITICAL: Hardcoded Secrets Found!")
        pdf.set_text_color(0, 0, 0)
        pdf.set_font('Arial', '', 9)
        
        for secret in secrets:
            s_type = pdf.safe_text(secret.get('type', 'Unknown'))
            s_file = pdf.safe_text(secret.get('file', 'Unknown'))
            s_snip = pdf.safe_text(secret.get('snippet', 'Unknown'))
            
            pdf.multi_cell(pdf.epw, 5, f"  [!] Type: {s_type}")
            pdf.multi_cell(pdf.epw, 5, f"      File: {s_file}")
            pdf.multi_cell(pdf.epw, 5, f"      Snippet: {s_snip}")
            pdf.ln(2)
    else:
        pdf.add_result_section("Hardcoded Secrets", ["No obvious secrets found in JS files."])
    
    # Standard Vulns
    pdf.add_result_section("A01: Broken Access Control", results['vulnerabilities'].get('A01_Broken_Access_Control', 'No data'))
    
    or_issues = results['vulnerabilities'].get('A01_Open_Redirect', [])
    if not or_issues: or_issues = ["No simple Open Redirect found."]
    pdf.add_result_section("A01: Open Redirects", or_issues)

    a02_issues = results['vulnerabilities'].get('A02_Cryptographic_Failures', [])
    if not a02_issues: a02_issues = ["No obvious issues found."]
    pdf.add_result_section("A02: Cryptographic Failures", a02_issues)
    
    a03_issues = results['vulnerabilities'].get('A03_Injection', [])
    if not a03_issues or (isinstance(a03_issues, list) and "No simple" in str(a03_issues[0])):
        a03_issues = ["No obvious issues found."]
    pdf.add_result_section("A03: Injection", a03_issues)
    
    a05_missing = results['vulnerabilities'].get('A05_Security_Misconfig_Headers', {}).get('missing', [])
    if not a05_missing: a05_missing = ["All checked headers are present."]
    pdf.add_result_section("A05: Security Misconfiguration (Missing Headers)", a05_missing)

    a06_comps = results['vulnerabilities'].get('A06_Vulnerable_Components', {})
    if not a06_comps: a06_comps = {"Info": "No exposed components found."}
    pdf.add_result_section("A06: Vulnerable Components", a06_comps)
    
    a07_issues = results['vulnerabilities'].get('A07_XSS', [])
    if not a07_issues or (isinstance(a07_issues, list) and "No simple" in str(a07_issues[0])):
        a07_issues = ["No simple reflected XSS detected."]
    pdf.add_result_section("A07: Cross-Site Scripting (XSS)", a07_issues)
    
    return bytes(pdf.output(dest='S'))