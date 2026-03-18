import streamlit as st
from fpdf import FPDF
from fpdf.enums import Align  # Import the Align enum for clarity

# --- Constants ---
# Usable page width (A4 210mm - 20mm margins)
PAGE_WIDTH = 190 

class PDF(FPDF):
    def header(self):
        self.set_font('Arial', 'B', 12)
        self.cell(0, 10, 'Web Application Security Scan Report', 0, 1, align='C')
    
    def footer(self):
        self.set_y(-15)
        self.set_font('Arial', 'I', 8)
        self.cell(0, 10, f'Page {self.page_no()}', 0, 0, align='C')

    def chapter_title(self, title):
        self.set_font('Arial', 'B', 12)
        self.set_fill_color(200, 220, 255)
        self.cell(0, 6, title, 0, 1, align='L', fill=True)
        self.ln(4)

    def chapter_body(self, body):
        self.set_font('Arial', '', 10)
        self.multi_cell(PAGE_WIDTH, 5, body)
        self.ln()
        
    def add_result_section(self, title, data):
        self.set_font('Arial', 'B', 10)
        
        # --- FIX ---
        # Removed the '1' which was causing the "multiple values for argument" error
        # Old: self.multi_cell(PAGE_WIDTH, 5, title, 0, 1, align='L')
        self.multi_cell(PAGE_WIDTH, 5, title, border=0, align='L')
        # --- END FIX ---
        
        self.set_font('Arial', '', 9)
        
        if isinstance(data, list):
            if not data:
                self.multi_cell(PAGE_WIDTH, 5, "  - None found.")
            for item in data:
                self.multi_cell(PAGE_WIDTH, 5, f"  - {str(item)}")
        elif isinstance(data, dict):
            if not data:
                self.multi_cell(PAGE_WIDTH, 5, "  - None found.")
            for k, v in data.items():
                self.multi_cell(PAGE_WIDTH, 5, f"  - {k}: {v}")
        else:
            self.multi_cell(PAGE_WIDTH, 5, f"  {str(data)}")
        self.ln(2)

def create_pdf_report(results, domain):
    pdf = PDF()
    pdf.add_page()
    
    # --- Summary ---
    pdf.chapter_title('Scan Summary')
    pdf.add_result_section("Target Domain", domain)
    pdf.add_result_section("Target IP", results['recon'].get('ip_address', 'N/A'))
    pdf.add_result_section("Initial Status Code", str(results['info'].get('status_code', 'N/A')))
    pdf.ln(5)

    # --- Reconnaissance ---
    pdf.chapter_title('Reconnaissance Results')
    pdf.add_result_section("Open Ports", results['recon'].get('open_ports', []))
    pdf.add_result_section("Admin Pages Found", results['recon'].get('admin_pages_found', []))
    pdf.add_result_section("Sensitive Files Found", results['recon'].get('sensitive_files_found', []))
    pdf.add_result_section("Robots.txt Disallowed", results['recon'].get('robots_txt_disallowed', []))
    pdf.add_result_section("JS Files Found", results['recon'].get('js_files_found', []))
    pdf.ln(5)

    # --- Vulnerabilities ---
    pdf.chapter_title('Vulnerability Report')

    # --- Add secrets to PDF ---
    secrets = results['vulnerabilities'].get('CRITICAL_Hardcoded_Secrets', [])
    if secrets:
        pdf.set_font('Arial', 'B', 11)
        pdf.set_text_color(220, 50, 50) # Dark red
        pdf.multi_cell(PAGE_WIDTH, 5, "CRITICAL: Hardcoded Secrets Found!")
        pdf.set_text_color(0, 0, 0) # Reset color
        pdf.set_font('Arial', '', 9)
        for secret in secrets:
            pdf.multi_cell(PAGE_WIDTH, 5, 
                f"  - Type: {secret['type']}\n"
                f"  - File: {secret['file']}\n"
                f"  - Snippet: {secret['snippet']}"
            )
    else:
        pdf.add_result_section("Hardcoded Secrets", ["No obvious secrets found in JS files."])
    
    # --- Inside create_pdf_report function ---
    pdf.chapter_title('AI Firewall Simulation (Defensive View)')
    sim = results.get('defense_sim', {})
    
    status = "BLOCKED" if sim.get('is_blocked') else "ALLOWED"
    pdf.add_result_section("Firewall Decision", status)
    pdf.add_result_section("Threat Score", f"{int(sim.get('threat_score', 0)*100)}%")
    pdf.add_result_section("Detected Patterns", sim.get('detected_patterns', []))
    
    if sim.get('is_blocked'):
        pdf.add_result_section("Suggested Mitigation", f"Apply Rule: {sim.get('firewall_rule')}")
    
    # A01
    pdf.add_result_section("A01: Broken Access Control", results['vulnerabilities'].get('A01_Broken_Access_Control', 'No data'))
    
    # A02
    a02_issues = results['vulnerabilities'].get('A02_Cryptographic_Failures', [])
    if not a02_issues:
        a02_issues = ["No obvious issues found."]
    pdf.add_result_section("A02: Cryptographic Failures", a02_issues)
    
    # A03
    a03_issues = results['vulnerabilities'].get('A03_Injection', [])
    if not a03_issues or "No simple" in a03_issues[0]:
        a03_issues = ["No obvious issues found."]
    pdf.add_result_section("A03: Injection", a03_issues)
    
    # A05
    a05_missing = results['vulnerabilities'].get('A05_Security_Misconfig_Headers', {}).get('missing', [])
    if not a05_missing:
        a05_missing = ["All checked headers are present."]
    pdf.add_result_section("A05: Security Misconfiguration (Missing Headers)", a05_missing)

    # A06
    a06_comps = results['vulnerabilities'].get('A06_Vulnerable_Components', {})
    if not a06_comps:
        a06_comps = {"Info": "No exposed components found."}
    pdf.add_result_section("A06: Vulnerable Components (Exposed Info)", a06_comps)
    
    # A07
    a07_issues = results['vulnerabilities'].get('A07_XSS', [])
    if not a07_issues or "No simple" in a07_issues[0]:
        a07_issues = ["No simple reflected XSS detected."]
    pdf.add_result_section("A07: Cross-Site Scripting (XSS)", a07_issues)
    
    # Return as bytes
    return bytes(pdf.output(dest='S'))