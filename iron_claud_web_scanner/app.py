import streamlit as st
import json
import pandas as pd
from scanner import OWASPTester
import time # For log timestamp parsing
from config import MITIGATIONS
import warnings

# Silence noisy third-party regex warnings from Wappalyzer signatures
warnings.filterwarnings(
    "ignore",
    message="Caught 'unbalanced parenthesis",
    category=UserWarning,
    module="Wappalyzer.Wappalyzer",
)


# --- Streamlit UI Configuration ---

st.set_page_config(
    
    layout="wide", 
    page_title="IronClad Security Scanner",
    page_icon="https://img.icons8.com/fluency/96/security-shield-green.png",
    initial_sidebar_state="expanded"
)

# --- THEME INJECTION: CYBERSECURITY COMMAND CENTER ---
st.markdown("""
<style>
    /* --- GLOBAL SETTINGS --- */
    @import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&display=swap');
    
    .stApp {
        background-color: #050505;
        background-image: radial-gradient(circle at 50% 50%, #111111 0%, #050505 100%);
        font-family: 'Share Tech Mono', monospace;
        color: #e0e0e0;
    }

    /* --- HEADERS --- */
    h1 {
        color: #00ff41 !important;
        font-family: 'Share Tech Mono', monospace !important;
        text-shadow: 0 0 10px rgba(0, 255, 65, 0.7);
        letter-spacing: 2px;
        text-transform: uppercase;
        border-bottom: 2px solid #00ff41;
        padding-bottom: 10px;
    }
    
    h2, h3 {
        color: #00d2ff !important;
        font-family: 'Share Tech Mono', monospace !important;
        text-shadow: 0 0 5px rgba(0, 210, 255, 0.5);
    }

    /* --- SIDEBAR --- */
    section[data-testid="stSidebar"] {
        background-color: #0a0a0a;
        border-right: 1px solid #333;
    }

    /* --- INPUT FIELDS --- */
    .stTextInput > div > div > input {
        background-color: #000;
        color: #00ff41;
        border: 1px solid #333;
        font-family: 'Share Tech Mono', monospace;
    }
    .stTextInput > div > div > input:focus {
        border-color: #00ff41;
        box-shadow: 0 0 10px rgba(0, 255, 65, 0.2);
    }

    /* --- BUTTONS --- */
    .stButton > button {
        background: transparent;
        color: #00ff41;
        border: 1px solid #00ff41;
        font-family: 'Share Tech Mono', monospace;
        font-size: 16px;
        text-transform: uppercase;
        transition: all 0.3s ease;
        width: 100%;
    }
    .stButton > button:hover {
        background: rgba(0, 255, 65, 0.1);
        box-shadow: 0 0 15px rgba(0, 255, 65, 0.5);
        border-color: #fff;
        color: #fff;
    }

    /* --- METRICS CARDS --- */
    div[data-testid="stMetric"] {
        background-color: #0f0f0f;
        border: 1px solid #333;
        padding: 15px;
        border-radius: 5px;
        border-left: 5px solid #00d2ff;
        box-shadow: 0 4px 6px rgba(0,0,0,0.3);
    }
    div[data-testid="stMetricLabel"] {
        color: #888;
        font-size: 14px;
    }
    div[data-testid="stMetricValue"] {
        color: #fff;
        font-family: 'Share Tech Mono', monospace;
        text-shadow: 0 0 5px #fff;
    }

    /* --- TABS --- */
    .stTabs [data-baseweb="tab-list"] {
        gap: 5px;
        border-bottom: 1px solid #333;
    }
    .stTabs [data-baseweb="tab"] {
        background-color: #0a0a0a;
        border: 1px solid #333;
        border-bottom: none;
        color: #888;
        border-radius: 5px 5px 0 0;
    }
    .stTabs [aria-selected="true"] {
        background-color: #00ff41 !important;
        color: #000 !important;
        font-weight: bold;
        box-shadow: 0 0 10px rgba(0, 255, 65, 0.5);
    }

    /* --- EXPANDERS --- */
    .streamlit-expanderHeader {
        background-color: #111;
        border: 1px solid #333;
        color: #00d2ff;
        font-family: 'Share Tech Mono', monospace;
    }
    
    /* --- ALERTS (Success/Error/Warning) --- */
    .stSuccess {
        background-color: rgba(0, 255, 65, 0.1);
        border: 1px solid #00ff41;
        color: #00ff41;
    }
    .stError {
        background-color: rgba(255, 0, 85, 0.1);
        border: 1px solid #ff0055;
        color: #ff0055;
    }
    .stWarning {
        background-color: rgba(255, 204, 0, 0.1);
        border: 1px solid #ffcc00;
        color: #ffcc00;
    }
    .stInfo {
        background-color: rgba(0, 210, 255, 0.1);
        border: 1px solid #00d2ff;
        color: #00d2ff;
    }

    /* --- DATAFRAMES & JSON --- */
    div[data-testid="stDataFrame"] {
        border: 1px solid #333;
    }
    
    /* --- CODE BLOCKS --- */
    code {
        color: #ff0055;
        background-color: #111;
        font-family: 'Share Tech Mono', monospace;
    }
</style>
""", unsafe_allow_html=True)

# --- APPLICATION LOGIC ---
# Main content area
st.title(" 🛡️ IRONCLAD SECURITY SCANNER")
st.caption(" ")
st.caption("ADVANCED PENTRATION TESTING SUITE \\ SYSTEM READY \\ TARGET ACQUISITION MODE ENGAGED")
st.markdown("---")

col_input, col_btn = st.columns([4, 1])
with col_input:
    target_url = st.text_input("TARGET_URL >", placeholder="https://target-system.com")
with col_btn:
    st.write("") # Spacer
    st.write("") # Spacer
    start_scan = st.button("🚀 INITIALIZE")

    
if start_scan and target_url:
    if not (target_url.startswith("http://") or target_url.startswith("https://")):
        st.error("❌ ERROR: INVALID PROTOCOL. TARGET MUST START WITH HTTP:// OR HTTPS://")
    else:
        try:
            with st.spinner("⚡ SCANNING TARGET INFRASTRUCTURE... PLEASE WAIT"):
                scanner = OWASPTester(target_url)
                results = scanner.run_all_checks()
                st.session_state.scan_results = results 
                st.session_state.scanner_domain = scanner.domain
            
            st.success(f"✅ TARGET ACQUIRED & SCANNED: {scanner.domain}")

            
            
            # --- Display Results in Tabs ---
            tab_dash, tab_ai, tab_defense, tab_infra, tab_content, tab_recon, tab_vuln, tab_headers, tab_data, tab_fix, tab_export = st.tabs([
            "📊 DASHBOARD",
            "🧠 AI Firewall", 
            "🛡️ DEFENSE", 
            "🌐 INFRASTRUCTURE", 
            "📄 CONTENT",  
            "🔎 RECON",     
            "🚨 VULNERABILITIES", 
            "🍪 HEADERS", 
            "🕸️ CRAWL DATA", 
            "✅ REMEDIATION",  
            "📤 EXPORT" 
            ])


            # --- DASHBOARD TAB ---
            with tab_dash:
    
                # Key Metrics
                d1, d2, d3, d4 = st.columns(4)
                d1.metric("STATUS CODE", results["info"].get("status_code"))
                
                # Display WAF separately now
                # Show WAF status
                waf = results["info"].get("waf_detected", "None")
                waf_display = ", ".join(waf) if isinstance(waf, list) else waf
                d2.metric("WAF DETECTED", waf_display)
                
                # Show Tech Stack count
                d3.metric("TECH STACK", len(results["recon"].get("tech_stack", [])))
                
                # Show Secrets count
                secrets_len = len(results["vulnerabilities"].get("CRITICAL_Hardcoded_Secrets", []))
                d4.metric("SECRETS FOUND", secrets_len, delta_color="inverse" if secrets_len == 0 else "normal")
                
                st.markdown("---")

                # HTTP/2 Check
                c1, c2, c3, c4 = st.columns(4)
                
                http2 = results["info"].get("http2_enabled")
                protocol_display = "HTTP/2 ⚡" if http2 else "HTTP/1.1 ⚠️"
                
                c1.metric("PROTOCOL", protocol_display)
                c2.metric("SUBDOMAINS", len(results["recon"].get("subdomains", [])))
                c3.metric("OPEN PORTS", len(results["recon"].get("open_ports", [])))
                c4.metric("API ENDPOINTS", len(results["recon"].get("api_endpoints", [])))
                
                # Charts
                st.markdown("### 📈 THREAT VISUALIZATION")
                col_a, col_b = st.columns(2)
                with col_a:
                    st.caption("VULNERABILITY DISTRIBUTION")
                    # Filter out "No issues" for cleaner chart
                    vuln_counts = {}
                    for k, v in results["vulnerabilities"].items():
                        if isinstance(v, list) and (not v or "No " in str(v[0])): continue
                        if isinstance(v, str) and "No " in v: continue
                        vuln_counts[k] = len(v) if isinstance(v, list) else 1
                    
                    if vuln_counts: st.bar_chart(vuln_counts)
                    else: st.info("NO MAJOR VULNERABILITIES DETECTED.")
                
                with col_b:
                    st.caption("ASSET DISCOVERY")
                    recon_stats = {
                        "Subdomains": len(results["recon"].get("subdomains", [])),
                        "Emails": len(results["recon"].get("emails_found", [])),
                        "JS Files": len(results["recon"].get("js_files_found", [])),
                        "Open Ports": len(results["recon"].get("open_ports", []))
                    }
                    st.bar_chart(recon_stats)

                st.markdown("---")

                st.subheader("📋 ADDITIONAL FINDINGS LOG")
                # Loop for any remaining unchecked items
                handled_keys = [
                    "CRITICAL_Hardcoded_Secrets", "A01_Open_Redirect", "A01_Broken_Access_Control",
                    "A02_Cryptographic_Failures", "A03_Injection", "A05_Security_Misconfig_Headers",
                    "A06_Vulnerable_Components", "A07_XSS"
                ]
                
                for cat, data in results["vulnerabilities"].items():
                    if cat in handled_keys: continue
                    
                    # Check if safe to skip
                    is_safe = False
                    if isinstance(data, list) and (not data or "No " in str(data[0])): is_safe = True
                    if isinstance(data, str) and "No " in data: is_safe = True

                    if not is_safe:
                        with st.expander(f"🔴 {cat}", expanded=True):
                            st.write(data)
                    else:
                        with st.expander(f"🟢 {cat} (SECURE)"):
                            st.write(data)

            # --- TAB 7: AI FIREWALL (New) ---
            with tab_ai:
                st.header("🧠 AI Powered Traffic Anomaly Detection")
                st.caption("Machine Learning model (Isolation Forest) that learns normal traffic patterns and blocks outliers.")

                # Status Panel
                col1, col2 = st.columns([1, 2])
                with col1:
                    st.subheader("System Status")
                    
                    # Check if log file exists to guess status
                    try:
                        with open('ai_firewall_events.log', 'r') as f:
                            logs = f.read()
                            if "AI Model Trained Successfully" in logs:
                                st.success("✅ **AI Model:** TRAINED & ACTIVE")
                                st.metric("Protection Mode", "Blocking Anomalies")
                            else:
                                st.warning("⚠️ **AI Model:** LEARNING")
                                st.metric("Protection Mode", "Data Collection")
                                st.info("Run `python ai_firewall.py` to start.")
                    except:
                        st.error("❌ AI Module Offline")
                        st.info("Run `python ai_firewall.py` in terminal.")

                with col2:
                    st.subheader("📊 Feature Analysis")
                    st.markdown("The AI monitors these features to detect anomalies:")
                    st.code("""Features = [
                        "Body Length",        # Detect Buffer Overflows / Large Payloads
                        "Header Count",       # Detect Header Stuffing / Abnormal Clients
                        "URI Length",         # Detect Buffer Overflows / LFI
                        "Param Count",        # Detect Parameter Pollution
                        "Special Char Count"  # Detect SQLi / XSS / Injection
                    ]
                    """, language="python")

                st.divider()

                # Live Anomaly Log
                st.subheader("🚨 Detected Anomalies")
                try:
                    with open('ai_firewall_events.log', 'r') as f:
                        lines = f.readlines()
                        anomalies = [line for line in lines if "ANOMALY BLOCKED" in line]
                        
                        if anomalies:
                            for log in reversed(anomalies[-10:]):
                                st.error(log.strip())
                        else:
                            st.success("No traffic anomalies detected yet.")
                except:
                    st.write("No logs available.")
            
            # --- DEFENSE & PATCHING (New) ---
            with tab_defense:
                st.header("🛡️ VIRTUAL PATCHING & HARDENING")
                st.caption("AUTO-GENERATED CONFIGURATIONS TO NEUTRALIZE DETECTED THREATS.")
                
                # 1. Traffic Anomaly Status
                st.subheader("🚦 TRAFFIC CONTROL STATUS")
                c1, c2 = st.columns(2)
                with c1:
                    rl = results["vulnerabilities"].get("A05_Rate_Limiting", {})
                    if rl.get("status") == "Vulnerable":
                        st.error(f"**RATE LIMITING:** FAILED\n\n{rl.get('details')}")
                    else:
                        st.success(f"**RATE LIMITING:** PASS\n\n{rl.get('details')}")
                
                with c2:
                    bot = results["vulnerabilities"].get("A06_Bot_Protection", {})
                    if bot.get("status") == "Vulnerable":
                        st.error(f"**BOT DETECTION:** FAILED\n\n{bot.get('details')}")
                    else:
                        st.success(f"**BOT DETECTION:** PASS\n\n{bot.get('details')}")

                st.divider()
                
                # 2. Server Hardening (Headers)
                st.subheader("🔧 SERVER HARDENING (HEADERS)")
                configs = results.get("defense_configs", {}).get("headers", {})
                
                if configs.get("nginx"):
                    st.text("NGINX CONFIGURATION (nginx.conf):")
                    st.code(configs["nginx"], language="nginx")
                    
                    st.text("APACHE CONFIGURATION (.htaccess):")
                    st.code(configs["apache"], language="apache")
                else:
                    st.success("HEADERS SECURE. NO CONFIGURATION NEEDED.")

                # 3. WAF Rules
                st.subheader("🔥 WAF RULES (ModSecurity)")
                waf = results.get("defense_configs", {}).get("waf", "")
                st.code(waf, language="apache")
            
                # 4. Live WAF Monitor
                
                st.header("🏰 IRONCLAD WAF MONITOR")
                st.caption("LIVE PACKET INSPECTION & ANOMALY BLOCKING.")
                
                col1, col2 = st.columns([1, 3])
                
                with col1:
                    st.metric("STATUS", "ACTIVE", "PORT 8080")
                    st.info("RUN `python ironclad_waf.py` TO START PROXY.")
                
                with col2:
                    st.subheader("🛡️ LIVE ATTACK STREAM")
                    try:
                        # Read the last 20 lines of the log file
                        with open('waf_events.log', 'r') as f:
                            lines = f.readlines()
                            if lines:
                                last_logs = lines[-10:]
                                for log in reversed(last_logs):
                                    if "BANNED" in log:
                                        st.error(f"⛔ {log.strip()}")
                                    else:
                                        st.warning(f"⚠️ {log.strip()}")
                            else:
                                st.write("NO ATTACKS DETECTED YET.")
                    except FileNotFoundError:
                        st.warning("LOG FILE NOT FOUND. WAF OFFLINE?")

                st.divider()
                st.subheader("⚙️ ACTIVE RULESET")
                st.json({
                    "SQL Injection": "BLOCK (UNION/SELECT)",
                    "XSS Protection": "BLOCK (<script>)",
                    "Rate Limiting": "20 REQ / MIN",
                    "Bot Ban Duration": "600 SECONDS",
                    "Honeypot Field": "csrf_debug_token_hidden"
                })
            
            # --- TAB 2: INFRASTRUCTURE (New Features) ---
            with tab_infra:
                st.header("INFRASTRUCTURE AUDIT")
                
                col_a, col_b = st.columns(2)
                
                with col_a:
                    st.subheader("☁️ CLOUD & STORAGE")
                    buckets = results["recon"].get("cloud_buckets", [])
                    if buckets and "No public" not in buckets[0]:
                        st.error(f"🚨 {len(buckets)} EXPOSED BUCKETS FOUND!")
                        for b in buckets: st.code(b)
                    else:
                        st.success("NO EXPOSED CLOUD BUCKETS.")

                    st.subheader("🔗 API DISCOVERY")
                    apis = results["recon"].get("api_endpoints", [])
                    if apis and "No common" not in apis[0]:
                        for api in apis: st.info(api)
                    else:
                        st.caption("NO STANDARD API ENDPOINTS DISCOVERED.")

                with col_b:
                    st.subheader("🌐 NETWORK & DNS")
                    
                    # Subdomains
                    subs = results["recon"].get("subdomains", [])
                    with st.expander(f"SUBDOMAINS FOUND ({len(subs)})"):
                        st.write(subs)
                    
                    # Zone Transfer
                    axfr = results["vulnerabilities"].get("A05_DNS_Zone_Transfer", [])
                    if "SUCCESS" in str(axfr):
                         st.error("🚨 CRITICAL: DNS ZONE TRANSFER ALLOWED!")
                         st.write(axfr)
                    else:
                        st.caption("DNS ZONE TRANSFER: SECURE")

                    # Email Security
                    email_sec = results["vulnerabilities"].get("A05_Email_Spoofing_Risks", [])
                    if "Secure" not in str(email_sec):
                        st.warning("⚠️ EMAIL SPOOFING RISKS DETECTED")
                        st.write(email_sec)
                
                #-- Active Injection Modules Section ---
                st.header("💣 ACTIVE INJECTION MODULES")
                st.warning("WARNING: THESE MODULES ACTIVELY EXPLOIT THE TARGET.")
                
                col1, col2, col3 = st.columns(3)
                
                with col1:
                    st.subheader("SSTI (TEMPLATE INJECTION)")
                    ssti = results["vulnerabilities"].get("A03_SSTI", [])
                    if ssti:
                        st.error("🚨 CRITICAL: SSTI CONFIRMED")
                        for s in ssti: st.write(s)
                    else:
                        st.success("NO SSTI PATTERNS.")

                with col2:
                    st.subheader("BLIND SQL INJECTION")
                    bsqli = results["vulnerabilities"].get("A03_Blind_SQL_Injection", [])
                    if bsqli:
                        st.error("🚨 CRITICAL: TIME-BASED SQLi")
                        for b in bsqli: st.write(b)
                    else:
                        st.success("NO DELAYS DETECTED.")

                with col3:
                    st.subheader("CRLF / HEADER INJECTION")
                    crlf = results["vulnerabilities"].get("A03_CRLF_Injection", [])
                    if crlf:
                        st.error("⚠️ CRLF INJECTION POSSIBLE")
                        for c in crlf: st.write(c)
                    else:
                        st.success("HEADERS SECURE.")
                
                st.divider()
                st.subheader("SPECIALIZED VECTORS")
                
                # Move Host Header & Prototype Pollution here
                c4, c5 = st.columns(2)
                with c4:
                    st.write("**HOST HEADER INJECTION:**")
                    hh = results["vulnerabilities"].get("A01_Host_Header_Injection", [])
                    if "Server appears" in str(hh): st.success("SECURE")
                    else: st.error(hh)
                    
                with c5:
                     st.write("**PROTOTYPE POLLUTION:**")
                     pp = results["vulnerabilities"].get("A03_Prototype_Pollution", [])
                     if pp: st.error(pp)
                     else: st.success("NO POLLUTION PATTERNS.")

            # --- TAB 3: CONTENT & PII (New Features) ---
            with tab_content:
                st.header("CONTENT & DATA MINING")
                
                c_pii, c_files = st.columns(2)
                
                with c_pii:
                    st.subheader("🕵️ PII & SECRETS")
                    pii = results["vulnerabilities"].get("A04_PII_Exposure", [])
                    if pii and "No PII" not in pii[0]:
                        st.error("🚨 PII EXPOSURE DETECTED")
                        for item in pii: st.write(f"- {item}")
                    else:
                        st.success("NO PII PATTERNS FOUND.")
                        
                    st.subheader("📝 DEVELOPER COMMENTS")
                    comments = results["vulnerabilities"].get("A05_Developer_Comments", [])
                    with st.expander(f"VIEW COMMENTS ({len(comments)})"):
                         for c in comments: st.code(c, language="html")

                with c_files:
                    st.subheader("📂 SENSITIVE FILES")
                    
                    # Smart Backups
                    backups = results["vulnerabilities"].get("A05_Sensitive_Backup_Files", [])
                    if backups:
                        st.error("🚨 BACKUP FILES FOUND!")
                        for b in backups: st.write(f"[{b}]({b})")
                    else:
                        st.info("NO BACKUP FILES FOUND.")
                    
                    # Robots.txt
                    robots_acc = results["recon"].get("robots_txt_accessible", [])
                    with st.expander("ROBOTS.TXT HIDDEN PATHS"):
                        for r in robots_acc: st.write(r)


            # --- RECON TAB ---
            with tab_recon:
                c1, c2 = st.columns(2)
            
                # Tech Stack
                with c1:
                    st.subheader("🛠️ TECHNOLOGY STACK")
                    tech_dict = results["recon"].get("tech_stack", {})
                    if tech_dict:
                        # Convert dict to simple dataframe for display
                        t_df = pd.DataFrame(list(tech_dict.items()), columns=["Technology", "Version"])
                        st.dataframe(t_df, width="stretch")
                    else:
                        st.info("NO SPECIFIC TECHNOLOGIES DETECTED.")
                    st.markdown("---")

                # SSL Info
                with c2:
                    st.subheader("🔒 SSL CERTIFICATE")
                    ssl_info = results["recon"].get("ssl_info", {})
                    if ssl_info.get("valid"):
                        st.success(f"VALID. DAYS REMAINING: {ssl_info.get('days_remaining')}")
                        st.caption(f"ISSUED BY: {ssl_info.get('issued_by')}")
                        st.caption(f"EXPIRES ON: {ssl_info.get('expires_on')}")
                    else:
                        st.error(f"SSL ERROR: {ssl_info.get('error', 'Unknown')}")
                    st.markdown("---")
                
                # Emails
                st.subheader("📧 DISCOVERED EMAILS")
                emails = results["recon"].get("emails_found", [])
                if emails:  st.write(", ".join(emails))
                else: st.info("NO EMAILS FOUND.")
                st.markdown("---")

                # Add Subdomains Section
                st.subheader("PASSIVE DNS SUBDOMAINS")
                st.markdown("FROM CERTIFICATE TRANSPARENCY LOGS (crt.sh).")
                subs = results["recon"].get("subdomains", [])
                if subs and isinstance(subs, list):
                    with st.expander(f"VIEW {len(subs)} SUBDOMAINS"):
                        st.write(subs)
                else:
                    st.info(f"{subs}")
                st.markdown("---")

                # --- Sitemap Section ---
                st.subheader("SITEMAP ENTRIES")
                sitemap = results["recon"].get("sitemap_entries", [])
                if sitemap and "not found" not in sitemap[0]:
                    with st.expander(f"VIEW {len(sitemap)} PAGES"):
                        st.write(sitemap)
                else: st.info("SITEMAP NOT FOUND.")

                st.markdown("---")

                # --- Target Info Section ---
                st.subheader("TARGET METADATA")
                col1, col2 = st.columns(2)
                col1.metric("DOMAIN", scanner.domain)
                col2.metric("IP ADDRESS", results["recon"].get("ip_address", "N/A"))

                st.markdown("---")

                # --- Open Ports Section ---
                st.subheader("OPEN NETWORK PORTS")
                st.info(f"**PORTS:** {results['recon'].get('open_ports') or 'None detected in common list.'}")

                st.markdown("---")

                # --- Admin Pages Section ---
                st.subheader("POTENTIAL ADMIN PANELS")
                st.info(f"**PATHS:** {results['recon'].get('admin_pages_found') or 'No common admin paths found.'}")

                st.markdown("---")

                # --- Sensitive Files Section ---
                st.subheader("SENSITIVE FILE EXPOSURE")
                sensitive_files = results['recon'].get('sensitive_files_found', [])
                if sensitive_files:
                    st.error(f"**FILES FOUND:** {sensitive_files}")
                else:
                    st.info("**FILES FOUND:** None detected in common list.")
                st.markdown("---")

                # --- Show robots.txt disallowed entries ---
                st.subheader("ROBOTS.TXT DISALLOW RULES")
                st.info(f"**PATHS:** {results['recon'].get('robots_txt_disallowed') or 'Not found or no entries.'}")

                # --- Show JS files found ---
                st.subheader("JAVASCRIPT ASSETS")
                js_files = results['recon'].get('js_files_found', [])
                st.info(f"**COUNT:** {len(js_files)} FILES.")
                with st.expander("VIEW JS FILE LIST"):
                    st.text_area("JS List", "\n".join(js_files), height=200, label_visibility="collapsed")
                st.markdown("---")
                with st.expander("WHOIS DATA"):
                    st.text(results["recon"].get("whois", "Error"))
                
                
            
            # Vulnerability Report Tab

            with tab_vuln:

                # Add Open Redirect Section
                st.subheader("**OPEN REDIRECT**")
                
                or_issues = results['vulnerabilities'].get('A01_Open_Redirect', [])
                if not or_issues or "No simple" in or_issues[0]:
                    st.success("🟢 NO ISSUES DETECTED")
                else:
                    st.error("🔴 HIGH RISK")
                    for issue in or_issues:
                        st.write(f"- {issue}")
                    with st.expander("REMEDIATION"):
                        st.markdown(MITIGATIONS["A01_Open_Redirect"])

                st.markdown("---")

                # --- Command Injection Section ---
                st.subheader("**OS COMMAND INJECTION**")
                cmd_issues = results['vulnerabilities'].get('A03_Command_Injection', [])
                if not cmd_issues or "No simple" in cmd_issues[0]:
                    st.success("🟢 NO ISSUES DETECTED")
                else:
                    st.error("🔴 CRITICAL VULNERABILITY")
                    for issue in cmd_issues:
                        st.write(f"- {issue}")
                    with st.expander("REMEDIATION"):
                        st.markdown("**Mitigation:** Use prepared statements. Validate input.")
                st.markdown("---")

                # ---  Clickjacking Section ---
                st.subheader("CLICKJACKING PROTECTION")
                clickjacking = results['vulnerabilities'].get('A05_Clickjacking', [])
                if not clickjacking or "Protected" in clickjacking[0]:
                    st.success("🟢 PROTECTED")
                else:
                    st.warning("🟡 VULNERABILITY DETECTED")
                    for issue in clickjacking:
                        st.write(f"- {issue}")
                    st.markdown("**Mitigation:** Add `X-Frame-Options: SAMEORIGIN` header.")
                st.markdown("---")

                # --- Directory Listing Section ---
                st.subheader("DIRECTORY LISTING")
                dir_listing = results['vulnerabilities'].get('A05_Directory_Listing', [])
                if not dir_listing or "No directory" in dir_listing[0]:
                    st.success("🟢 SECURE")
                else:
                    st.warning("🟡 ENABLED (RISK)")
                    for url in dir_listing:
                        st.write(f"- {url}")
                    with st.expander("REMEDIATION"):
                        st.markdown("Disable `Options +Indexes` in web server config.")

                st.markdown("---")
                
                # --- CORS Section ---
                st.subheader("CORS MISCONFIGURATION")
                cors_issues = results['vulnerabilities'].get('A05_CORS_Misconfiguration', [])
                if not cors_issues or "No obvious" in cors_issues[0]:
                    st.success("🟢 SECURE")
                else:
                    st.warning("🟡 ISSUES DETECTED")
                    for issue in cors_issues:
                        st.write(f"- {issue}")
                    with st.expander("REMEDIATION"):
                        st.markdown("Avoid wildcards in Access-Control-Allow-Origin.")
                st.markdown("---")

                # --- SRI Section ---
                st.subheader("SUBRESOURCE INTEGRITY (SRI)")
                sri_issues = results['vulnerabilities'].get('A06_Missing_SRI', [])
                if not sri_issues or (sri_issues and "All external" in str(sri_issues[0])):
                    st.success("🟢 GOOD")
                else:
                    st.warning("🟡 MISSING ON SOME RESOURCES")
                    # Show only first 5 to avoid clutter if there are many
                    for issue in sri_issues[:5]:
                        st.write(f"- {issue}")
                    if len(sri_issues) > 5:
                        st.caption(f"...and {len(sri_issues)-5} more.")
                    with st.expander("REMEDIATION"):
                        st.markdown(MITIGATIONS["A06_Missing_SRI"])
                
                st.markdown("---")

                # --- Critical Secrets Findings ---
                st.subheader("CRITICAL FINDINGS")
                st.subheader("**HARDCODED SECRETS**")
                
                secrets = results['vulnerabilities'].get('CRITICAL_Hardcoded_Secrets', [])
                if secrets:
                    st.error("🚨 **CRITICAL: SECRETS EXPOSED** 🚨")
                    st.caption("**IMMEDIATE ROTATION REQUIRED**")
                    for secret in secrets:
                        st.warning(f"**TYPE:** `{secret['type']}` | **FILE:** `{secret['file']}`\n**MATCH:** `{secret['snippet']}`")
                else:
                    st.success("✅ NO SECRETS IN JS FILES.")
                    st.markdown("---")
                
                # A01 Broken Access Control

                st.subheader(" **A01: BROKEN ACCESS CONTROL**")
                a01_finding = results['vulnerabilities'].get('A01_Broken_Access_Control', '')
                if "Found" in a01_finding:
                    st.error("🔴 POTENTIAL RISK")
                    st.caption(f"**DETAIL:** {a01_finding}")
                    with st.expander("REMEDIATION"):
                        st.markdown(MITIGATIONS["A01"])
                else:
                    st.success("🟢 NO OBVIOUS ISSUES")
                st.markdown("------")
                
                # A02 Cryptographic Failures
                st.subheader(" **A02: CRYPTOGRAPHIC FAILURES**")
                a02_issues = results['vulnerabilities'].get('A02_Cryptographic_Failures', [])

                if a02_issues:
                    st.error("🔴 HIGH RISK")
                    st.caption("**DETAILS:**")
                    for issue in a02_issues:  st.write(f"- {issue}")
                    with st.expander("REMEDIATION"):
                        st.markdown(MITIGATIONS["A02"])
                else:
                    st.success("🟢 SECURE")
                st.markdown("------")
                
                # A03 Injection & Command Injection

                st.subheader(" **A03: INJECTION**")
                
                a03_issues = results['vulnerabilities'].get('A03_Injection', [])
                cmd_issues = results['vulnerabilities'].get('A03_Command_Injection', [])
                if (not a03_issues or "No simple" in a03_issues[0]) and (not cmd_issues or "No simple" in cmd_issues[0]):
                    st.success("🟢 NO OBVIOUS ISSUES")
                else:
                    st.error("🔴 CRITICAL RISK")
                    if cmd_issues and "No simple" not in cmd_issues[0]:
                        st.markdown("**COMMAND INJECTION DETECTED:**")
                        for i in cmd_issues: st.write(f"- {i}")
                        st.info(MITIGATIONS["A03_Command_Injection"])
                    if a03_issues and "No simple" not in a03_issues[0]:
                        st.markdown("**SQL INJECTION DETECTED:**")
                        for i in a03_issues: st.write(f"- {i}")
                    with st.expander("REMEDIATION"):    
                        st.markdown(MITIGATIONS["A03"])

                st.markdown("---")
                
                # A05 Security Misconfiguration 
                st.subheader(" **A05: SECURITY MISCONFIGURATION**")
                
                a05_missing = results['vulnerabilities'].get('A05_Security_Misconfig_Headers', {}).get('missing', [])
                if a05_missing:
                    st.warning(f"🟡 MEDIUM RISK")
                    st.caption("**MISSING HEADERS:**")
                    for h in a05_missing: st.write(f"- `{h}`")
                    with st.expander("REMEDIATION"):    
                        st.markdown(MITIGATIONS["A05"])
                else:
                    st.success("🟢 GOOD")
                st.markdown("---")
                
                # A06 Vulnerable Components
                st.subheader(" **A06: VULNERABLE COMPONENTS**")
                
                a06_comps = results['vulnerabilities'].get('A06_Vulnerable_Components', {})
                if a06_comps:
                    st.warning("🟡 INFORMATIONAL")
                    st.caption("**EXPOSED INFO:**")
                    for k, v in a06_comps.items():
                        st.write(f"- `{k}: {v}`")
                    with st.expander("REMEDIATION"):
                        st.markdown(MITIGATIONS["A06"])
                else:
                    st.success("🟢 GOOD")
                st.markdown("---")

                # A07 XSS
                st.subheader(" **A07: CROSS-SITE SCRIPTING (XSS)**")
                
                a07_issues = results['vulnerabilities'].get('A07_XSS', [])
                if not a07_issues or "No simple" in a07_issues[0]:
                    st.success("🟢 NO OBVIOUS ISSUES")
                else:
                    st.error("🔴 HIGH RISK")
                    st.caption("**DETAILS:**")
                    for issue in a07_issues:
                        st.write(f"- {issue}")
                    with st.expander("REMEDIATION"):
                        st.markdown(MITIGATIONS["A07"])
                
                st.markdown("---")

            # --- HEADERS & COOKIES TAB ---
            with tab_headers:
                st.subheader("🍪 COOKIES")
                cookies = results["details"].get("cookies", [])
                if cookies:
                    st.dataframe(pd.DataFrame(cookies))
                else:
                    st.info("NO COOKIES FOUND.")
                
                st.markdown("---")

                st.subheader("📡 RESPONSE HEADERS")
                st.json(results["details"].get("response_headers", {}))
                
                st.markdown("---")
                st.subheader("📤 REQUEST HEADERS")
                st.json(results["details"].get("request_headers", {}))

            # --- Crawl Tab ---
            with tab_data:
                st.subheader("CRAWLED LINKS MAP")
                st.write(f"FOUND {len(results['recon'].get('crawled_links', []))} NODES:")
                st.text_area(
                    label="Crawled Links List", 
                    value="\n".join(results['recon'].get('crawled_links', [])), 
                    height=400,
                    label_visibility="collapsed" 
                )
            
            # --- NEW: MITIGATION PLAN TAB ---
            with tab_fix:
                st.subheader("✅ REMEDIATION CHECKLIST")
                st.markdown("PRIORITIZED ACTION PLAN:")
                
                checklist = []
                # Check Secrets
                st.subheader("HARDCODED SECRETS")
                if results['vulnerabilities'].get('CRITICAL_Hardcoded_Secrets'):
                    checklist.append("🔴 **REVOKE API KEYS:** SECRETS FOUND IN JS. ROTATE IMMEDIATELY.")
                
                # Check Headers
                st.subheader("HEADERS & CONFIG")
                missing = results['vulnerabilities'].get('A05_Security_Misconfig_Headers', {}).get('missing', [])
                if missing:
                    checklist.append(f"🟡 **ADD HEADERS:** CONFIGURE: {', '.join(missing)}")
                
                # Check SSL
                st.subheader("SSL / TLS")
                ssl_data = results['recon'].get('ssl_info', {})
                if ssl_data.get('days_remaining', 365) < 30:
                    checklist.append(f"🟡 **RENEW SSL:** EXPIRES IN {ssl_data.get('days_remaining')} DAYS.")
                
                # Check Clickjacking
                st.subheader("CLICKJACKING")
                click = results['vulnerabilities'].get('A05_Clickjacking', [])
                if click and "Protected" not in click[0]:
                    checklist.append("🟡 **DENY FRAMING:** ADD 'X-Frame-Options: DENY'.")

                
                st.subheader("SUMMARY")
                if not checklist:
                    st.success("🎉 SYSTEM SECURE. NO MAJOR ACTIONS.")
                else:
                    for item in checklist:
                        st.markdown(f"- {item}")
                    
                    st.markdown("---")

            # --- Export Tab ---
            with tab_export:
                st.subheader("REPORT GENERATION")
                
                # 1. JSON Export
                json_data = json.dumps(results, indent=2)
                
                # 2. CSV Export (Flattening the data)
                # We create a simple summary CSV
                csv_rows = []
                
                # Add General Info
                csv_rows.append({"Category": "Info", "Item": "Target", "Value": results["info"].get("target")})
                csv_rows.append({"Category": "Info", "Item": "IP", "Value": results["recon"].get("ip_address")})
                
                # Add Open Ports
                for p in results["recon"].get("open_ports", []):
                    csv_rows.append({"Category": "Recon", "Item": "Open Port", "Value": p})
                
                # Add Vulnerabilities (Simplified)
                for cat, val in results["vulnerabilities"].items():
                    if isinstance(val, list):
                        for v in val:
                            # Clean up the text for CSV
                            clean_v = str(v).replace('\n', ' ').strip()
                            csv_rows.append({"Category": "Vulnerability", "Item": cat, "Value": clean_v})
                    elif isinstance(val, dict):
                        # Handle header dicts
                        if "missing" in val:
                            for m in val["missing"]:
                                csv_rows.append({"Category": "Vulnerability", "Item": f"{cat} (Missing)", "Value": m})
                
                df = pd.DataFrame(csv_rows)
                csv_data = df.to_csv(index=False).encode('utf-8')
                
                col1, col2 = st.columns(2)

                st.subheader("RAW JSON OUTPUT")
                json_data = json.dumps(results, indent=2)
                st.code(json_data, language="json")
                col1, col2 = st.columns(2)
                
                with col1:
                    st.download_button(
                        label="DOWNLOAD JSON REPORT",
                        data=json_data,
                        file_name=f"{scanner.domain}_report.json",
                        mime="application/json",
                        width="stretch"
                    )
                
                with col2:
                    st.download_button(
                        label="DOWNLOAD CSV REPORT",
                        data=csv_data,
                        file_name=f"{scanner.domain}_report.csv",
                        mime="text/csv",
                        width="stretch"
                    )

        except Exception as e:
            st.error(f"SYSTEM FAILURE: {e}")
            # print details to console for debugging
            print(e)

elif start_scan:
    st.warning("AWAITING TARGET INPUT...")