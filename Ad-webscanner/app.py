import streamlit as st
import json
from scanner import OWASPTester
from config import MITIGATIONS
from pdf_report import create_pdf_report


# --- Streamlit UI ---

st.set_page_config(layout="wide", page_title="Web App Security Scanner")
st.title("Web Application Security Scanner")
st.caption("An educational tool for learning about web vulnerabilities. **Use only on targets you are authorized to test.**")


# --- UI Layout ---

# Main content area
st.header("🎯 Target")
target_url = st.text_input("Enter URL:", placeholder="http://example.com")
    
start_scan = st.button("🚀 Start Scan")
if start_scan and target_url:
    if not (target_url.startswith("http://") or target_url.startswith("https://")):
        st.error("Invalid URL. Must start with http:// or https://")
    else:
        try:
            scanner = OWASPTester(target_url)
            results = scanner.run_all_checks()
            st.session_state.scan_results = results 
            st.session_state.scanner_domain = scanner.domain
            
            st.success(f"Scan complete for {scanner.domain}")
            
            # --- Display Results in Tabs ---

            
            # --- Tab list --- 
            tab_recon, tab_vuln, tab_crawl, tab_defense, tab_export = st.tabs([
                "💡 Reconnaissance", "🚨 Vulnerability Report", "🕸️ Crawl Data", "🛡️ AI Defense Sim", "📄 Raw JSON"
            ])


            # Recon Tab
            with tab_recon:
                st.subheader("Target Info")
                col1, col2 = st.columns(2)
                col1.metric("Domain", scanner.domain)
                col2.metric("IP Address", results["recon"].get("ip_address", "N/A"))

                st.subheader("Open Network Ports")
                st.markdown("These are like open doors on your server. Common ports are 80 (HTTP) and 443 (HTTPS). Other open ports might be for databases or other services that should ideally not be public.")
                st.info(f"**Open Ports Found:** {results['recon'].get('open_ports') or 'None detected in common list.'}")

                st.subheader("Potential Admin Pages")
                st.markdown("Finding an admin page isn't a vulnerability, but it's a high-value target for attackers. This list shows common paths that responded successfully.")
                st.info(f"**Pages Found:** {results['recon'].get('admin_pages_found') or 'No common admin paths found.'}")

                # --- NEW ---
                st.subheader("Potential Sensitive Files")
                st.markdown("These are files that should not be public (like `.env` or `.git` files). If any are found, they should be secured immediately.")
                sensitive_files = results['recon'].get('sensitive_files_found', [])
                if sensitive_files:
                    st.error(f"**Sensitive Files Found:** {sensitive_files}")
                else:
                    st.info("**Sensitive Files Found:** None detected in common list.")
                

                st.subheader("Robots.txt Disallowed Entries")
                st.markdown("This file tells search engines what not to crawl. It can sometimes reveal sensitive paths that the owner wants to hide.")
                st.info(f"**Disallowed Paths:** {results['recon'].get('robots_txt_disallowed') or 'Not found or no entries.'}")

                # --- Show JS files found ---
                st.subheader("JavaScript Files Found")
                st.markdown("These files were crawled and scanned for hardcoded secrets.")
                js_files = results['recon'].get('js_files_found', [])
                st.info(f"**JS Files Found:** {len(js_files)} files.")
                with st.expander("Show JS File List"):
                    st.text_area("JavaScript File List", "\n".join(js_files), height=200, label_visibility="collapsed")

                with st.expander("WHOIS Lookup"):
                    st.text(results["recon"].get("whois", "Error"))

            # Vulnerability Scan Tab
            with tab_vuln:
                # Inside tab_vuln in app.py
                st.header("Shield Status: Attacks Detected & Prevented")
                
                # Mapping our new detections to the UI
                attack_map = {
                    "DDoS_Detection": "🚫 DDoS Attack Prevention",
                    "Port_Scan_Detected": "🔒 Port Scan Blocking",
                    "Brute_Force_Attack": "🔑 Brute Force Mitigation",
                    "Malware_C2_Communication": "🦠 Malware C2 Interception",
                    "Data_Exfiltration": "📡 Data Leak Prevention"
                }

                for key, label in attack_map.items():
                    data = results["vulnerabilities"].get(key)
                    if data:
                        with st.expander(f"{label} - {data['status']}", expanded=True):
                            st.error(f"**Threat:** {data['reason']}")
                            st.success(f"**Action:** IP {results['recon']['ip_address']} has been automatically **BLOCKED** via AI Firewall Rules.")
                            st.code(f"iptables -A INPUT -s {results['recon']['ip_address']} -j DROP", language="bash")
                    else:
                        st.write(f"✅ {label}: No threats detected.")

                st.subheader("OWASP Top 10 Report Card")
                st.markdown("---")

                # --- Critical Secrets Findings ---
                secrets = results['vulnerabilities'].get('CRITICAL_Hardcoded_Secrets', [])
                if secrets:
                    st.error("🚨 **CRITICAL: Hardcoded Secrets Found!** 🚨")
                    st.markdown("""
                    **What this means:** Your public JavaScript files contain text that
                    looks like an API key or a password. This is extremely dangerous.
                    An attacker can use these secrets to take over your accounts,
                    steal your data, or incur massive costs on your behalf.
                    """)
                    st.caption("**Immediate Action Required:**")
                    for secret in secrets:
                        st.warning(f"**Type:** `{secret['type']}`\n"
                                f"**File:** `{secret['file']}`\n"
                                f"**Secret:** `{secret['snippet']}`")
                    with st.expander("How to Fix"):
                        st.markdown("""
                        1.  **Invalidate Immediately:** Go to the service provider (e.g., AWS, Stripe) and
                            revoke or delete this key **NOW**.
                        2.  **Remove from Code:** Delete the secret from your source code.
                        3.  **Use Environment Variables:** Store all secrets in a `.env` file or
                            your server's secure environment variables. Your code should
                            load the secret from the environment (`os.environ.get("MY_KEY")`),
                            not have it written in the code.
                        4.  **Check Git History:** Ensure this secret is not in your `git` history.
                            If it is, you must rotate the key and clean your history.
                        """)
                else:
                    st.success("✅ **Hardcoded Secrets:** No obvious secrets found in JavaScript files.")
                st.markdown("---")
                
                # A01
                a01_finding = results['vulnerabilities'].get('A01_Broken_Access_Control', '')
                if "Found" in a01_finding:
                    st.error("🔴 **A01: Broken Access Control:** Potential Risk")
                    st.markdown("**What this means:** We found a page like `/admin` that was accessible. This *could* mean that sensitive parts of your site are not properly protected, allowing unauthorized users to see or change data.")
                    st.caption(f"**Technical Detail:** {a01_finding}")
                else:
                    st.success("🟢 **A01: Broken Access Control:** No Obvious Issues")
                    st.markdown("**What we checked:** We looked for common admin-related paths (`/admin`, `/panel`, etc.) and did not find any that were obviously accessible.")
                with st.expander("Learn More & How to Fix"):
                    st.markdown(MITIGATIONS["A01"])
                st.markdown("---")
                
                # A02
                a02_issues = results['vulnerabilities'].get('A02_Cryptographic_Failures', [])
                if a02_issues:
                    st.error("🔴 **A02: Cryptographic Failures:** High Risk")
                    st.markdown("**What this means:** Your website has issues with encryption. This could mean data sent by your users (like passwords or credit cards) is not protected and could be stolen by attackers.")
                    st.caption("**Technical Details:**")
                    for issue in a02_issues:
                        st.write(f"- {issue}")
                else:
                    st.success("🟢 **A02: Cryptographic Failures:** Secure")
                    st.markdown("**What we checked:** Your site appears to use HTTPS correctly and doesn't have basic issues with its security headers (like HSTS) or cookie flags.")
                with st.expander("Learn More & How to Fix"):
                    st.markdown(MITIGATIONS["A02"])
                st.markdown("---")
                
                # A03
                a03_issues = results['vulnerabilities'].get('A03_Injection', [])
                if not a03_issues or "No simple" in a03_issues[0]:
                    st.success("🟢 **A03: Injection:** No Obvious Issues")
                    st.markdown("**What we checked:** We sent basic SQL injection payloads to forms on your site and did not receive a database error, suggesting you are not vulnerable to this simple test.")
                else:
                    st.error("🔴 **A03: Injection:** Critical Risk")
                    st.markdown("**What this means:** Your website may be vulnerable to SQL Injection. An attacker could potentially use this flaw to steal, change, or delete your entire database.")
                    st.caption("**Technical Details:**")
                    for issue in a03_issues:
                        st.write(f"- {issue}")
                with st.expander("Learn More & How to Fix"):
                    st.markdown(MITIGATIONS["A03"])
                st.markdown("---")
                
                # A05
                a05_missing = results['vulnerabilities'].get('A05_Security_Misconfig_Headers', {}).get('missing', [])
                if a05_missing:
                    st.warning(f"🟡 **A05: Security Misconfiguration:** Medium Risk")
                    st.markdown("**What this means:** Your server is **missing key security headers**. These headers are free, easy-to-add instructions that tell browsers how to protect your users from common attacks like clickjacking and code injection.")
                    st.caption("**Missing Headers:**")
                    for h in a05_missing:
                        st.write(f"- `{h}`")
                else:
                    st.success("🟢 **A05: Security Misconfiguration:** Good")
                    st.markdown("**What we checked:** Your server is configured with all the recommended security headers we looked for.")
                with st.expander("Learn More & How to Fix"):
                    st.markdown(MITIGATIONS["A05"])
                st.markdown("---")
                
                # A06
                a06_comps = results['vulnerabilities'].get('A06_Vulnerable_Components', {})
                if a06_comps:
                    st.warning("🟡 **A06: Vulnerable Components:** Informational")
                    st.markdown("**What this means:** Your server is publicly announcing what software and version it runs (e.g., `Server: Apache/2.4.1`). This is like giving a burglar a blueprint of your alarm system, making it easier for them to find a known exploit.")
                    st.caption("**Exposed Information:**")
                    for k, v in a06_comps.items():
                        st.write(f"- `{k}: {v}`")
                else:
                    st.success("🟢 **A06: Vulnerable Components:** Good")
                    st.markdown("**What we checked:** Your server does not seem to be revealing its software versions in common headers like `Server` or `X-Powered-By`.")
                with st.expander("Learn More & How to Fix"):
                    st.markdown(MITIGATIONS["A06"])
                st.markdown("---")

                # A07
                a07_issues = results['vulnerabilities'].get('A07_XSS', [])
                if not a07_issues or "No simple" in a07_issues[0]:
                    st.success("🟢 **A07: Cross-Site Scripting (XSS):** No Obvious Issues")
                    st.markdown("**What we checked:** We tried a basic reflected XSS payload in the URL and did not see it reflected on the page.")
                else:
                    st.error("🔴 **A07: Cross-Site Scripting (XSS):** High Risk")
                    st.markdown("**What this means:** Your site seems to take user input (from a URL) and print it directly to the page. An attacker could use this to create a malicious link that steals other users' session cookies or redirects them to a phishing site.")
                    st.caption("**Technical Details:**")
                    for issue in a07_issues:
                        st.write(f"- {issue}")
                with st.expander("Learn More & How to Fix"):
                    st.markdown(MITIGATIONS["A07"])
                pass
            
            # Crawl Tab
            with tab_crawl:
                st.subheader("Crawled Links")
                st.write(f"Found {len(results['recon'].get('crawled_links', []))} links:")
                st.text_area(
                    label="Crawled Links List", # Descriptive label for accessibility
                    value="\n".join(results['recon'].get('crawled_links', [])), 
                    height=400,
                    label_visibility="collapsed" # Hides the label from the UI
                )
                pass
            
            # AI Defense Simulation Tab
            with tab_defense:
                st.subheader("🛡️ Live Firewall Console")
                sim = results.get("defense_sim", {})
                ml_pred = sim.get("ml_prediction")
                if ml_pred == -1:
                    st.markdown("### ML Model Output: `[-1] ANOMALY DETECTED`")
                else:
                    st.markdown("### ML Model Output: `[1] NORMAL TRAFFIC`")
                
                # Create a scrolling log box
                logs = results.get("firewall_logs", [])
                log_text = "\n".join(logs)
                
                st.text_area("System Events", value=log_text, height=300, label_visibility="collapsed")
                
                sim = results.get("defense_sim", {})
                # Add a "Kill Switch" simulation
                if sim.get("is_blocked"):
                    st.error("🔥 SYSTEM ALERT: Active Attack Blocked")
                    if st.button("Manually Release IP Block"):
                        st.info("Release command sent to iptables.")
                
                st.subheader("AI Threat Analysis (WMA Model)")
                            
                # 1. Show the final score as a gauge/progress bar
                score = sim.get("final_score", 0.0)
                # Sanitize score to prevent infinity values
                if isinstance(score, float) and (score == float('inf') or score == float('-inf')):
                    score = 0.0
                score = max(0.0, min(1.0, float(score)))
                st.write(f"**Final Threat Probability:** {int(score*100)}%")
                st.progress(score)
                
                # 2. THE CHART: This generates the visual progression
                st.markdown("#### Threat Score Progression")
                history_data = sim.get("threat_history", [0])
                
                # Sanitize chart data to prevent infinity values
                history_data = [max(0.0, min(1.0, float(val) if not (isinstance(val, float) and (val == float('inf') or val == float('-inf'))) else 0.0)) for val in history_data]
                
                # We use st.line_chart which automatically handles the list
                st.line_chart(history_data)
                
                st.caption("X-Axis: Scan Sequence | Y-Axis: Threat Level (0.0 - 1.0)")
                
                # 3. Status Results
                status = sim.get("status")
                if status == "BLOCKED":
                    st.error(f"🛑 **Action:** IP Address {st.session_state.scan_results['recon'].get('ip_address')} has been dropped.")
                    st.code(sim.get("firewall_rule"), language="bash")
                else:
                    st.success("✅ **Action:** No immediate blocking required.")

            # Export Tab
            with tab_export:
                st.subheader("Raw JSON Output")
                json_data = json.dumps(results, indent=2)
                st.code(json_data, language="json")
                # st.download_button(
                #     label="Download Report",
                #     data=json_data,
                #     file_name=f"{scanner.domain}_report.json",
                #     mime="application/json"
                # )
                # --- MODIFIED ---
                # Add columns for side-by-side buttons
                col1, col2 = st.columns(2)
                
                with col1:
                    st.download_button(
                        label="Download JSON Report",
                        data=json_data,
                        file_name=f"{scanner.domain}_report.json",
                        mime="application/json",
                        use_container_width=True
                    )
                
                with col2:
                    # Create the PDF data
                    pdf_data = create_pdf_report(results, scanner.domain)
                    st.download_button(
                        label="Download PDF Report",
                        data=pdf_data,
                        file_name=f"{scanner.domain}_report.pdf",
                        mime="application/pdf",
                        use_container_width=True
                    )
                # --- END MODIFIED ---

                


        except Exception as e:
            st.error(f"An unexpected error occurred: {e}")

elif start_scan:
    st.warning("Please enter a URL to scan.")



# with tab_charts:
                #     st.subheader("📡 Live Network Traffic Monitoring")

                #     placeholder = st.empty()

                #     for _ in range(10):  # 10 updates
                #         scanner.update_live_metrics()

                #         with placeholder.container():
                #             st.line_chart(
                #                 st.session_state.traffic_data.set_index("Time")[["PPS", "SYN_Rate"]]
                #             )
                #             st.line_chart(
                #                 st.session_state.traffic_data.set_index("Time")[["Unique_IPs"]]
                #             )

                #         time.sleep(2)