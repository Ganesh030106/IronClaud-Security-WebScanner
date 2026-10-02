from config import SECURITY_HEADERS

class DefenseGenerator:
    def __init__(self):
        pass

    # --- Feature 3: Header Hardening Configs ---
    def generate_header_fixes(self, missing_headers):
        """
        Generates Nginx and Apache config snippets to add missing headers.
        """
        nginx_conf = []
        apache_conf = []
        
        defaults = {
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
            "X-Frame-Options": "SAMEORIGIN",
            "X-Content-Type-Options": "nosniff",
            "Content-Security-Policy": "default-src 'self';",
            "Referrer-Policy": "strict-origin-when-cross-origin",
            "Permissions-Policy": "geolocation=(), microphone=()"
        }

        for header in missing_headers:
            val = defaults.get(header, "value")
            nginx_conf.append(f'add_header {header} "{val}";')
            apache_conf.append(f'Header always set {header} "{val}"')
            
        return {
            "nginx": "\n".join(nginx_conf),
            "apache": "\n".join(apache_conf)
        }

    # --- Feature 4: WAF Rule Generator (Virtual Patching) ---
    def generate_waf_rules(self, vulnerabilities):
        """
        Generates ModSecurity rules for specific vulnerabilities found.
        """
        modsec_rules = []
        
        sqli = vulnerabilities.get("A03_Injection", [])
        blind_sqli = vulnerabilities.get("A03_Blind_SQL_Injection", [])
        
        if (sqli and "No simple" not in str(sqli)) or (blind_sqli):
            modsec_rules.append("# BLOCK SQL INJECTION")
            modsec_rules.append('SecRule ARGS "@detectSQLi" "id:1001,phase:2,deny,status:403,msg:\'Virtual Patch: SQL Injection Detected\'"')

        xss = vulnerabilities.get("A07_XSS", [])
        if xss and "No simple" not in str(xss):
            modsec_rules.append("# BLOCK XSS")
            modsec_rules.append('SecRule ARGS "@detectXSS" "id:1002,phase:2,deny,status:403,msg:\'Virtual Patch: XSS Detected\'"')

        if any("etc/passwd" in str(v) for v in vulnerabilities.values()) or vulnerabilities.get("A03_Path_Traversal_LFI"):
            modsec_rules.append("# BLOCK PATH TRAVERSAL / LFI")
            modsec_rules.append(r'SecRule ARGS "@rx \.\.\/|\.\.\\|etc\/passwd|win\.ini" "id:1003,phase:2,deny,status:403,msg:\'Virtual Patch: Path Traversal\'"')

        ssrf = vulnerabilities.get("A10_SSRF", [])
        if ssrf and "No SSRF" not in str(ssrf):
            modsec_rules.append("# BLOCK SSRF / CLOUD METADATA")
            modsec_rules.append(r'SecRule ARGS "@rx 169\.254\.169\.254|metadata\.google|127\.0\.0\.1|localhost" "id:1004,phase:2,deny,status:403,msg:\'Virtual Patch: SSRF Detected\'"')

        nosql = vulnerabilities.get("A03_NoSQL_Injection", [])
        if nosql and "No NoSQL" not in str(nosql):
            modsec_rules.append("# BLOCK NOSQL OPERATOR INJECTION")
            modsec_rules.append(r'SecRule ARGS "@rx \$ne|\$gt|\$where|\$regex" "id:1005,phase:2,deny,status:403,msg:\'Virtual Patch: NoSQL Operator Injection\'"')

        xxe = vulnerabilities.get("A08_XXE_Injection", [])
        if xxe and "No XML" not in str(xxe):
            modsec_rules.append("# BLOCK XXE / EXTERNAL ENTITIES")
            modsec_rules.append(r'SecRule REQUEST_BODY "@rx <!ENTITY|SYSTEM\s*\"file:" "id:1006,phase:2,deny,status:403,msg:\'Virtual Patch: XXE Detected\'"')

        if not modsec_rules:
            return "No critical vulnerabilities requiring specific WAF rules found."
        
        return "\n".join(modsec_rules)

