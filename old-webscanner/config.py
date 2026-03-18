# --- Configuration & Payloads ---

# --- NEW: Regex for finding secrets ---
# This is a list of common patterns for API keys and secrets.
SECRET_REGEX = {
    "Google API Key": r"AIza[0-9A-Za-z-_]{35}",
    "Amazon AWS Key": r"AKIA[0-9A-Z]{16}",
    "Stripe Live Key": r"sk_live_[0-9a-zA-Z]{24}",
    "Stripe Test Key": r"sk_test_[0-9a-zA-Z]{24}",
    "GitHub Token": r"ghp_[0-9a-zA-Z]{36}",
    "Slack Token": r"xox[bpa]-[0-9a-zA-Z]{10,48}",
    "Generic High Entropy (test)": r"['\"]([A-Za-z0-9+/]{30,60})['\"]"
}

# Common admin paths for the admin page finder
ADMIN_PATHS = [
    "/admin", "/admin/login.php", "/administrator", "/login", "/wp-admin", 
    "/admin.php", "/admin/login", "/cp", "/panel", "/adminpanel"
]

# --- NEW ---
# Common sensitive files and directories
SENSITIVE_PATHS = [
    "/.env", "/.git/config", "/.aws/credentials", "/.ssh/id_rsa",
    "/config/config.json", "/backup.sql", "/db_backup.zip", "/app.log"
]
# Basic payloads for injection checks. 
# ... (rest of the file is unchanged) ...

# Basic payloads for injection checks. 
# These are educational and detect simple, classic vulnerabilities.
SQLI_PAYLOADS = {
    "Error-Based": "' OR '1'='1",
    "Boolean-Based": "' AND '1'='1"
}

# Basic XSS payload for reflection checks
XSS_PAYLOAD = "<script>console.log('XSS-Test')</script>"

# Headers to check for Security Misconfiguration
SECURITY_HEADERS = [
    "Content-Security-Policy",
    "Strict-Transport-Security",
    "X-Content-Type-Options",
    "X-Frame-Options",
    "Referrer-Policy",
    "Permissions-Policy"
]

# --- Educational Content ---

MITIGATIONS = {
    "A01": ("**Info:** Broken Access Control (BAC) happens when users can access resources or perform actions they shouldn't be able to. Finding an '/admin' page is just a hint; the real test is trying to access it without being an admin.\n\n"
            "**Mitigation:** Enforce access control checks on the server for *every* request. Deny by default. Use role-based access control (RBAC)."),
    "A02": ("**Info:** This category covers failures related to cryptography, like using weak ciphers, missing encryption (HTTP), or insecure cookie settings.\n\n"
            "**Mitigation:** Always use HTTPS. Enable HSTS (`Strict-Transport-Security` header) to enforce it. Set `Secure` and `HttpOnly` flags on all session cookies."),
    "A03": ("**Info:** Injection flaws, like SQL Injection (SQLi), occur when untrusted data is sent to an interpreter as part of a command or query. A basic error message can reveal that the application is vulnerable.\n\n"
            "**Mitigation:** Use parameterized queries (prepared statements) to separate data from commands. Validate and sanitize all user input."),
    "A05": ("**Info:** This is a broad category for missing or incorrect security configurations. Missing headers are a common example, as they fail to enable browser-level security features.\n\n"
            "**Mitigation:** Implement a strong `Content-Security-Policy` (CSP). Add all recommended security headers (`X-Content-Type-Options`, `X-Frame-Options`, etc.). Disable directory listing and remove default credentials."),
    "A06": ("**Info:** Using components (libraries, frameworks) with known vulnerabilities. Publicly visible version numbers (`Server`, `X-Powered-By`) make it easy for attackers to find exploits.\n\n"
            "**Mitigation:** Remove or obscure version headers. Regularly scan dependencies for known vulnerabilities (e.g., using `npm audit`, `pip-audit`) and patch them."),
    "A07": ("**Info:** Cross-Site Scripting (XSS) happens when untrusted data is included in a web page without proper validation, allowing attackers to run scripts in the user's browser.\n\n"
            "**Mitigation:** Context-aware output encoding is the primary defense. Encode all user-supplied data before rendering it in HTML. A strong CSP can also be a powerful secondary defense.")
}