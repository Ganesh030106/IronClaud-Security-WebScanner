# --- Configuration & Payloads ---


# --- AI Firewall Settings ---
AI_MODEL_CONTAMINATION = 0.05  # Approximate % of anomalies in training data
AI_TRAINING_SIZE = 50          # Requests needed to train the model (Low for demo purposes)
AI_SAVE_PATH = "ai_model.pkl"

# Features to extract from every request for ML analysis
AI_FEATURES = [
    "body_length",       # Size of the POST body
    "header_count",      # Number of headers
    "uri_length",        # Length of the URL
    "param_count",       # Number of URL parameters
    "special_char_count" # Count of potential attack chars (', ", <, >)
]


# --- BLOCKING RULES (Regex) ---
WAF_RULES = {
    "SQL_INJECTION": r"(?i)(\bunion\b.*\bselect\b|\bselect\b.*\bfrom\b|--|\'|\"|\b0x[0-9a-f]+\b)",
    "XSS": r"(?i)(<script|javascript:|on\w+=|document\.cookie|alert\()",
    "LFI_RCE": r"(?i)(\.\./|/etc/passwd|/bin/sh|cmd\.exe|\${)",
    "SHELLSHOCK": r"(?i)\(\)\s*\{",
    "JAVA_DESERIALIZATION": r"(?i)rO0AB"
}

# --- ANOMALY SETTINGS ---
RATE_LIMIT_THRESHOLD = 20  # Max requests per minute
BAN_DURATION = 600         # Ban for 10 minutes
HONEYPOT_FIELD_NAME = "csrf_debug_token_hidden" # If touched, INSTANT BAN


# --- Bad User Agents (Anomaly Traffic Simulation) ---
BAD_USER_AGENTS = [
    "sqlmap/1.4",
    "Nikto",
    "Mozilla/5.0 (compatible; Nmap Scripting Engine)",
    "python-requests/2.28", # Default scripts often blocked
    "acunetix"
]

# --- Defense Templates ---

# Templates to generate fixes
NGINX_HEADER_TEMPLATE = 'add_header {header} "{value}";'
APACHE_HEADER_TEMPLATE = 'Header always set {header} "{value}"'

# --- SSTI Payloads ---
# Expressions that different template engines (Jinja2, Twig, Freemarker) might evaluate
SSTI_PAYLOADS = {
    "Jinja2/Twig": ("{{7*7}}", "49"),
    "Spring/Java": ("${7*7}", "49"),
    "ERB/Ruby": ("<%= 7*7 %>", "49")
}

# --- CRLF Payloads ---
# Tries to inject a fake header
CRLF_PAYLOADS = [
    "/%0d%0aSet-Cookie:crlf=injection",
    "/%0aSet-Cookie:crlf=injection",
    "/%0dSet-Cookie:crlf=injection"
]

# --- Time-Based SQLi Payloads ---
# Payloads that ask the DB to pause. Key is the DB type.
TIME_BASED_SQLI = {
    "MySQL": "SLEEP(3)",
    "PostgreSQL": "pg_sleep(3)",
    "MSSQL": "WAITFOR DELAY '0:0:3'"
}
# --- GraphQL Introspection Query ---
GRAPHQL_INTROSPECTION_PAYLOAD = {
    "query": "query { __schema { types { name } } }"
}

# --- Host Header Injection Payloads ---
HOST_HEADER_PAYLOADS = [
    "evil.com",
    "google.com"
]

# --- Prototype Pollution Patterns (Regex) ---
# Looks for dangerous assignments in JS code
PROTO_POLLUTION_REGEX = r'(\[[\'"]__proto__[\'"]\]|\[[\'"]constructor[\'"]\]|\[[\'"]prototype[\'"]\])'


# Headers often used to trick servers into trusting a request
BYPASS_HEADERS = {
    "X-Forwarded-For": "127.0.0.1",
    "X-Originating-IP": "127.0.0.1",
    "X-Remote-IP": "127.0.0.1",
    "Client-IP": "127.0.0.1",
    "X-Real-IP": "127.0.0.1"
}

# --- API Discovery ---
API_ENDPOINTS = [
    "/api", "/api/v1", "/v1", "/graphql", "/swagger.json", "/openapi.json",
    "/api/doc", "/docs", "/api/users", "/api/login"
]

# --- Cloud Bucket Patterns ---
# %s will be replaced by the domain name
CLOUD_BUCKET_PATTERNS = {
    "AWS S3": "http://%s.s3.amazonaws.com",
    "Google Storage": "http://storage.googleapis.com/%s",
    "Azure Blob": "http://%s.blob.core.windows.net/container"
}

# --- CMS Sensitive Files ---
CMS_SENSITIVE_FILES = {
    "WordPress": ["/wp-config.php.bak", "/wp-config.php.save", "/xmlrpc.php"],
    "Drupal": ["/CHANGELOG.txt", "/sites/default/settings.php.bak"],
    "Joomla": ["/configuration.php.bak"]
}

# --- Subdomain Takeover Signatures ---

# Fingerprints to detect if a cloud service is unclaimed
TAKEOVER_SIGNATURES = {
    "GitHub Pages": "There isn't a GitHub Pages site here",
    "Heroku": "Heroku | No such app",
    "Amazon S3": "The specified bucket does not exist",
    "Shopify": "Sorry, this shop is currently unavailable",
    "Tumblr": "There's nothing here",
    "WP Engine": "The site you were looking for could not be found"
}

# --- JWT Weak Algorithms ---
JWT_WEAK_ALGS = ["none", "HS256", "RS256"] # Flag HS256 if key is likely weak (simplified check)

# --- Command Injection Payloads ---

# Tries to execute a harmless 'echo' command or 'id'
COMMAND_INJECTION_PAYLOADS = [
    "; echo 'vulnerable'",
    "| echo 'vulnerable'",
    "&& echo 'vulnerable'",
    "; id",
    "| id",
    "&& id"
]

# --- Tech Stack Signatures ---

# Patterns to guess the technology stack from HTML or Headers
TECH_SIGNATURES = {
    "WordPress": [r"/wp-content/", r"wp-includes", r'name="generator" content="WordPress'],
    "Drupal": [r"Drupal", r"/sites/default/files"],
    "Joomla": [r"Joomla", r"/media/system/js"],
    "React": [r"react-dom", r"react.production.min.js"],
    "Vue.js": [r"vue.min.js", r"vue.js"],
    "Bootstrap": [r"bootstrap.min.css", r"bootstrap.js", r"bootstrap.min.js"],
    "jQuery": [r"jquery.min.js", r"jquery.js"],
    "Apache": [r"Apache"],
    "Nginx": [r"nginx"],
    "Cloudflare": [r"Cloudflare", r"__cfduid"]
}

# --- Regex for finding emails ---

EMAIL_REGEX = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'

# --- WAF Signatures ---

# Headers that indicate a firewall is protecting the site
WAF_SIGNATURES = {
    "Cloudflare": ["cf-ray", "cloudflare", "__cfduid", "cf-cache-status"],
    "AWS WAF": ["x-amzn-requestid", "x-amz-cf-id"],
    "Akamai": ["akamai-origin-hop", "akamai-x-cache"],
    "Imperva": ["x-cdn", "incap-ses", "visid_incap"],
    "F5 BIG-IP": ["x-cnection", "bigip", "f5_cspm"]
}

# --- Regex for finding secrets ---

SECRET_REGEX = {
    "Google API Key": r"AIza[0-9A-Za-z-_]{35}",
    "Amazon AWS Key": r"AKIA[0-9A-Z]{16}",
    "Stripe Live Key": r"sk_live_[0-9a-zA-Z]{24}",
    "Stripe Test Key": r"sk_test_[0-9a-zA-Z]{24}",
    "GitHub Token": r"ghp_[0-9a-zA-Z]{36}",
    "Slack Token": r"xox[bpa]-[0-9a-zA-Z]{10,48}",
    "Generic High Entropy (test)": r"['\"]([A-Za-z0-9+/]{30,60})['\"]"
}

# Common admin paths
ADMIN_PATHS = [
    "/admin", "/admin/login.php", "/administrator", "/login", "/wp-admin", 
    "/admin.php", "/admin/login", "/cp", "/panel", "/adminpanel"
]

# Sensitive files
SENSITIVE_PATHS = [
    "/.env", "/.git/config", "/.aws/credentials", "/.ssh/id_rsa",
    "/config/config.json", "/backup.sql", "/db_backup.zip", "/app.log"
]

# Open Redirect Payloads
OPEN_REDIRECT_PAYLOADS = [
    "http://google.com", "//google.com", "https://google.com"
]

# Injection Payloads
SQLI_PAYLOADS = {
    "Error-Based": "' OR '1'='1",
    "Boolean-Based": "' AND '1'='1"
}

XSS_PAYLOAD = "<script>console.log('XSS-Test')</script>"

# Security Headers
SECURITY_HEADERS = [
    "Content-Security-Policy", "Strict-Transport-Security",
    "X-Content-Type-Options", "X-Frame-Options",
    "Referrer-Policy", "Permissions-Policy"
]

# Educational Content
MITIGATIONS = {
    "A01": "**Broken Access Control:** Enforce access checks for every request. Use Role-Based Access Control (RBAC).",
    "A01_Open_Redirect": "**Open Redirect:** Validate all redirect targets against a whitelist. Do not trust user input for destinations.",
    "A02": "**Cryptographic Failures:** Enforce HTTPS using HSTS. Ensure all cookies have 'Secure' and 'HttpOnly' flags.",
    "A03": "**Injection:** Use prepared statements (parameterized queries) for SQL. Validate input for all forms.",
    "A05": "**Security Misconfiguration:** Implement strict headers (CSP, HSTS). Remove default accounts and unused pages.",
    "A06": "**Vulnerable Components:** Hide version headers (Server, X-Powered-By). Regularly patch all libraries.",
    "A07": "**XSS:** Encode all user input before displaying it in HTML. Use a Content Security Policy (CSP).",
    "WAF": "**WAF Detected:** A firewall may be blocking your scan. Results might be incomplete.",
    "Missing_SRI": "**Mitigation:** Generate an SRI hash for your external scripts and add the `integrity` and `crossorigin` attributes to your `<script>` tags."
        # "**Info:** Subresource Integrity (SRI) ensures that external files (like scripts loaded from a CDN) have not been tampered with. "
        # "If a CDN is hacked, SRI blocks the malicious script.\n\n"
        
}

MITIGATIONS.update({
    "A05_CORS_Misconfiguration": (
        "**Info:** Cross-Origin Resource Sharing (CORS) allows servers to specify who can access their assets. "
        "Misconfigurations (like reflecting the 'Origin' header) can allow attackers to read sensitive data from your site.\n\n"
        "**Mitigation:** Avoid using wildcards (`*`) if `Allow-Credentials` is true. Strictly whitelist trusted domains."
    ),
})

# --- Directory Listing Signatures ---
# Common text patterns found when a server lists directory contents
DIRECTORY_LISTING_SIGNATURES = [
    "Index of /",
    "Parent Directory",
    "Directory listing for",
    "[To Parent Directory]"
]

# --- PII Regex Patterns ---
PII_REGEX = {
    "Credit Card": r'\b(?:\d[ -]*?){13,16}\b',
    "SSN (US)": r'\b\d{3}-\d{2}-\d{4}\b',
    "Phone (US/Generic)": r'\b(?:\+?1[-. ]?)?\(?\d{3}\)?[-. ]?\d{3}[-. ]?\d{4}\b'
}

# --- Dangerous JS Sinks (DOM XSS) ---
# Patterns in JS that indicate potential DOM-based XSS
JS_DANGEROUS_SINKS = [
    "innerHTML", "document.write", "outerHTML", "eval(", "setTimeout(", "setInterval("
]

# --- Smart Mutation Extensions ---
# Extensions appended to found files to look for backups
MUTATION_EXTENSIONS = [".bak", ".old", "~", ".swp", ".save", ".tmp", "_backup"]



