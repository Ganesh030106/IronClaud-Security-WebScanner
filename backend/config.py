# ============================================================
# IronClad Security Scanner — Unified Configuration
# Merged from: iron_claud_web_scanner + Ad-webscanner
# ============================================================

# --- AI Firewall Settings ---
AI_MODEL_CONTAMINATION = 0.05
AI_TRAINING_SIZE = 50
AI_SAVE_PATH = "ai_model.pkl"

AI_FEATURES = [
    "body_length",
    "header_count",
    "uri_length",
    "param_count",
    "special_char_count"
]

# --- AI Firewall Threat Scoring (from Ad-webscanner) ---
ANOMALY_THRESHOLD = 0.15
WMA_DECAY = 0.3
THRESHOLD_CRITICAL = 0.7
THRESHOLD_WARNING = 0.4

THREAT_WEIGHTS = {
    "port_scan": 0.2,
    "directory_bruteforce": 0.4,
    "injection_attempt": 0.8,
    "secret_discovery": 1.0
}

THREAT_IMPACT = {
    "recon_dns": 0.05,
    "port_scan_small": 0.1,
    "port_scan_large": 0.4,
    "admin_enum": 0.5,
    "sql_injection": 0.9,
    "xss_attempt": 0.7,
    "secret_found": 1.0
}

# --- WAF Blocking Rules (Regex) ---
WAF_RULES = {
    "SQL_INJECTION": r"(?i)(\bunion\b.*\bselect\b|\bselect\b.*\bfrom\b|--|\\'|\\\"|\b0x[0-9a-f]+\b)",
    "XSS": r"(?i)(<script|javascript:|on\w+=|document\.cookie|alert\()",
    "LFI_RCE": r"(?i)(\.\./|/etc/passwd|/bin/sh|cmd\.exe|\${)",
    "SHELLSHOCK": r"(?i)\(\)\s*\{",
    "JAVA_DESERIALIZATION": r"(?i)rO0AB"
}

# --- WAF / Anomaly Settings ---
RATE_LIMIT_THRESHOLD = 20
BAN_DURATION = 600
HONEYPOT_FIELD_NAME = "csrf_debug_token_hidden"

# --- Bad User Agents ---
BAD_USER_AGENTS = [
    "sqlmap/1.4",
    "Nikto",
    "Mozilla/5.0 (compatible; Nmap Scripting Engine)",
    "python-requests/2.28",
    "acunetix"
]

# --- Defense Templates ---
NGINX_HEADER_TEMPLATE = 'add_header {header} "{value}";'
APACHE_HEADER_TEMPLATE = 'Header always set {header} "{value}"'

# --- SSTI Payloads ---
SSTI_PAYLOADS = {
    "Jinja2/Twig": ("{{7*7}}", "49"),
    "Spring/Java": ("${7*7}", "49"),
    "ERB/Ruby": ("<%= 7*7 %>", "49")
}

# --- CRLF Payloads ---
CRLF_PAYLOADS = [
    "/%0d%0aSet-Cookie:crlf=injection",
    "/%0aSet-Cookie:crlf=injection",
    "/%0dSet-Cookie:crlf=injection"
]

# --- Time-Based SQLi Payloads ---
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

# --- Prototype Pollution Patterns ---
PROTO_POLLUTION_REGEX = r'([\[\'"]__proto__[\'"\]]|[\[\'"]constructor[\'"\]]|[\[\'"]prototype[\'"\]])'

# --- Bypass Headers ---
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
TAKEOVER_SIGNATURES = {
    "GitHub Pages": "There isn't a GitHub Pages site here",
    "Heroku": "Heroku | No such app",
    "Amazon S3": "The specified bucket does not exist",
    "Shopify": "Sorry, this shop is currently unavailable",
    "Tumblr": "There's nothing here",
    "WP Engine": "The site you were looking for could not be found"
}

# --- JWT Weak Algorithms ---
JWT_WEAK_ALGS = ["none", "HS256", "RS256"]

# --- Command Injection Payloads ---
COMMAND_INJECTION_PAYLOADS = [
    "; echo 'vulnerable'",
    "| echo 'vulnerable'",
    "&& echo 'vulnerable'",
    "; id",
    "| id",
    "&& id"
]

# --- Tech Stack Signatures ---
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

# --- Regex Patterns ---
EMAIL_REGEX = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'

WAF_SIGNATURES = {
    "Cloudflare": ["cf-ray", "cloudflare", "__cfduid", "cf-cache-status"],
    "AWS WAF": ["x-amzn-requestid", "x-amz-cf-id"],
    "Akamai": ["akamai-origin-hop", "akamai-x-cache"],
    "Imperva": ["x-cdn", "incap-ses", "visid_incap"],
    "F5 BIG-IP": ["x-cnection", "bigip", "f5_cspm"]
}

SECRET_REGEX = {
    "Google API Key": r"AIza[0-9A-Za-z-_]{35}",
    "Amazon AWS Key": r"AKIA[0-9A-Z]{16}",
    "AWS Secret Access Key": r"(?i)aws_(?:secret_)?(?:access_)?key[\s=:\'\"`]+([a-zA-Z0-9/+=]{40})",
    "OpenAI API Key": r"sk-(?:proj-|live-)?[a-zA-Z0-9]{32,64}",
    "HuggingFace Token": r"hf_[a-zA-Z0-9]{34}",
    "SendGrid API Key": r"SG\.[a-zA-Z0-9_\-\.]{66}",
    "Mailgun Private Key": r"key-[a-zA-Z0-9]{32}",
    "Twilio Account SID / Key": r"(?:AC|SK)[a-f0-9]{32}",
    "Firebase Database URL": r"https://[a-z0-9\-]+\.firebaseio\.com",
    "Stripe Live Key": r"sk_live_[0-9a-zA-Z]{24}",
    "Stripe Test Key": r"sk_test_[0-9a-zA-Z]{24}",
    "GitHub Token": r"ghp_[0-9a-zA-Z]{36}",
    "Slack Token": r"xox[bpa]-[0-9a-zA-Z]{10,48}",
    "JWT Token (Hardcoded)": r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",
    "Generic High Entropy (test)": r"['\"]([A-Za-z0-9+/]{30,60})['\"]"
}

# --- Scan Path Lists ---
ADMIN_PATHS = [
    "/admin", "/admin/login.php", "/administrator", "/login", "/wp-admin",
    "/admin.php", "/admin/login", "/cp", "/panel", "/adminpanel"
]

SENSITIVE_PATHS = [
    "/.env", "/.env.local", "/.env.production", "/.git/config", "/.aws/credentials", "/.ssh/id_rsa",
    "/config/config.json", "/backup.sql", "/db_backup.zip", "/app.log",
    "/docker-compose.yml", "/Dockerfile", "/web.config", "/server.xml",
    "/phpinfo.php", "/wp-config.php.bak", "/package.json", "/.DS_Store",
    "/storage/logs/laravel.log"
]

# --- SSRF (Server-Side Request Forgery) Payloads ---
SSRF_PAYLOADS = {
    "AWS Metadata": "http://169.254.169.254/latest/meta-data/",
    "GCP Metadata": "http://metadata.google.internal/computeMetadata/v1/",
    "Localhost Loopback IPv4": "http://127.0.0.1:80/",
    "Localhost Alternate": "http://localhost:8080/",
    "IPv6 Loopback": "http://[::1]:80/"
}

# --- NoSQL Injection Payloads ---
NOSQL_PAYLOADS = [
    {"$ne": None},
    {"$gt": ""},
    "[$ne]=1",
    "admin' || '1'=='1",
    "true, $where: '1 == 1'"
]

# --- Path Traversal / LFI Payloads ---
PATH_TRAVERSAL_PAYLOADS = [
    "../../../../../../etc/passwd",
    "..%2f..%2f..%2f..%2f..%2fetc%2fpasswd",
    "....//....//....//....//etc/passwd",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "../../../../../../windows/win.ini",
    "..%5c..%5c..%5c..%5cwindows%5cwin.ini"
]

# --- XXE (XML External Entity) Payloads ---
XXE_PAYLOADS = [
    """<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root><name>&xxe;</name></root>""",
    """<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]><root><name>&xxe;</name></root>"""
]

# --- Web Cache Poisoning & Deception Probes ---
CACHE_POISONING_HEADERS = {
    "X-Forwarded-Host": "attacker-cache-poison.evil.com",
    "X-Host": "attacker-cache-poison.evil.com",
    "X-Original-URL": "/admin",
    "X-Rewrite-URL": "/admin"
}

# --- Insecure Deserialization Signatures ---
SERIALIZATION_SIGNATURES = {
    "Java Serialized Object": [rb"\xac\xed\x00\x05", "rO0AB"],
    "PHP Serialized Object": [r'O:\d+:"', r'a:\d+:\{'],
    "Python Pickle": [rb"cos\nsystem", rb"cposix\nsystem"],
    "Node.js Serialize": [r"_$$ND_FUNC$$_"]
}

# --- Enterprise Cloud & Database Port Scan Profiles ---
DEFAULT_PORTS_ENTERPRISE = [21, 22, 25, 80, 443, 3306, 5432, 6379, 8080, 8443, 9200, 27017]

OPEN_REDIRECT_PAYLOADS = [
    "http://google.com", "//google.com", "https://google.com"
]

SQLI_PAYLOADS = {
    "Error-Based": "' OR '1'='1",
    "Boolean-Based": "' AND '1'='1"
}

XSS_PAYLOAD = "<script>console.log('XSS-Test')</script>"

SECURITY_HEADERS = [
    "Content-Security-Policy", "Strict-Transport-Security",
    "X-Content-Type-Options", "X-Frame-Options",
    "Referrer-Policy", "Permissions-Policy"
]

# --- Directory Listing Signatures ---
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

# --- Dangerous JS Sinks ---
JS_DANGEROUS_SINKS = [
    "innerHTML", "document.write", "outerHTML", "eval(", "setTimeout(", "setInterval("
]

# --- Smart Mutation Extensions ---
MUTATION_EXTENSIONS = [".bak", ".old", "~", ".swp", ".save", ".tmp", "_backup"]

# --- Educational Mitigations (merged: detailed from old + extras from iron_claud) ---
MITIGATIONS = {
    "A01": (
        "**Info:** Broken Access Control (BAC) happens when users can access resources "
        "or perform actions they shouldn't be able to. Finding an '/admin' page is just "
        "a hint; the real test is trying to access it without being an admin.\n\n"
        "**Mitigation:** Enforce access control checks on the server for *every* request. "
        "Deny by default. Use role-based access control (RBAC)."
    ),
    "A01_Open_Redirect": (
        "**Open Redirect:** Validate all redirect targets against a whitelist. "
        "Do not trust user input for destinations."
    ),
    "A02": (
        "**Info:** This category covers failures related to cryptography, like using "
        "weak ciphers, missing encryption (HTTP), or insecure cookie settings.\n\n"
        "**Mitigation:** Always use HTTPS. Enable HSTS (`Strict-Transport-Security` header) "
        "to enforce it. Set `Secure` and `HttpOnly` flags on all session cookies."
    ),
    "A03": (
        "**Info:** Injection flaws, like SQL Injection (SQLi), occur when untrusted data "
        "is sent to an interpreter as part of a command or query.\n\n"
        "**Mitigation:** Use parameterized queries (prepared statements) to separate data "
        "from commands. Validate and sanitize all user input."
    ),
    "A03_Command_Injection": (
        "**Mitigation:** Never pass user input directly to system commands. "
        "Use prepared statements and validate input."
    ),
    "A05": (
        "**Info:** This is a broad category for missing or incorrect security configurations. "
        "Missing headers fail to enable browser-level security features.\n\n"
        "**Mitigation:** Implement a strong `Content-Security-Policy` (CSP). Add all recommended "
        "security headers. Disable directory listing and remove default credentials."
    ),
    "A05_CORS_Misconfiguration": (
        "**Info:** CORS allows servers to specify who can access their assets. "
        "Misconfigurations can allow attackers to read sensitive data.\n\n"
        "**Mitigation:** Avoid wildcards (`*`) if `Allow-Credentials` is true. "
        "Strictly whitelist trusted domains."
    ),
    "A06": (
        "**Info:** Using components with known vulnerabilities. Publicly visible version "
        "numbers make it easy for attackers to find exploits.\n\n"
        "**Mitigation:** Remove or obscure version headers. Regularly scan dependencies "
        "for known vulnerabilities and patch them."
    ),
    "A06_Missing_SRI": (
        "**Mitigation:** Generate SRI hashes for external scripts and add `integrity` "
        "and `crossorigin` attributes to `<script>` tags."
    ),
    "A07": (
        "**Info:** Cross-Site Scripting (XSS) happens when untrusted data is included in "
        "a web page without proper validation.\n\n"
        "**Mitigation:** Context-aware output encoding is the primary defense. Encode all "
        "user-supplied data before rendering. A strong CSP is a powerful secondary defense."
    ),
    "A08_Insecure_Deserialization": (
        "**Info:** Insecure Deserialization occurs when untrusted serialized data is passed "
        "to a backend parser, leading to Remote Code Execution (RCE) or state tampering.\n\n"
        "**Mitigation:** Avoid accepting serialized objects from untrusted sources. Use safe data formats like JSON. "
        "If serialization is necessary, implement cryptographic signature checks (HMAC)."
    ),
    "A08_XXE": (
        "**Info:** XML External Entity (XXE) attacks occur when an XML parser evaluates external entity "
        "declarations, allowing local file disclosure or internal network scanning.\n\n"
        "**Mitigation:** Disable DTD (External Entities) resolution completely in XML parsers (`disallow-doctype-decl`)."
    ),
    "A10_SSRF": (
        "**Info:** Server-Side Request Forgery (SSRF) allows attackers to coerce the web server into "
        "making unintended requests to internal resources, cloud metadata (169.254.169.254), or loopback APIs.\n\n"
        "**Mitigation:** Validate and sanitize all target URLs against a strict domain whitelist. "
        "Block requests to private RFC 1918 and loopback IP ranges at the network and firewall layer. Disable IMDSv1 on AWS."
    ),
    "A03_Path_Traversal": (
        "**Info:** Path Traversal (LFI) lets attackers access restricted server files (e.g. `/etc/passwd`, `win.ini`) "
        "by manipulating file path variables with `../` sequences.\n\n"
        "**Mitigation:** Avoid passing user input directly to filesystem APIs. Use basename validation, "
        "canonical path checking (`realpath`), and an explicit whitelist of permissible file identifiers."
    ),
    "A03_NoSQL": (
        "**Info:** NoSQL Injection occurs when query operators like `$gt` or `$ne` are accepted from user input, "
        "bypassing database authentication or filtering.\n\n"
        "**Mitigation:** Strictly cast and validate input types. Reject objects or arrays where scalar primitives are expected. "
        "Use schema validation tools like Mongoose with strict filtering."
    ),
    "A05_Cache_Poisoning": (
        "**Info:** Web Cache Poisoning manipulates caching proxies using unkeyed headers (e.g., `X-Forwarded-Host`) "
        "to serve malicious cached payloads to other visitors.\n\n"
        "**Mitigation:** Disable support for unkeyed host headers. Ensure proxy headers are strictly validated and overwritten "
        "by reverse proxies, or incorporate headers into cache keys."
    )
}

