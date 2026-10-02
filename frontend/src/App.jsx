import { useState, useEffect, useRef } from 'react';
import { 
  Shield, Terminal, AlertTriangle, Database, FileText, 
  Download, Play, RefreshCw, CheckCircle2, AlertCircle, 
  Zap, ShieldAlert, Search, X, Copy 
} from 'lucide-react';
import { 
  ResponsiveContainer, AreaChart, Area, BarChart, Bar, XAxis, YAxis, Tooltip, CartesianGrid 
} from 'recharts';
import { scannerApi } from './api/scanner';
import './App.css';

const VULNERABILITY_CATALOG = [
  { 
    id: 'CRITICAL_Hardcoded_Secrets', 
    title: 'CRITICAL: Hardcoded API Keys / Secrets',
    cwe: 'CWE-798',
    cvss_score: 9.8,
    cvss_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
    severity: 'CRITICAL',
    vector_summary: 'Remote Unauthenticated Key Exposure',
    remediation: 'Immediately revoke leaked keys from cloud provider dashboards (OpenAI, AWS, Stripe, GitHub). Transition to runtime environment secrets (.env) and add secret scanning hooks to CI/CD.',
    virtual_patch: 'SecRule RESPONSE_BODY "(?:sk-[a-zA-Z0-9]{20,}|AKIA[0-9A-Z]{16}|ghp_[a-zA-Z0-9]{36})" "id:100101,phase:4,deny,status:500,log,msg:\'Data Leak: Hardcoded Secret Intercepted\'"'
  },
  { 
    id: 'A10_SSRF', 
    title: 'A10: Server-Side Request Forgery (SSRF)',
    cwe: 'CWE-918',
    cvss_score: 9.6,
    cvss_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N',
    severity: 'CRITICAL',
    vector_summary: 'Cloud Metadata & Internal Network Pivot',
    remediation: 'Filter outbound web requests by blocking private IP ranges (127.0.0.1, 169.254.169.254, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16). Enforce strict URL domain whitelists for server-side fetches.',
    virtual_patch: 'SecRule ARGS "(?:169\\.254\\.169\\.254|127\\.0\\.0\\.1|metadata\\.google|localhost)" "id:100102,phase:2,deny,status:403,log,msg:\'SSRF Target Blocked\'"'
  },
  { 
    id: 'A03_Path_Traversal_LFI', 
    title: 'A03: Path Traversal / Local File Inclusion (LFI)',
    cwe: 'CWE-22',
    cvss_score: 9.3,
    cvss_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N',
    severity: 'CRITICAL',
    vector_summary: 'Filesystem Directory Escape & File Retrieval',
    remediation: 'Sanitize input with path.basename() or reject dot-dot-slash patterns. Never pass untrusted user input directly to filesystem APIs (open, readFile, include).',
    virtual_patch: 'SecRule ARGS "(?:\\.\\./|\\.\\.\\\\|/etc/passwd|win\\.ini|system32)" "id:100103,phase:2,deny,status:403,log,msg:\'Path Traversal / LFI Attempt Blocked\'"'
  },
  { 
    id: 'A03_Command_Injection', 
    title: 'A03: OS Command Injection',
    cwe: 'CWE-78',
    cvss_score: 9.8,
    cvss_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
    severity: 'CRITICAL',
    vector_summary: 'Arbitrary Remote System Code Execution',
    remediation: 'Avoid invoking OS shells (exec, system, popen). Use parameterized process APIs like subprocess.run([cmd, arg1, arg2], shell=False).',
    virtual_patch: 'SecRule ARGS "(?:;\\s*cat\\s+/etc/passwd|\\|\\s*whoami|`id`|\\$\\(whoami\\))" "id:100104,phase:2,deny,status:403,log,msg:\'Command Injection Blocked\'"'
  },
  { 
    id: 'A03_SSTI', 
    title: 'A03: Server-Side Template Injection (SSTI)',
    cwe: 'CWE-1336',
    cvss_score: 9.0,
    cvss_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
    severity: 'CRITICAL',
    vector_summary: 'Template Engine Code Execution',
    remediation: 'Pass untrusted user parameters as template context variables instead of string concatenation. Enable sandbox environments in Jinja2/Twig/Smarty.',
    virtual_patch: 'SecRule ARGS "(?:\\{\\{.*\\}\\}|\\$\\{.*\\}|<%.*%>|#\\{.*\\})" "id:100105,phase:2,deny,status:403,log,msg:\'SSTI Template Delimiter Blocked\'"'
  },
  { 
    id: 'A03_NoSQL_Injection', 
    title: 'A03: NoSQL Operator Injection',
    cwe: 'CWE-943',
    cvss_score: 8.8,
    cvss_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N',
    severity: 'HIGH',
    vector_summary: 'NoSQL Authentication Bypass & Data Dumping',
    remediation: 'Sanitize query selectors using mongo-sanitize. Disallow dollar ($) operators from user inputs and enforce schema typing.',
    virtual_patch: 'SecRule ARGS_NAMES "^\\$(?:gt|ne|eq|regex|where)" "id:100106,phase:2,deny,status:403,log,msg:\'NoSQL Operator Injection Blocked\'"'
  },
  { 
    id: 'A08_XXE_Injection', 
    title: 'A08: XML External Entity (XXE) Injection',
    cwe: 'CWE-611',
    cvss_score: 8.6,
    cvss_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H',
    severity: 'HIGH',
    vector_summary: 'XML Parser Entity Resolution & Disclosure',
    remediation: 'Disable external DTD resolution (disallow-doctype-decl) and general entities in all XML parsers and soap clients.',
    virtual_patch: 'SecRule REQUEST_BODY "(?:<!ENTITY|SYSTEM\\s+[\'"].*[\'"]|<!DOCTYPE)" "id:100107,phase:2,deny,status:403,log,msg:\'XXE Injection Blocked\'"'
  },
  { 
    id: 'A08_Insecure_Deserialization', 
    title: 'A08: Insecure Deserialization',
    cwe: 'CWE-502',
    cvss_score: 8.9,
    cvss_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
    severity: 'HIGH',
    vector_summary: 'Object Unpickling & Gadget Chain Execution',
    remediation: 'Do not accept serialized objects from untrusted sources. Use standard JSON with schema validation.',
    virtual_patch: 'SecRule REQUEST_COOKIES|ARGS "(?:_\\$\\$ND_FUNC\\$\\$_|rO0AB|cos\\nsystem)" "id:100108,phase:2,deny,status:403,log,msg:\'Insecure Deserialization Token Blocked\'"'
  },
  { 
    id: 'A03_Injection', 
    title: 'A03: SQL Injection Risks',
    cwe: 'CWE-89',
    cvss_score: 8.9,
    cvss_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N',
    severity: 'HIGH',
    vector_summary: 'Database Query Hijack & Extraction',
    remediation: 'Use parameterized statements and ORMs. Avoid string concatenation when building queries.',
    virtual_patch: 'SecRule ARGS "(?:union\\s+select|select.*from|\'\\s*or\\s*\'1\'=\'1)" "id:100109,phase:2,deny,status:403,log,msg:\'SQL Injection Blocked\'"'
  },
  { 
    id: 'A03_Blind_SQL_Injection', 
    title: 'A03: Time-Based Blind SQLi',
    cwe: 'CWE-89',
    cvss_score: 8.7,
    cvss_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N',
    severity: 'HIGH',
    vector_summary: 'Inference Data Exfiltration Via Sleep Delays',
    remediation: 'Validate input data types strictly (e.g., cast IDs to integer) and enforce prepared statements across all endpoints.',
    virtual_patch: 'SecRule ARGS "(?:waitfor\\s+delay|pg_sleep|sleep\\s*\\(|dbms_pipe\\.receive_message)" "id:100110,phase:2,deny,status:403,log,msg:\'Blind SQLi Time Delay Blocked\'"'
  },
  { 
    id: 'A07_XSS', 
    title: 'A07: Cross-Site Scripting (XSS / Breakouts)',
    cwe: 'CWE-79',
    cvss_score: 7.2,
    cvss_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N',
    severity: 'HIGH',
    vector_summary: 'Client Browser Execution & Session Hijack',
    remediation: 'HTML-entity-encode dynamic data before outputting in templates, and configure a strict Content-Security-Policy (CSP) with script nonces.',
    virtual_patch: 'SecRule ARGS "(?:<script|javascript:|onerror\\s*=|onload\\s*=|alert\\s*\\()" "id:100111,phase:2,deny,status:403,log,msg:\'XSS Payload Blocked\'"'
  },
  { 
    id: 'A01_Broken_Access_Control', 
    title: 'A01: Broken Access Control',
    cwe: 'CWE-284',
    cvss_score: 7.5,
    cvss_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N',
    severity: 'HIGH',
    vector_summary: 'Privilege Escalation & Unauthorized Admin Access',
    remediation: 'Enforce access checks server-side on every protected endpoint and route using JWT authorization middleware.',
    virtual_patch: 'SecRule REQUEST_URI "@rx ^/(admin|dashboard|portal|manage)" "id:100112,phase:1,chain,deny,status:401\\n SecRule REQUEST_HEADERS:Authorization "@eq 0""'
  },
  { 
    id: 'A05_Web_Cache_Poisoning', 
    title: 'A05: Web Cache Poisoning & Deception',
    cwe: 'CWE-444',
    cvss_score: 6.8,
    cvss_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N',
    severity: 'MEDIUM',
    vector_summary: 'Unkeyed HTTP Header Cache Poisoning',
    remediation: 'Include unkeyed headers (X-Forwarded-Host, X-Original-URL) in cache keys or strip them at the CDN/reverse proxy layer before request processing.',
    virtual_patch: 'SecRule REQUEST_HEADERS:X-Forwarded-Host "!@rx ^[a-zA-Z0-9.-]+$" "id:100113,phase:1,deny,status:400,log,msg:\'Cache Poisoning Header Blocked\'"'
  },
  { 
    id: 'A03_CRLF_Injection', 
    title: 'A03: CRLF Injection / Header Splitting',
    cwe: 'CWE-113',
    cvss_score: 6.5,
    cvss_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N',
    severity: 'MEDIUM',
    vector_summary: 'HTTP Response Header Injection',
    remediation: 'Sanitize %0d and %0a characters before placing user values into HTTP headers or redirect URLs.',
    virtual_patch: 'SecRule ARGS "(?:%0d|%0a|\\r|\\n)" "id:100114,phase:2,deny,status:403,log,msg:\'CRLF Header Splitting Blocked\'"'
  },
  { 
    id: 'A01_Host_Header_Injection', 
    title: 'A01: Host Header Injection',
    cwe: 'CWE-601',
    cvss_score: 6.1,
    cvss_vector: 'CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N',
    severity: 'MEDIUM',
    vector_summary: 'Host Header Spoofing & Cache Poisoning',
    remediation: 'Configure web servers to only respond to explicitly whitelisted Host headers and reject unknown virtual hosts.',
    virtual_patch: 'SecRule REQUEST_HEADERS:Host "!@rx ^(localhost|[a-zA-Z0-9.-]+\\.yourdomain\\.com)$" "id:100115,phase:1,deny,status:400,log,msg:\'Untrusted Host Header\'"'
  },
  { 
    id: 'A02_Cryptographic_Failures', 
    title: 'A02: Cryptographic Failures & Cookie Security',
    cwe: 'CWE-319',
    cvss_score: 6.5,
    cvss_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N',
    severity: 'MEDIUM',
    vector_summary: 'Insecure Transmission & Missing Cookie Flags',
    remediation: 'Enable HSTS (Strict-Transport-Security), enforce HTTPS everywhere, and add Secure, HttpOnly, and SameSite=Lax attributes to all cookies.',
    virtual_patch: 'SecRule RESPONSE_HEADERS:Set-Cookie "!@rx (?i)samesite" "id:100116,phase:3,pass,log,msg:\'Cookie missing SameSite attribute\'"'
  },
  { 
    id: 'A03_Prototype_Pollution', 
    title: 'A03: Prototype Pollution (Client-Side)',
    cwe: 'CWE-1321',
    cvss_score: 6.3,
    cvss_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N',
    severity: 'MEDIUM',
    vector_summary: 'Client Object Prototype Manipulation',
    remediation: 'Sanitize __proto__ and constructor property names in recursive object-merging utilities or freeze prototypes with Object.freeze().',
    virtual_patch: 'SecRule ARGS "(?:__proto__|prototype|constructor\\[)" "id:100117,phase:2,deny,status:403,log,msg:\'Prototype Pollution Attempt Blocked\'"'
  },
  { 
    id: 'A05_Security_Misconfig_Headers', 
    title: 'A05: Security Misconfigurations (Missing Headers)',
    cwe: 'CWE-16',
    cvss_score: 5.3,
    cvss_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N',
    severity: 'MEDIUM',
    vector_summary: 'Missing Browser Defense Policy Headers',
    remediation: 'Deploy Content-Security-Policy, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, and Permissions-Policy headers.',
    virtual_patch: 'SecRule RESPONSE_HEADERS:X-Frame-Options "@eq 0" "id:100118,phase:3,pass,log,msg:\'Missing X-Frame-Options Header\'"'
  },
  { 
    id: 'A06_Vulnerable_Components', 
    title: 'A06: Vulnerable Third-Party Components',
    cwe: 'CWE-1104',
    cvss_score: 5.0,
    cvss_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N',
    severity: 'LOW',
    vector_summary: 'Software Version Disclosure & Outdated Components',
    remediation: 'Strip Server and X-Powered-By response headers to conceal backend framework and runtime versions.',
    virtual_patch: 'SecRule RESPONSE_HEADERS:Server "!@rx ^$" "id:100119,phase:3,pass,log,msg:\'Server Banner Leaked\'"'
  }
];

export default function App() {
  const [activeTab, setActiveTab] = useState('DASHBOARD');
  const [targetUrl, setTargetUrl] = useState('');
  const [scanState, setScanState] = useState({
    status: 'idle', // idle, scanning, completed, failed
    url: null,
    results: null,
    error: null
  });
  const [wafLogs, setWafLogs] = useState([]);
  const [aiStatus, setAiStatus] = useState({ is_trained: false, logs: [] });
  const [loading, setLoading] = useState(false);
  const [terminalOutput, setTerminalOutput] = useState([
    '[SYSTEM] IronClad Command Center Ready.',
    '[SYSTEM] Awaiting target authorization... Enter target URL above.'
  ]);
  const [wafRunning, setWafRunning] = useState(false);
  const [aiRunning, setAiRunning] = useState(false);
  const [wafConfig, setWafConfig] = useState({ whitelist: [], blacklist: [] });
  const [newWhitelistIp, setNewWhitelistIp] = useState('');
  const [newBlacklistIp, setNewBlacklistIp] = useState('');
  
  // HUD Advanced Controls & CVSS States
  const [scanMode, setScanMode] = useState('deep');
  const [vulnSearch, setVulnSearch] = useState('');
  const [vulnSeverityFilter, setVulnSeverityFilter] = useState('ALL');
  const [hideCleanChecks, setHideCleanChecks] = useState(false);
  const [selectedDossier, setSelectedDossier] = useState(null);
  const [copyToast, setCopyToast] = useState('');

  const terminalEndRef = useRef(null);

  const handleCopyText = (text, label) => {
    if (navigator?.clipboard?.writeText) {
      navigator.clipboard.writeText(typeof text === 'string' ? text : JSON.stringify(text, null, 2));
    }
    setCopyToast(label);
    setTimeout(() => setCopyToast(''), 2500);
  };

  // Auto-scroll terminal
  useEffect(() => {
    if (terminalEndRef.current) {
      terminalEndRef.current.scrollIntoView({ behavior: 'smooth' });
    }
  }, [terminalOutput]);

  // Append log utility
  const appendLog = (category, message) => {
    const timestamp = new Date().toLocaleTimeString();
    setTerminalOutput(prev => [...prev, `[${timestamp}] [${category}] ${message}`]);
  };

  // Poll scan status
  useEffect(() => {
    let intervalId = null;

    if (scanState.status === 'scanning') {
      intervalId = setInterval(async () => {
        try {
          const status = await scannerApi.getScanStatus();
          setScanState(status);
          
          if (status.status === 'completed') {
            appendLog('SUCCESS', 'Target analysis complete! Results compiled.');
            clearInterval(intervalId);
          } else if (status.status === 'failed') {
            appendLog('ERROR', `Scan aborted: ${status.error}`);
            clearInterval(intervalId);
          } else {
            appendLog('RECON', 'Probing target ports, scanning SSL cert, crawling HTML...');
          }
        } catch (err) {
          appendLog('ERROR', `Polling failed: ${err.message}`);
        }
      }, 3000);
    }

    return () => {
      if (intervalId) clearInterval(intervalId);
    };
  }, [scanState.status]);

  const fetchWafConfig = async () => {
    try {
      const config = await scannerApi.getWafConfig();
      setWafConfig(config);
    } catch (err) {
      console.error(err);
    }
  };


  const handleAddWhitelist = async (e) => {
    e.preventDefault();
    const ip = newWhitelistIp.trim();
    if (!ip) return;
    try {
      const config = await scannerApi.addWhitelist(ip);
      setWafConfig(config);
      setNewWhitelistIp('');
      appendLog('FIREWALL', `Successfully whitelisted IP: ${ip}`);
    } catch (err) {
      appendLog('ERROR', `Failed to whitelist IP: ${err.message}`);
    }
  };

  const handleAddBlacklist = async (e) => {
    e.preventDefault();
    const ip = newBlacklistIp.trim();
    if (!ip) return;
    try {
      const config = await scannerApi.addBlacklist(ip);
      setWafConfig(config);
      setNewBlacklistIp('');
      appendLog('FIREWALL', `Successfully blacklisted IP: ${ip}`);
    } catch (err) {
      appendLog('ERROR', `Failed to blacklist IP: ${err.message}`);
    }
  };

  const handleRemoveWhitelist = async (ip) => {
    try {
      const config = await scannerApi.removeWhitelist(ip);
      setWafConfig(config);
      appendLog('FIREWALL', `Removed IP from whitelist: ${ip}`);
    } catch (err) {
      appendLog('ERROR', `Failed to remove whitelist IP: ${err.message}`);
    }
  };

  const handleRemoveBlacklist = async (ip) => {
    try {
      const config = await scannerApi.removeBlacklist(ip);
      setWafConfig(config);
      appendLog('FIREWALL', `Removed IP from blacklist: ${ip}`);
    } catch (err) {
      appendLog('ERROR', `Failed to remove blacklist IP: ${err.message}`);
    }
  };

  const handleResetAiModel = async () => {
    if (!window.confirm("Are you sure you want to delete the AI IsolationForest model and clear training stats?")) return;
    try {
      const res = await scannerApi.resetAiModel();
      appendLog('AI_FIREWALL', res.message);
      const ai = await scannerApi.getAiStatus();
      setAiStatus(ai);
      setAiRunning(ai.is_running || false);
    } catch (err) {
      appendLog('ERROR', `Failed to reset AI model: ${err.message}`);
    }
  };

  // Fetch initial scan state on mount
  useEffect(() => {
    const fetchInitial = async () => {
      try {
        const status = await scannerApi.getScanStatus();
        setScanState(status);
        if (status.status === 'completed') {
          appendLog('SYSTEM', `Loaded previous scan for: ${status.url}`);
        }
        
        // Fetch WAF and AI status
        const waf = await scannerApi.getWafLogs();
        setWafLogs(waf.logs || []);
        setWafRunning(waf.is_running || false);
        
        const ai = await scannerApi.getAiStatus();
        setAiStatus(ai);
        setAiRunning(ai.is_running || false);

        await fetchWafConfig();
      } catch (err) {
        console.error(err);
      }
    };
    fetchInitial();
  }, []);

  // Launch scan
  const handleStartScan = async (e) => {
    e.preventDefault();
    if (!targetUrl) return;

    try {
      setLoading(true);
      appendLog('INITIALIZE', `Acquiring target lock on: ${targetUrl} [${scanMode.toUpperCase()} MODE]`);
      
      await scannerApi.startScan(targetUrl, scanMode);
      setScanState({
        status: 'scanning',
        url: targetUrl,
        scan_mode: scanMode,
        results: null,
        error: null
      });
      setLoading(false);
      appendLog('INITIALIZE', `Scan launched (${scanMode} mode). Background execution threads spawned.`);
    } catch (err) {
      setLoading(false);
      appendLog('ERROR', err.message);
      alert(err.message);
    }
  };

  const getThreatMatrix = () => {
    if (!results || !results.vulnerabilities) return null;
    let maxCvss = 0.0;
    let criticalCount = 0;
    let highCount = 0;
    let mediumCount = 0;
    let lowCount = 0;

    VULNERABILITY_CATALOG.forEach(cat => {
      const desc = results.vulnerabilities[cat.id];
      const hasIssue = Array.isArray(desc)
        ? desc.length > 0 && !desc[0]?.toString().includes("No ") && !desc[0]?.toString().includes("Secure") && !desc[0]?.toString().includes("Protected")
        : desc && !desc.toString().includes("No ") && !desc.toString().includes("Protected");
      
      if (hasIssue) {
        if (cat.cvss_score > maxCvss) maxCvss = cat.cvss_score;
        if (cat.severity === 'CRITICAL') criticalCount++;
        else if (cat.severity === 'HIGH') highCount++;
        else if (cat.severity === 'MEDIUM') mediumCount++;
        else if (cat.severity === 'LOW') lowCount++;
      }
    });

    return {
      maxCvss: maxCvss || 0.0,
      criticalCount,
      highCount,
      mediumCount,
      lowCount,
      totalThreats: criticalCount + highCount + mediumCount + lowCount
    };
  };

  const refreshWafAndAi = async () => {
    try {
      const waf = await scannerApi.getWafLogs();
      setWafLogs(waf.logs || []);
      setWafRunning(waf.is_running || false);
      
      const ai = await scannerApi.getAiStatus();
      setAiStatus(ai);
      setAiRunning(ai.is_running || false);

      await fetchWafConfig();
      appendLog('FIREWALL', 'Fetched latest firewall traffic logs and configurations.');
    } catch (err) {
      appendLog('ERROR', `Failed to fetch firewall logs: ${err.message}`);
    }
  };

  const results = scanState.results;

  // Compute metrics for Dashboard
  const getVulnCounts = () => {
    if (!results || !results.vulnerabilities) return [];
    
    let critical = 0;
    let high = 0;
    let medium = 0;
    let low = 0;
    let info = 0;

    const vulns = results.vulnerabilities;
    
    Object.keys(vulns).forEach(key => {
      const details = vulns[key];
      const isVulnerable = Array.isArray(details) 
        ? details.length > 0 && !details[0]?.toString().includes("No ") && !details[0]?.toString().includes("Secure") && !details[0]?.toString().includes("Protected")
        : details && !details.toString().includes("No ") && !details.toString().includes("Protected");
      
      if (isVulnerable) {
        if (key.includes('CRITICAL') || key.includes('SSTI') || key.includes('Secrets') || key.includes('A10_SSRF') || key.includes('A08_XXE')) critical++;
        else if (key.includes('A03') || key.includes('Injection') || key.includes('Command') || key.includes('Traversal') || key.includes('NoSQL')) high++;
        else if (key.includes('A01') || key.includes('A02') || key.includes('Access') || key.includes('A08_Insecure_Deserialization') || key.includes('XSS')) medium++;
        else if (key.includes('A05') || key.includes('A06') || key.includes('Headers') || key.includes('Cache')) low++;
        else info++;
      }
    });

    return [
      { name: 'CRITICAL', value: critical, fill: '#ff0055' },
      { name: 'HIGH', value: high, fill: '#ffb700' },
      { name: 'MEDIUM', value: medium, fill: '#00d2ff' },
      { name: 'LOW', value: low, fill: '#bd00ff' },
      { name: 'INFO', value: info, fill: '#00ff41' }
    ];
  };

  const getThreatHistoryData = () => {
    if (results?.defense_sim?.threat_history) {
      return results.defense_sim.threat_history.map((score, index) => ({
        step: `Step ${index}`,
        score: score
      }));
    }
    return [
      { step: 'Step 0', score: 0 },
      { step: 'Step 1', score: 0.1 },
      { step: 'Step 2', score: 0.25 },
      { step: 'Step 3', score: 0.4 },
      { step: 'Step 4', score: 0.8 }
    ];
  };

  const countTotalVulns = () => {
    return getVulnCounts().reduce((acc, curr) => acc + curr.value, 0);
  };

  return (
    <div style={{ maxWidth: '1200px', margin: '0 auto', padding: '20px', width: '100%' }}>
      {/* Header */}
      <header style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', borderBottom: '1px solid var(--border-color)', paddingBottom: '20px', marginBottom: '20px' }}>
        <div>
          <h1 className="cyber-glitch-title">
            <Shield size={36} color="var(--color-cyan)" /> IRONCLAD SYSTEM
          </h1>
          <p style={{ color: 'var(--text-secondary)', marginTop: '5px' }}>
            AI-POWERED VULNERABILITY AUDITOR & REVERSE PROXY FIREWALL
          </p>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: '15px' }}>
          <div style={{ textAlign: 'right' }}>
            <span style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>ENGINE STATUS:</span>
            <div style={{ display: 'flex', alignItems: 'center', gap: '5px', color: 'var(--color-green)' }}>
              <span style={{ width: '8px', height: '8px', borderRadius: '50%', backgroundColor: 'var(--color-green)', display: 'inline-block', boxShadow: '0 0 8px var(--color-green)' }}></span>
              ACTIVE
            </div>
          </div>
        </div>
      </header>

      {/* Scan Mode Switcher */}
      <div className="scan-mode-container">
        <button 
          type="button"
          onClick={() => setScanMode('quick')}
          className={`scan-mode-btn quick ${scanMode === 'quick' ? 'active' : ''}`}
          disabled={scanState.status === 'scanning'}
        >
          <Zap size={16} /> ⚡ QUICK RECON (Fast Surface & SSL Triage • ~5-10s)
        </button>
        <button 
          type="button"
          onClick={() => setScanMode('deep')}
          className={`scan-mode-btn deep ${scanMode === 'deep' ? 'active' : ''}`}
          disabled={scanState.status === 'scanning'}
        >
          <ShieldAlert size={16} /> 🛡️ DEEP AUDIT (Full OWASP + Active Fuzzing & Exploits • ~30-60s)
        </button>
      </div>

      {/* Target input Form */}
      <form onSubmit={handleStartScan} className="cyber-form">
        <input 
          type="url" 
          placeholder="ENTER TARGET LOCK-ON URL (e.g., https://example.com)..." 
          value={targetUrl}
          onChange={(e) => setTargetUrl(e.target.value)}
          className="cyber-input"
          disabled={scanState.status === 'scanning'}
          required
        />
        <button 
          type="submit" 
          className="cyber-btn"
          disabled={scanState.status === 'scanning' || loading}
        >
          {scanState.status === 'scanning' ? (
            <span style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
              <RefreshCw className="pulse-text" size={18} style={{ animation: 'rotate 2s linear infinite' }} /> SCANNING
            </span>
          ) : (
            <span style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
              <Play size={18} /> LAUNCH {scanMode.toUpperCase()} AUDIT
            </span>
          )}
        </button>
      </form>

      {/* Polling/Scanning HUD */}
      {scanState.status === 'scanning' && (
        <div className="loading-hud">
          <div className="loading-spinner-cyber"></div>
          <div className="pulse-text">ACTIVE PENTESTING RUNNING ON {scanState.url}</div>
          <p style={{ marginTop: '10px', color: 'var(--text-muted)', fontSize: '0.9rem' }}>
            FASTAPI backend is crawling pages, testing OWASP injections, checking DNS and ports...
          </p>
        </div>
      )}

      {/* Navigation tabs */}
      <nav className="cyber-tabs">
        {[
          { id: 'DASHBOARD', label: '📊 DASHBOARD' },
          { id: 'RECON', label: '🔎 RECON' },
          { id: 'VULNERABILITIES', label: '🚨 VULNERABILITIES' },
          { id: 'INFRASTRUCTURE', label: '🌐 INFRASTRUCTURE' },
          { id: 'CONTENT', label: '📄 CONTENT' },
          { id: 'DEFENSE', label: '🛡️ WAF MONITOR' },
          { id: 'AI_FIREWALL', label: '🧠 AI FIREWALL' },
          { id: 'HEADERS', label: '🍪 COOKIES/HEADERS' },
          { id: 'REMEDIATION', label: '✅ REMEDIATION' },
          { id: 'EXPORT', label: '📤 EXPORT' }
        ].map(tab => (
          <button 
            key={tab.id}
            onClick={() => setActiveTab(tab.id)}
            className={`cyber-tab ${activeTab === tab.id ? 'active' : ''}`}
          >
            {tab.label}
          </button>
        ))}
      </nav>

      {/* Main content grid */}
      <main style={{ minHeight: '450px', marginBottom: '30px' }}>
        {scanState.status === 'idle' && (
          <div className="cyber-card warning" style={{ textAlign: 'center', padding: '50px' }}>
            <AlertTriangle size={48} color="var(--color-yellow)" style={{ marginBottom: '15px' }} />
            <h3>SYSTEM IN STANDBY MODE</h3>
            <p style={{ color: 'var(--text-secondary)', marginTop: '10px' }}>
              No scanner execution has been initiated. Type in a URL target above to launch the pentest audit.
            </p>
          </div>
        )}

        {scanState.status === 'failed' && (
          <div className="cyber-card critical" style={{ padding: '30px' }}>
            <AlertCircle size={36} color="var(--color-red)" style={{ marginBottom: '10px' }} />
            <h3>SCAN PIPELINE BROKEN</h3>
            <p style={{ color: 'var(--text-secondary)', marginTop: '10px' }}>
              The scan failed due to connection error: <code style={{ color: 'var(--color-red)', background: '#110505' }}>{scanState.error}</code>
            </p>
            <p style={{ color: 'var(--text-muted)', marginTop: '10px' }}>
              Make sure the destination URL is accessible, correctly spelled, and includes the protocol (e.g. http://localhost:5000).
            </p>
          </div>
        )}

        {/* Dashboard Tab */}
        {activeTab === 'DASHBOARD' && results && (
          <div>
            {/* Real-time Inline Firewall HUD */}
            <div className="cyber-grid-2" style={{ marginBottom: '20px' }}>
              <div className={`cyber-card ${wafRunning ? 'success' : 'critical'}`} style={{ borderLeft: `4px solid ${wafRunning ? 'var(--color-green)' : 'var(--color-red)'}` }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <div>
                    <span style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>TRADITIONAL WAF (PORT 8080)</span>
                    <h3 style={{ color: wafRunning ? 'var(--color-green)' : 'var(--color-red)', marginTop: '5px' }}>
                      {wafRunning ? '🟢 SHIELD ACTIVE' : '🔴 OFFLINE (MANDATORY)'}
                    </h3>
                  </div>
                  <span style={{ fontSize: '0.75rem', padding: '3px 8px', borderRadius: '3px', background: wafRunning ? 'rgba(0, 255, 65, 0.15)' : 'rgba(255, 0, 85, 0.15)', color: wafRunning ? 'var(--color-green)' : 'var(--color-red)', border: `1px solid ${wafRunning ? 'var(--color-green)' : 'var(--color-red)'}` }}>
                    INLINE DETECTION
                  </span>
                </div>
              </div>

              <div className={`cyber-card ${aiRunning ? 'success' : 'critical'}`} style={{ borderLeft: `4px solid ${aiRunning ? 'var(--color-green)' : 'var(--color-red)'}` }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <div>
                    <span style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>AI FIREWALL (PORT 8081)</span>
                    <h3 style={{ color: aiRunning ? 'var(--color-green)' : 'var(--color-red)', marginTop: '5px' }}>
                      {aiRunning ? '🟢 SHIELD ACTIVE' : '🔴 OFFLINE (MANDATORY)'}
                    </h3>
                  </div>
                  <span style={{ fontSize: '0.75rem', padding: '3px 8px', borderRadius: '3px', background: aiRunning ? 'rgba(0, 255, 65, 0.15)' : 'rgba(255, 0, 85, 0.15)', color: aiRunning ? 'var(--color-green)' : 'var(--color-red)', border: `1px solid ${aiRunning ? 'var(--color-green)' : 'var(--color-red)'}` }}>
                    ANOMALY ENGINE
                  </span>
                </div>
              </div>
            </div>
            <div className="cyber-grid-4" style={{ marginBottom: '20px' }}>
              <div className="cyber-card success">
                <span style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>TARGET</span>
                <h3 style={{ fontSize: '1.2rem', color: 'var(--color-cyan)', textOverflow: 'ellipsis', overflow: 'hidden', whiteSpace: 'nowrap' }}>
                  {results.info.target}
                </h3>
              </div>
              <div className="cyber-card success">
                <span style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>IP ADDRESS</span>
                <h3 style={{ fontSize: '1.4rem', color: '#fff' }}>
                  {results.recon.ip_address}
                </h3>
              </div>
              <div className="cyber-card critical">
                <span style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>TOTAL VULNERABILITIES</span>
                <h3 style={{ fontSize: '1.6rem', color: 'var(--color-red)' }}>
                  {countTotalVulns()}
                </h3>
              </div>
              <div className="cyber-card warning">
                <span style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>FIREWALL ACTION</span>
                <h3 style={{ fontSize: '1.4rem', color: 'var(--color-yellow)' }}>
                  {results.defense_sim?.status || 'MONITORING'}
                </h3>
              </div>
            </div>

            <div className="cyber-grid-2">
              {/* Vuln distribution */}
              <div className="cyber-card">
                <h3 style={{ color: 'var(--color-cyan)', borderBottom: '1px solid var(--border-color)', paddingBottom: '10px', marginBottom: '15px' }}>
                  VULNERABILITY SPECTRUM
                </h3>
                <div style={{ width: '100%', height: '220px' }}>
                  <ResponsiveContainer>
                    <BarChart data={getVulnCounts()}>
                      <CartesianGrid strokeDasharray="3 3" stroke="var(--border-color)" />
                      <XAxis dataKey="name" stroke="var(--text-muted)" />
                      <YAxis stroke="var(--text-muted)" />
                      <Tooltip contentStyle={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-color)' }} />
                      <Bar dataKey="value" />
                    </BarChart>
                  </ResponsiveContainer>
                </div>
              </div>

              {/* Threat WMA Score */}
              <div className="cyber-card">
                <h3 style={{ color: 'var(--color-cyan)', borderBottom: '1px solid var(--border-color)', paddingBottom: '10px', marginBottom: '15px' }}>
                  WMA TRAFFIC THREAT DYNAMICS
                </h3>
                <div style={{ width: '100%', height: '220px' }}>
                  <ResponsiveContainer>
                    <AreaChart data={getThreatHistoryData()}>
                      <CartesianGrid strokeDasharray="3 3" stroke="var(--border-color)" />
                      <XAxis dataKey="step" stroke="var(--text-muted)" />
                      <YAxis stroke="var(--text-muted)" />
                      <Tooltip contentStyle={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-color)' }} />
                      <Area type="monotone" dataKey="score" stroke="var(--color-red)" fill="rgba(255, 0, 85, 0.2)" />
                    </AreaChart>
                  </ResponsiveContainer>
                </div>
              </div>
            </div>

            {/* CVSS Threat Matrix & Risk Profiler */}
            {getThreatMatrix() && (
              <div className="cyber-card" style={{ marginTop: '20px' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', borderBottom: '1px solid var(--border-color)', paddingBottom: '10px', marginBottom: '15px' }}>
                  <h3 style={{ color: 'var(--color-cyan)', display: 'flex', alignItems: 'center', gap: '8px' }}>
                    <ShieldAlert size={20} /> CVSS v3.1 THREAT MATRIX & RISK PROFILER
                  </h3>
                  <span className={`cvss-pill ${getThreatMatrix().maxCvss >= 9 ? 'critical' : getThreatMatrix().maxCvss >= 7 ? 'high' : getThreatMatrix().maxCvss >= 4 ? 'medium' : 'clean'}`}>
                    MAX RISK SCORE: {getThreatMatrix().maxCvss.toFixed(1)} / 10.0
                  </span>
                </div>

                <div className="cvss-breakdown-grid" style={{ marginBottom: '15px' }}>
                  <div className="cvss-metric-box" style={{ cursor: 'pointer' }} onClick={() => { setActiveTab('VULNERABILITIES'); setVulnSeverityFilter('CRITICAL'); }}>
                    <span className="label">🔴 CRITICAL RISKS</span>
                    <span className="val" style={{ color: 'var(--color-red)' }}>{getThreatMatrix().criticalCount} Findings</span>
                  </div>
                  <div className="cvss-metric-box" style={{ cursor: 'pointer' }} onClick={() => { setActiveTab('VULNERABILITIES'); setVulnSeverityFilter('HIGH'); }}>
                    <span className="label">🟠 HIGH RISKS</span>
                    <span className="val" style={{ color: '#ff7800' }}>{getThreatMatrix().highCount} Findings</span>
                  </div>
                  <div className="cvss-metric-box" style={{ cursor: 'pointer' }} onClick={() => { setActiveTab('VULNERABILITIES'); setVulnSeverityFilter('MEDIUM'); }}>
                    <span className="label">🟡 MEDIUM RISKS</span>
                    <span className="val" style={{ color: 'var(--color-yellow)' }}>{getThreatMatrix().mediumCount} Findings</span>
                  </div>
                  <div className="cvss-metric-box" style={{ cursor: 'pointer' }} onClick={() => { setActiveTab('VULNERABILITIES'); setVulnSeverityFilter('LOW'); }}>
                    <span className="label">🔵 LOW RISKS</span>
                    <span className="val" style={{ color: 'var(--color-cyan)' }}>{getThreatMatrix().lowCount} Findings</span>
                  </div>
                  <div className="cvss-metric-box">
                    <span className="label">EXPLOIT VECTOR</span>
                    <span className="val" style={{ color: '#fff' }}>Network (AV:N)</span>
                  </div>
                  <div className="cvss-metric-box">
                    <span className="label">AUTH PREREQUISITE</span>
                    <span className="val" style={{ color: 'var(--color-green)' }}>Unauthenticated</span>
                  </div>
                </div>

                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', background: '#070814', padding: '10px 15px', borderRadius: '4px', fontSize: '0.85rem' }}>
                  <span style={{ color: 'var(--text-secondary)' }}>
                    Active Audit Profile: <strong style={{ color: 'var(--color-cyan)' }}>{results.info.mode_description || results.info.scan_mode?.toUpperCase() || 'STANDARD'}</strong>
                  </span>
                  <button 
                    onClick={() => setActiveTab('VULNERABILITIES')} 
                    className="cyber-btn" 
                    style={{ padding: '4px 12px', fontSize: '0.75rem' }}
                  >
                    INSPECT ALL IN GRID &rarr;
                  </button>
                </div>
              </div>
            )}

            <div className="cyber-card" style={{ marginTop: '20px' }}>
              <h3 style={{ color: 'var(--color-cyan)', borderBottom: '1px solid var(--border-color)', paddingBottom: '10px', marginBottom: '15px' }}>
                TECHNOLOGY & HOST PROFILE
              </h3>
              <div className="cyber-grid-3">
                <div>
                  <span style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>SSL VERDICT:</span>
                  <p style={{ color: results.recon.ssl_info?.valid ? 'var(--color-green)' : 'var(--color-red)', marginTop: '5px' }}>
                    {results.recon.ssl_info?.valid 
                      ? `Valid (Expires in ${results.recon.ssl_info.days_remaining} days)` 
                      : `Invalid / Secure Connection Failed: ${results.recon.ssl_info?.error || 'N/A'}`
                    }
                  </p>
                </div>
                <div>
                  <span style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>WAF FINGERPRINT:</span>
                  <p style={{ color: '#fff', marginTop: '5px' }}>
                    {results.info.waf_detected?.join(', ') || 'None'}
                  </p>
                </div>
                <div>
                  <span style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>HTTP ARCHITECTURE:</span>
                  <p style={{ color: '#fff', marginTop: '5px' }}>
                    {results.info.http_version} {results.info.http2_enabled ? '(HTTP/2 Enabled)' : '(HTTP/1.1 Standard)'}
                  </p>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* Recon Tab */}
        {activeTab === 'RECON' && results && (
          <div className="cyber-grid-2">
            <div>
              <div className="cyber-card">
                <h3 style={{ color: 'var(--color-cyan)', borderBottom: '1px solid var(--border-color)', paddingBottom: '10px', marginBottom: '15px' }}>
                  OPEN TCP PORTS
                </h3>
                {results.recon.open_ports?.length > 0 ? (
                  <ul style={{ listStyleType: 'none' }}>
                    {results.recon.open_ports.map((port, idx) => (
                      <li key={idx} style={{ padding: '8px', borderBottom: '1px solid #1a1d2d', color: 'var(--color-yellow)' }}>
                        🔌 {port}
                      </li>
                    ))}
                  </ul>
                ) : (
                  <p style={{ color: 'var(--text-muted)' }}>No open service ports identified in basic scanner profile.</p>
                )}
              </div>

              <div className="cyber-card">
                <h3 style={{ color: 'var(--color-cyan)', borderBottom: '1px solid var(--border-color)', paddingBottom: '10px', marginBottom: '15px' }}>
                  ADMINISTRATIVE CONSOLE PATHS
                </h3>
                {results.recon.admin_pages_found?.length > 0 ? (
                  <ul style={{ listStyleType: 'none' }}>
                    {results.recon.admin_pages_found.map((page, idx) => (
                      <li key={idx} style={{ padding: '8px', borderBottom: '1px solid #1a1d2d', color: 'var(--color-red)' }}>
                        🚧 {page} (STATUS: 200 OK)
                      </li>
                    ))}
                  </ul>
                ) : (
                  <p style={{ color: 'var(--text-muted)' }}>No exposed admin login consoles discovered.</p>
                )}
              </div>
            </div>

            <div>
              <div className="cyber-card">
                <h3 style={{ color: 'var(--color-cyan)', borderBottom: '1px solid var(--border-color)', paddingBottom: '10px', marginBottom: '15px' }}>
                  SOFTWARE TECHNOLOGY STACK
                </h3>
                {Object.keys(results.recon.tech_stack || {}).length > 0 ? (
                  <table className="cyber-table">
                    <thead>
                      <tr>
                        <th>Tech / Component</th>
                        <th>Identified Version</th>
                      </tr>
                    </thead>
                    <tbody>
                      {Object.entries(results.recon.tech_stack).map(([name, ver]) => (
                        <tr key={name}>
                          <td>{name}</td>
                          <td style={{ color: 'var(--color-cyan)' }}>{ver}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                ) : (
                  <p style={{ color: 'var(--text-muted)' }}>No technology footprints detected via header / regex analysis.</p>
                )}
              </div>

              <div className="cyber-card">
                <h3 style={{ color: 'var(--color-cyan)', borderBottom: '1px solid var(--border-color)', paddingBottom: '10px', marginBottom: '15px' }}>
                  PASSIVE SUBDOMAINS (CRT.SH)
                </h3>
                <div style={{ maxHeight: '150px', overflowY: 'auto' }}>
                  {results.recon.subdomains?.length > 0 ? (
                    <ul style={{ listStyleType: 'none' }}>
                      {results.recon.subdomains.map((sub, idx) => (
                        <li key={idx} style={{ padding: '4px 0', color: 'var(--text-primary)' }}>
                          🌐 {sub}
                        </li>
                      ))}
                    </ul>
                  ) : (
                    <p style={{ color: 'var(--text-muted)' }}>No passive DNS subdomains cataloged.</p>
                  )}
                </div>
              </div>
            </div>
          </div>
        )}

        {/* Vulnerabilities Tab */}
        {activeTab === 'VULNERABILITIES' && results && (
          <div>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '15px' }}>
              <div>
                <h3 style={{ color: 'var(--color-cyan)', display: 'flex', alignItems: 'center', gap: '8px' }}>
                  <ShieldAlert size={20} /> OWASP TOP 10 DANGER GRID & CVSS AUDIT
                </h3>
                <p style={{ color: 'var(--text-secondary)', fontSize: '0.85rem', marginTop: '4px' }}>
                  Real-time vulnerability findings categorized by CVSS v3.1 severity, CWE classification, and automated ModSecurity defense patches.
                </p>
              </div>
            </div>

            {/* Filter Toolbar */}
            <div className="vuln-toolbar">
              <div className="vuln-search-box">
                <Search size={16} color="var(--text-muted)" />
                <input 
                  type="text" 
                  placeholder="Filter findings by name, CWE, payload signature..."
                  value={vulnSearch}
                  onChange={(e) => setVulnSearch(e.target.value)}
                />
                {vulnSearch && (
                  <button onClick={() => setVulnSearch('')} style={{ background: 'transparent', border: 'none', color: 'var(--text-muted)', cursor: 'pointer' }}>
                    <X size={14} />
                  </button>
                )}
              </div>

              <div className="filter-pills-row">
                {['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'CLEAN'].map((f) => (
                  <button
                    key={f}
                    onClick={() => setVulnSeverityFilter(f)}
                    className={`filter-pill-btn ${vulnSeverityFilter === f ? (f === 'CRITICAL' ? 'active critical' : 'active') : ''}`}
                  >
                    {f}
                  </button>
                ))}

                <button 
                  onClick={() => setHideCleanChecks(prev => !prev)}
                  className={`filter-pill-btn ${hideCleanChecks ? 'active' : ''}`}
                  style={{ marginLeft: '6px' }}
                >
                  {hideCleanChecks ? '✓ Hiding Clean Checks' : 'Show All Checks'}
                </button>
              </div>
            </div>

            {/* Vulnerabilities Grid */}
            <div className="cyber-grid-2">
              {VULNERABILITY_CATALOG
                .map(vuln => {
                  const desc = results.vulnerabilities[vuln.id];
                  const isSafe = Array.isArray(desc)
                    ? desc.length === 0 || desc[0]?.toString().includes("No ") || desc[0]?.toString().includes("Secure") || desc[0]?.toString().includes("Skipped")
                    : !desc || 
                      (typeof desc === 'object' 
                        ? Object.keys(desc).length === 0 
                        : desc.toString().includes("No ") || desc.toString().includes("Protected"));

                  return { ...vuln, desc, isSafe };
                })
                .filter(vuln => {
                  // Severity filter
                  if (vulnSeverityFilter === 'CLEAN') {
                    if (!vuln.isSafe) return false;
                  } else if (vulnSeverityFilter !== 'ALL') {
                    if (vuln.isSafe || vuln.severity !== vulnSeverityFilter) return false;
                  }

                  // Hide clean checks toggle
                  if (hideCleanChecks && vulnSeverityFilter === 'ALL' && vuln.isSafe) {
                    return false;
                  }

                  // Search keyword filter
                  if (vulnSearch.trim()) {
                    const q = vulnSearch.toLowerCase();
                    const titleMatch = vuln.title.toLowerCase().includes(q);
                    const cweMatch = vuln.cwe.toLowerCase().includes(q);
                    const descMatch = JSON.stringify(vuln.desc).toLowerCase().includes(q);
                    if (!titleMatch && !cweMatch && !descMatch) return false;
                  }

                  return true;
                })
                .map(vuln => {
                  return (
                    <div key={vuln.id} className={`cyber-card ${vuln.isSafe ? 'success' : 'critical'}`} style={{ display: 'flex', flexDirection: 'column', justifyContent: 'space-between' }}>
                      <div>
                        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', gap: '10px', marginBottom: '8px' }}>
                          <h4 style={{ color: vuln.isSafe ? 'var(--color-green)' : 'var(--color-red)', display: 'flex', alignItems: 'center', gap: '8px' }}>
                            {vuln.isSafe ? <CheckCircle2 size={18} /> : <AlertTriangle size={18} />} {vuln.title}
                          </h4>
                          <span className={`cvss-pill ${vuln.isSafe ? 'clean' : vuln.severity.toLowerCase()}`}>
                            {vuln.isSafe ? 'CLEAN' : `${vuln.severity} ${vuln.cvss_score}`}
                          </span>
                        </div>

                        <div style={{ display: 'flex', gap: '8px', marginBottom: '10px' }}>
                          <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)', background: '#090a14', padding: '2px 6px', borderRadius: '3px', border: '1px solid var(--border-color)' }}>
                            {vuln.cwe}
                          </span>
                          <span style={{ fontSize: '0.75rem', color: 'var(--color-cyan)', background: '#090a14', padding: '2px 6px', borderRadius: '3px', border: '1px solid var(--border-color)' }}>
                            {vuln.vector_summary}
                          </span>
                        </div>

                        <div style={{ fontSize: '0.9rem' }}>
                          {Array.isArray(vuln.desc) ? (
                            vuln.desc.length > 0 ? (
                              <ul style={{ paddingLeft: '20px' }}>
                                {vuln.desc.map((d, idx) => (
                                  <li key={idx} style={{ margin: '5px 0' }}>
                                    {typeof d === 'object' ? (
                                      <div>
                                        <strong style={{ color: 'var(--color-red)' }}>[{d.type}]</strong> in {d.file}
                                        <pre style={{ background: '#090a12', padding: '8px', overflowX: 'auto', marginTop: '5px', border: '1px solid #1a1d2d', color: '#ffb700' }}>
                                          {d.snippet}
                                        </pre>
                                      </div>
                                    ) : d}
                                  </li>
                                ))}
                              </ul>
                            ) : (
                              <span style={{ color: 'var(--text-muted)' }}>Secure / Checked. No findings.</span>
                            )
                          ) : typeof vuln.desc === 'object' && vuln.desc !== null ? (
                            Object.keys(vuln.desc).length > 0 ? (
                              <ul style={{ paddingLeft: '20px' }}>
                                {Object.entries(vuln.desc).map(([k, v]) => (
                                  <li key={k} style={{ margin: '5px 0' }}>
                                    <strong>{k}:</strong> {v}
                                  </li>
                                ))}
                              </ul>
                            ) : (
                              <span style={{ color: 'var(--text-muted)' }}>Secure / Checked. No exposed components.</span>
                            )
                          ) : (
                            <p style={{ color: 'var(--text-primary)' }}>{vuln.desc || 'Checked. No vulnerabilities detected.'}</p>
                          )}
                        </div>
                      </div>

                      <div style={{ marginTop: '15px', paddingTop: '10px', borderTop: '1px solid var(--border-color)', display: 'flex', justifyContent: 'flex-end' }}>
                        <button
                          onClick={() => setSelectedDossier(vuln)}
                          className="cyber-btn"
                          style={{ padding: '4px 12px', fontSize: '0.75rem', display: 'flex', alignItems: 'center', gap: '5px' }}
                        >
                          <FileText size={12} /> INSPECT DOSSIER & VIRTUAL PATCH
                        </button>
                      </div>
                    </div>
                  );
                })}
            </div>
          </div>
        )}

        {/* Infrastructure Tab */}
        {activeTab === 'INFRASTRUCTURE' && results && (
          <div className="cyber-grid-2">
            <div>
              <div className="cyber-card">
                <h3 style={{ color: 'var(--color-cyan)', borderBottom: '1px solid var(--border-color)', paddingBottom: '10px', marginBottom: '15px' }}>
                  CLOUD BUCKET ENUMERATION
                </h3>
                <ul style={{ listStyleType: 'none' }}>
                  {results.recon.cloud_buckets?.map((bucket, idx) => (
                    <li key={idx} style={{ padding: '8px', borderBottom: '1px solid #1a1d2d', color: bucket.includes('OPEN') ? 'var(--color-red)' : 'var(--text-secondary)' }}>
                      ☁️ {bucket}
                    </li>
                  ))}
                </ul>
              </div>

              <div className="cyber-card">
                <h3 style={{ color: 'var(--color-cyan)', borderBottom: '1px solid var(--border-color)', paddingBottom: '10px', marginBottom: '15px' }}>
                  DISCOVERED API ENDPOINTS
                </h3>
                <ul style={{ listStyleType: 'none' }}>
                  {results.recon.api_endpoints?.map((api, idx) => (
                    <li key={idx} style={{ padding: '8px', borderBottom: '1px solid #1a1d2d', color: 'var(--color-cyan)' }}>
                      ⚙️ {api}
                    </li>
                  ))}
                </ul>
              </div>
            </div>

            <div>
              <div className="cyber-card">
                <h3 style={{ color: 'var(--color-cyan)', borderBottom: '1px solid var(--border-color)', paddingBottom: '10px', marginBottom: '15px' }}>
                  DNS INTEL & ZONE CHECKS
                </h3>
                <div style={{ marginBottom: '15px' }}>
                  <span style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>REVERSE PTR RESOLUTION:</span>
                  <p style={{ marginTop: '5px', color: '#fff' }}>{results.recon.reverse_dns}</p>
                </div>
                <div style={{ marginBottom: '15px' }}>
                  <span style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>ZONE TRANSFER (AXFR):</span>
                  <p style={{ marginTop: '5px', color: results.vulnerabilities.A05_DNS_Zone_Transfer?.[0]?.includes('SUCCESS') ? 'var(--color-red)' : 'var(--color-green)' }}>
                    {results.vulnerabilities.A05_DNS_Zone_Transfer?.join(', ')}
                  </p>
                </div>
              </div>

              <div className="cyber-card">
                <h3 style={{ color: 'var(--color-cyan)', borderBottom: '1px solid var(--border-color)', paddingBottom: '10px', marginBottom: '15px' }}>
                  403/WAF HEADER BYPASS AUDIT
                </h3>
                <ul style={{ listStyleType: 'none' }}>
                  {results.vulnerabilities.A01_Bypass_Techniques?.map((bypass, idx) => (
                    <li key={idx} style={{ padding: '8px', borderBottom: '1px solid #1a1d2d', color: bypass.includes('Possible') ? 'var(--color-red)' : 'var(--text-muted)' }}>
                      🔓 {bypass}
                    </li>
                  ))}
                </ul>
              </div>
            </div>
          </div>
        )}

        {/* Content Tab */}
        {activeTab === 'CONTENT' && results && (
          <div className="cyber-grid-2">
            <div>
              <div className="cyber-card">
                <h3 style={{ color: 'var(--color-cyan)', borderBottom: '1px solid var(--border-color)', paddingBottom: '10px', marginBottom: '15px' }}>
                  PII DATA DISCOVERY
                </h3>
                <ul style={{ listStyleType: 'none' }}>
                  {results.vulnerabilities.A04_PII_Exposure?.map((pii, idx) => (
                    <li key={idx} style={{ padding: '8px', borderBottom: '1px solid #1a1d2d', color: pii.includes('found') ? 'var(--color-red)' : 'var(--text-muted)' }}>
                      👤 {pii}
                    </li>
                  ))}
                </ul>
              </div>

              <div className="cyber-card">
                <h3 style={{ color: 'var(--color-cyan)', borderBottom: '1px solid var(--border-color)', paddingBottom: '10px', marginBottom: '15px' }}>
                  DEVELOPER COMMENTS EXCAVATED
                </h3>
                <div style={{ maxHeight: '250px', overflowY: 'auto' }}>
                  {results.vulnerabilities.A05_Developer_Comments?.map((comm, idx) => (
                    <li key={idx} style={{ padding: '8px', borderBottom: '1px solid #1a1d2d', color: 'var(--color-yellow)', fontSize: '0.9rem' }}>
                      💬 {comm}
                    </li>
                  ))}
                </div>
              </div>
            </div>

            <div>
              <div className="cyber-card">
                <h3 style={{ color: 'var(--color-cyan)', borderBottom: '1px solid var(--border-color)', paddingBottom: '10px', marginBottom: '15px' }}>
                  SENSITIVE BACKUPS & DUSTY FILES
                </h3>
                <ul style={{ listStyleType: 'none' }}>
                  {results.vulnerabilities.A05_Sensitive_Backup_Files ? (
                    results.vulnerabilities.A05_Sensitive_Backup_Files.map((file, idx) => (
                      <li key={idx} style={{ padding: '8px', borderBottom: '1px solid #1a1d2d', color: 'var(--color-red)' }}>
                        💾 {file}
                      </li>
                    ))
                  ) : (
                    <p style={{ color: 'var(--text-muted)' }}>No backup files (e.g. .bak, .old, .zip) discovered on the host.</p>
                  )}
                </ul>
              </div>

              <div className="cyber-card">
                <h3 style={{ color: 'var(--color-cyan)', borderBottom: '1px solid var(--border-color)', paddingBottom: '10px', marginBottom: '15px' }}>
                  MIXED CONTENT & DANGEROUS SINKS
                </h3>
                <ul style={{ listStyleType: 'none' }}>
                  {results.vulnerabilities['A06_Mixed_Content_&_Sinks']?.map((sink, idx) => (
                    <li key={idx} style={{ padding: '8px', borderBottom: '1px solid #1a1d2d', color: 'var(--color-yellow)', fontSize: '0.9rem' }}>
                      ⚡ {sink}
                    </li>
                  ))}
                </ul>
              </div>
            </div>
          </div>
        )}

        {/* WAF Monitor Tab */}
        {activeTab === 'DEFENSE' && (
          <div>
            {/* Status Alert */}
            <div style={{ display: 'flex', gap: '15px', marginBottom: '20px' }}>
              <div style={{ flex: 1, padding: '12px 20px', background: wafRunning ? 'rgba(0,255,65,0.05)' : 'rgba(255,0,85,0.05)', border: `1px solid ${wafRunning ? 'var(--color-green)' : 'var(--color-red)'}`, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <span>SHIELD STATUS: <strong style={{ color: wafRunning ? 'var(--color-green)' : 'var(--color-red)' }}>{wafRunning ? '🟢 ONLINE & PROTECTING' : '🔴 OFFLINE (MANDATORY SERVICE NOT RUNNING)'}</strong></span>
                {!wafRunning && <span style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>Launch with: <code>python ironclad_waf.py</code> inside <code>backend/firewall</code></span>}
              </div>
            </div>

            <div className="cyber-card">
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', borderBottom: '1px solid var(--border-color)', paddingBottom: '15px', marginBottom: '20px' }}>
                <h3 style={{ color: 'var(--color-cyan)' }}>🛡️ IRONCLAD REVERSE-PROXY WAF EVENT LOGGER</h3>
                <button onClick={refreshWafAndAi} className="cyber-btn" style={{ padding: '5px 15px', fontSize: '0.8rem' }}>
                  <span style={{ display: 'flex', alignItems: 'center', gap: '5px' }}><RefreshCw size={12} /> REFRESH LOGS</span>
                </button>
              </div>

              <p style={{ color: 'var(--text-secondary)', marginBottom: '15px' }}>
                The reverse proxy WAF protects the backend application by sniffing traffic and blocking SQLi, XSS, Path Traversal, and rate floods.
              </p>

              <div className="cyber-terminal">
                {wafLogs.length > 0 ? (
                  wafLogs.map((log, idx) => (
                    <p key={idx} style={{ color: log.includes('BANNED') || log.includes('BLOCKED') ? 'var(--color-red)' : 'var(--color-green)' }}>
                      {log}
                    </p>
                  ))
                ) : (
                  <p style={{ color: 'var(--text-muted)' }}>No WAF logs found. Run the standalone WAF proxy to capture attacks.</p>
                )}
                <div ref={terminalEndRef}></div>
              </div>
            </div>

            {/* Whitelist / Blacklist Console */}
            <div className="cyber-grid-2" style={{ marginTop: '20px', marginBottom: '20px' }}>
              {/* Whitelist */}
              <div className="cyber-card">
                <h3 style={{ color: 'var(--color-green)', borderBottom: '1px solid var(--border-color)', paddingBottom: '10px', marginBottom: '15px' }}>
                  🟢 INLINE PROTECTION BYPASS WHITELIST
                </h3>
                <form onSubmit={handleAddWhitelist} style={{ display: 'flex', gap: '10px', marginBottom: '15px' }}>
                  <input 
                    type="text" 
                    placeholder="ENTER CLIENT IP TO WHITELIST..." 
                    value={newWhitelistIp} 
                    onChange={e => setNewWhitelistIp(e.target.value)} 
                    className="cyber-input"
                    style={{ flex: 1, padding: '5px 10px', fontSize: '0.9rem' }}
                  />
                  <button type="submit" className="cyber-btn active-green" style={{ padding: '5px 15px', fontSize: '0.9rem' }}>
                    + ADD IP
                  </button>
                </form>
                <div style={{ maxHeight: '180px', overflowY: 'auto' }}>
                  {wafConfig.whitelist?.length > 0 ? (
                    <table className="cyber-table">
                      <thead>
                        <tr>
                          <th>Whitelisted IP</th>
                          <th style={{ textAlign: 'right' }}>Actions</th>
                        </tr>
                      </thead>
                      <tbody>
                        {wafConfig.whitelist.map(ip => (
                          <tr key={ip}>
                            <td>{ip}</td>
                            <td style={{ textAlign: 'right' }}>
                              <button onClick={() => handleRemoveWhitelist(ip)} className="cyber-btn critical" style={{ padding: '2px 8px', fontSize: '0.8rem' }}>
                                REMOVE
                              </button>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  ) : (
                    <p style={{ color: 'var(--text-muted)', fontSize: '0.9rem' }}>Whitelist is currently empty. Whitelisted IPs bypass WAF inspections.</p>
                  )}
                </div>
              </div>

              {/* Blacklist */}
              <div className="cyber-card">
                <h3 style={{ color: 'var(--color-red)', borderBottom: '1px solid var(--border-color)', paddingBottom: '10px', marginBottom: '15px' }}>
                  🔴 PERMANENT CONCURRENT BLOCK LIST
                </h3>
                <form onSubmit={handleAddBlacklist} style={{ display: 'flex', gap: '10px', marginBottom: '15px' }}>
                  <input 
                    type="text" 
                    placeholder="ENTER CLIENT IP TO BLOCK..." 
                    value={newBlacklistIp} 
                    onChange={e => setNewBlacklistIp(e.target.value)} 
                    className="cyber-input"
                    style={{ flex: 1, padding: '5px 10px', fontSize: '0.9rem' }}
                  />
                  <button type="submit" className="cyber-btn critical" style={{ padding: '5px 15px', fontSize: '0.9rem' }}>
                    + BLOCK IP
                  </button>
                </form>
                <div style={{ maxHeight: '180px', overflowY: 'auto' }}>
                  {wafConfig.blacklist?.length > 0 ? (
                    <table className="cyber-table">
                      <thead>
                        <tr>
                          <th>Blacklisted IP</th>
                          <th style={{ textAlign: 'right' }}>Actions</th>
                        </tr>
                      </thead>
                      <tbody>
                        {wafConfig.blacklist.map(ip => (
                          <tr key={ip}>
                            <td>{ip}</td>
                            <td style={{ textAlign: 'right' }}>
                              <button onClick={() => handleRemoveBlacklist(ip)} className="cyber-btn critical" style={{ padding: '2px 8px', fontSize: '0.8rem' }}>
                                UNBLOCK
                              </button>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  ) : (
                    <p style={{ color: 'var(--text-muted)', fontSize: '0.9rem' }}>Blacklist is currently empty. Blacklisted IPs are rejected immediately.</p>
                  )}
                </div>
              </div>
            </div>

            {results?.defense_configs && (
              <div className="cyber-grid-2" style={{ marginTop: '20px' }}>
                <div className="cyber-card">
                  <h3 style={{ color: 'var(--color-cyan)', borderBottom: '1px solid var(--border-color)', paddingBottom: '10px', marginBottom: '15px' }}>
                    VIRTUAL PATCH: MODSECURITY RULES
                  </h3>
                  <pre style={{ background: '#030305', padding: '15px', color: 'var(--color-yellow)', border: '1px solid var(--border-color)', overflowX: 'auto', fontSize: '0.85rem' }}>
                    {results.defense_configs.waf}
                  </pre>
                </div>
                <div className="cyber-card">
                  <h3 style={{ color: 'var(--color-cyan)', borderBottom: '1px solid var(--border-color)', paddingBottom: '10px', marginBottom: '15px' }}>
                    NGINX HARDENING CONFS
                  </h3>
                  <pre style={{ background: '#030305', padding: '15px', color: 'var(--color-cyan)', border: '1px solid var(--border-color)', overflowX: 'auto', fontSize: '0.85rem' }}>
                    {results.defense_configs.headers?.nginx}
                  </pre>
                </div>
              </div>
            )}
          </div>
        )}

        {/* AI Firewall Tab */}
        {activeTab === 'AI_FIREWALL' && (
          <div>
            {/* Status Alert */}
            <div style={{ display: 'flex', gap: '15px', marginBottom: '20px' }}>
              <div style={{ flex: 1, padding: '12px 20px', background: aiRunning ? 'rgba(0,255,65,0.05)' : 'rgba(255,0,85,0.05)', border: `1px solid ${aiRunning ? 'var(--color-green)' : 'var(--color-red)'}`, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <span>SHIELD STATUS: <strong style={{ color: aiRunning ? 'var(--color-green)' : 'var(--color-red)' }}>{aiRunning ? '🟢 ONLINE & SHIELDING' : '🔴 OFFLINE (MANDATORY SERVICE NOT RUNNING)'}</strong></span>
                {!aiRunning && <span style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>Launch with: <code>python ai_firewall.py</code> inside <code>backend/firewall</code></span>}
              </div>
            </div>

            <div className="cyber-card">
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', borderBottom: '1px solid var(--border-color)', paddingBottom: '15px', marginBottom: '20px' }}>
                <h3 style={{ color: 'var(--color-cyan)' }}>🧠 MACHINE LEARNING ANOMALY DETECTION STATUS</h3>
                <button onClick={refreshWafAndAi} className="cyber-btn" style={{ padding: '5px 15px', fontSize: '0.8rem' }}>
                  <span style={{ display: 'flex', alignItems: 'center', gap: '5px' }}><RefreshCw size={12} /> REFRESH</span>
                </button>
              </div>

              <div className="cyber-grid-3" style={{ marginBottom: '25px' }}>
                <div className="cyber-card">
                  <span style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>MODEL TRAINED</span>
                  <h4 style={{ color: aiStatus.is_trained ? 'var(--color-green)' : 'var(--color-yellow)', fontSize: '1.3rem', marginTop: '5px' }}>
                    {aiStatus.is_trained ? 'YES (IsolationForest Active)' : 'NO (Learning Mode)'}
                  </h4>
                </div>
                <div className="cyber-card">
                  <span style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>CONTAMINATION RATE</span>
                  <h4 style={{ color: '#fff', fontSize: '1.3rem', marginTop: '5px' }}>
                    5% (0.05)
                  </h4>
                </div>
                <div className="cyber-card">
                  <span style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>INPUT ATTRIBUTES</span>
                  <h4 style={{ color: '#fff', fontSize: '1.3rem', marginTop: '5px' }}>
                    5 Dimensions
                  </h4>
                </div>
              </div>

              <div className="cyber-terminal">
                {aiStatus.logs?.length > 0 ? (
                  aiStatus.logs.map((log, idx) => (
                    <p key={idx} style={{ color: log.includes('ANOMALY') || log.includes('BLOCKED') ? 'var(--color-red)' : '#bd00ff' }}>
                      {log}
                    </p>
                  ))
                ) : (
                  <p style={{ color: 'var(--text-muted)' }}>No anomaly events caught. Connect traffic to port 8081 for AI protection.</p>
                )}
                <div ref={terminalEndRef}></div>
              </div>
            </div>

            {/* AI Model Reset & Tuning Panel */}
            <div className="cyber-card" style={{ marginTop: '20px', borderLeft: '4px solid var(--color-purple)' }}>
              <h3 style={{ color: 'var(--color-purple)', borderBottom: '1px solid var(--border-color)', paddingBottom: '10px', marginBottom: '15px' }}>
                ⚙️ MODEL ADMINISTRATION CONSOLE
              </h3>
              <p style={{ color: 'var(--text-secondary)', fontSize: '0.9rem', marginBottom: '15px' }}>
                If you want to clear the currently loaded model and retrain it from scratch with new baseline samples, trigger a model reset. This will wipe out <code>ai_model.pkl</code> and set the firewall proxy back to active learning mode.
              </p>
              <button 
                onClick={handleResetAiModel} 
                className="cyber-btn critical" 
                style={{ display: 'flex', alignItems: 'center', gap: '8px' }}
              >
                ⚠️ RESET ML MODEL & RETRAIN
              </button>
            </div>
          </div>
        )}

        {/* Cookies / Headers Tab */}
        {activeTab === 'HEADERS' && results && (
          <div className="cyber-grid-2">
            <div className="cyber-card">
              <h3 style={{ color: 'var(--color-cyan)', borderBottom: '1px solid var(--border-color)', paddingBottom: '10px', marginBottom: '15px' }}>
                ACTIVE COOKIE AUDIT
              </h3>
              {results.details.cookies?.length > 0 ? (
                <div style={{ overflowX: 'auto' }}>
                  <table className="cyber-table">
                    <thead>
                      <tr>
                        <th>Cookie Name</th>
                        <th>Secure</th>
                        <th>HttpOnly</th>
                      </tr>
                    </thead>
                    <tbody>
                      {results.details.cookies.map((cookie, idx) => (
                        <tr key={idx}>
                          <td>{cookie.Name}</td>
                          <td style={{ color: cookie.Secure ? 'var(--color-green)' : 'var(--color-red)' }}>
                            {cookie.Secure ? 'True' : 'Missing'}
                          </td>
                          <td style={{ color: cookie.HttpOnly ? 'var(--color-green)' : 'var(--color-red)' }}>
                            {cookie.HttpOnly ? 'True' : 'Missing'}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              ) : (
                <p style={{ color: 'var(--text-muted)' }}>No session cookies returned by server.</p>
              )}
            </div>

            <div className="cyber-card">
              <h3 style={{ color: 'var(--color-cyan)', borderBottom: '1px solid var(--border-color)', paddingBottom: '10px', marginBottom: '15px' }}>
                RAW HTTP RESPONSE HEADERS
              </h3>
              <div style={{ maxHeight: '300px', overflowY: 'auto', background: '#030305', padding: '10px', border: '1px solid var(--border-color)' }}>
                {results.details.response_headers ? (
                  Object.entries(results.details.response_headers).map(([k, v]) => (
                    <p key={k} style={{ fontSize: '0.85rem', marginBottom: '5px' }}>
                      <strong style={{ color: 'var(--color-cyan)' }}>{k}:</strong> <span style={{ color: 'var(--text-primary)' }}>{v}</span>
                    </p>
                  ))
                ) : (
                  <p style={{ color: 'var(--text-muted)' }}>No headers captured.</p>
                )}
              </div>
            </div>
          </div>
        )}

        {/* Remediation Tab */}
        {activeTab === 'REMEDIATION' && results && (
          <div className="cyber-card">
            <h3 style={{ color: 'var(--color-cyan)', borderBottom: '1px solid var(--border-color)', paddingBottom: '10px', marginBottom: '15px' }}>
              PRIORITIZED REMEDIATION ACTION PROTOCOL
            </h3>
            
            <p style={{ color: 'var(--text-secondary)', marginBottom: '20px' }}>
              Based on findings compiled by the scanner, follow this prioritized checklist to patch the host.
            </p>

            <ul style={{ listStyleType: 'none' }}>
              {[
                { 
                  id: 'secrets', 
                  title: 'Secure Hardcoded Secrets immediately', 
                  desc: 'Remove API keys, passwords, and tokens from all public or client-side JavaScript bundle files.', 
                  priority: 'HIGH_CRITICAL', 
                  triggered: results.vulnerabilities.CRITICAL_Hardcoded_Secrets?.length > 0 
                },
                { 
                  id: 'ssrf', 
                  title: 'Block Server-Side Request Forgery (SSRF)', 
                  desc: 'Validate all target endpoints against an explicit hostname whitelist and enforce strict firewall egress rules against RFC 1918 and cloud metadata IPs (169.254.169.254).', 
                  priority: 'HIGH_CRITICAL', 
                  triggered: results.vulnerabilities.A10_SSRF?.length > 0 && !results.vulnerabilities.A10_SSRF[0]?.includes('No SSRF') 
                },
                { 
                  id: 'lfi', 
                  title: 'Sanitize Filepath & Directory Parameters (LFI / Traversal)', 
                  desc: 'Enforce realpath() canonicalization, strip directory traversal tokens (../), and avoid passing user input into filesystem operations.', 
                  priority: 'HIGH_CRITICAL', 
                  triggered: results.vulnerabilities.A03_Path_Traversal_LFI?.length > 0 && !results.vulnerabilities.A03_Path_Traversal_LFI[0]?.includes('No simple') 
                },
                { 
                  id: 'nosql', 
                  title: 'Harden NoSQL Queries against Operator Injection', 
                  desc: 'Sanitize request bodies, strictly cast types, and disallow objects containing MongoDB operators ($gt, $ne, $where).', 
                  priority: 'HIGH_CRITICAL', 
                  triggered: results.vulnerabilities.A03_NoSQL_Injection?.length > 0 && !results.vulnerabilities.A03_NoSQL_Injection[0]?.includes('No NoSQL') 
                },
                { 
                  id: 'sqli', 
                  title: 'Implement Prepared Statements for SQL inputs', 
                  desc: 'Sanitize form variables and parameter bindings to stop SQL injection attacks.', 
                  priority: 'HIGH_CRITICAL', 
                  triggered: results.vulnerabilities.A03_Injection?.length > 0 && !results.vulnerabilities.A03_Injection[0]?.includes('No ') 
                },
                { 
                  id: 'xss', 
                  title: 'Encode server-side outputs / dynamic rendering', 
                  desc: 'Ensure all reflected URL query variables are filtered and encoded to prevent CSS/JS injection.', 
                  priority: 'MEDIUM', 
                  triggered: results.vulnerabilities.A07_XSS?.length > 0 && !results.vulnerabilities.A07_XSS[0]?.includes('No ') 
                },
                { 
                  id: 'headers', 
                  title: 'Inject standard security headers', 
                  desc: 'Enable CSP, X-Frame-Options, HSTS, and X-Content-Type-Options via Nginx or Apache server configurations.', 
                  priority: 'LOW_WARNING', 
                  triggered: results.vulnerabilities.A05_Security_Misconfig_Headers?.missing?.length > 0 
                },
                { 
                  id: 'cookies', 
                  title: 'Secure session cookie attributes', 
                  desc: 'Set the Secure, HttpOnly, and SameSite flags on all cookies parsed by backend sessions.', 
                  priority: 'MEDIUM', 
                  triggered: results.vulnerabilities.A02_Cryptographic_Failures?.some(x => x.includes('Cookie')) 
                }
              ].map((fix) => (
                <li key={fix.id} style={{ display: 'flex', gap: '15px', padding: '15px', borderBottom: '1px solid var(--border-color)', background: fix.triggered ? 'rgba(255, 0, 85, 0.02)' : 'transparent' }}>
                  <div style={{ marginTop: '3px' }}>
                    <input 
                      type="checkbox" 
                      defaultChecked={!fix.triggered} 
                      disabled 
                      style={{ cursor: 'not-allowed', accentColor: 'var(--color-green)', width: '18px', height: '18px' }} 
                    />
                  </div>
                  <div>
                    <h4 style={{ textDecoration: !fix.triggered ? 'line-through' : 'none', color: fix.triggered ? '#fff' : 'var(--text-muted)' }}>
                      {fix.title}
                    </h4>
                    <p style={{ fontSize: '0.9rem', color: fix.triggered ? 'var(--text-secondary)' : 'var(--text-muted)', marginTop: '5px' }}>
                      {fix.desc}
                    </p>
                    {fix.triggered && (
                      <span style={{ 
                        display: 'inline-block', 
                        fontSize: '0.75rem', 
                        padding: '2px 8px', 
                        borderRadius: '3px', 
                        marginTop: '8px', 
                        backgroundColor: fix.priority === 'HIGH_CRITICAL' ? 'rgba(255, 0, 85, 0.15)' : 'rgba(255, 183, 0, 0.15)',
                        color: fix.priority === 'HIGH_CRITICAL' ? 'var(--color-red)' : 'var(--color-yellow)',
                        border: `1px solid ${fix.priority === 'HIGH_CRITICAL' ? 'var(--color-red)' : 'var(--color-yellow)'}` 
                      }}>
                        {fix.priority}
                      </span>
                    )}
                  </div>
                </li>
              ))}
            </ul>
          </div>
        )}


        {/* Export Tab */}
        {activeTab === 'EXPORT' && results && (
          <div className="cyber-card" style={{ textAlign: 'center', padding: '50px' }}>
            <Download size={48} color="var(--color-cyan)" style={{ marginBottom: '20px' }} />
            <h3>COMPACT INTEL REPORT EXPORTS</h3>
            <p style={{ color: 'var(--text-secondary)', marginTop: '10px', marginBottom: '30px' }}>
              Download the pentesting database and mitigation guidelines for target {results.info.target} in various formats.
            </p>

            <div style={{ display: 'flex', justifyContent: 'center', gap: '20px', flexWrap: 'wrap' }}>
              <a href={scannerApi.getExportJsonUrl()} target="_blank" rel="noopener noreferrer" style={{ textDecoration: 'none' }}>
                <button className="cyber-btn active-green" style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                  <FileText size={18} /> DOWNLOAD JSON
                </button>
              </a>

              <a href={scannerApi.getExportCsvUrl()} target="_blank" rel="noopener noreferrer" style={{ textDecoration: 'none' }}>
                <button className="cyber-btn" style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                  <Database size={18} /> DOWNLOAD CSV
                </button>
              </a>

              <a href={scannerApi.getExportPdfUrl()} target="_blank" rel="noopener noreferrer" style={{ textDecoration: 'none' }}>
                <button className="cyber-btn critical" style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                  <Download size={18} /> GENERATE PDF REPORT
                </button>
              </a>
            </div>
          </div>
        )}
      </main>

      {/* Terminal Footer */}
      <footer className="cyber-card" style={{ borderLeftColor: 'var(--color-purple)' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px', borderBottom: '1px solid var(--border-color)', paddingBottom: '10px', marginBottom: '15px' }}>
          <Terminal size={18} color="var(--color-purple)" />
          <span style={{ fontSize: '0.9rem', letterSpacing: '1px', textTransform: 'uppercase', color: 'var(--color-purple)' }}>
            IRONCLAD SHELL CONSOLE
          </span>
        </div>
        <div className="cyber-terminal">
          {terminalOutput.map((log, idx) => (
            <p key={idx}>{log}</p>
          ))}
          <div ref={terminalEndRef}></div>
        </div>
      </footer>

      {/* Interactive Cyber Dossier & Virtual Patch Modal */}
      {selectedDossier && (
        <div className="cyber-modal-overlay" onClick={() => setSelectedDossier(null)}>
          <div className="cyber-modal-card" onClick={(e) => e.stopPropagation()}>
            <div className="cyber-modal-header">
              <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                <span className={`cvss-pill ${selectedDossier.isSafe ? 'clean' : selectedDossier.severity.toLowerCase()}`}>
                  {selectedDossier.isSafe ? 'CLEAN' : `${selectedDossier.severity} ${selectedDossier.cvss_score}`}
                </span>
                <h3 style={{ color: 'var(--text-primary)', fontSize: '1.05rem' }}>
                  {selectedDossier.title}
                </h3>
              </div>
              <button 
                onClick={() => setSelectedDossier(null)}
                style={{ background: 'transparent', border: 'none', color: 'var(--text-muted)', cursor: 'pointer' }}
              >
                <X size={20} />
              </button>
            </div>

            <div className="cyber-modal-body">
              {/* CVSS v3.1 Breakdown Grid */}
              <div className="cvss-breakdown-grid">
                <div className="cvss-metric-box">
                  <span className="label">CWE IDENTIFIER</span>
                  <span className="val">{selectedDossier.cwe}</span>
                </div>
                <div className="cvss-metric-box">
                  <span className="label">CVSS v3.1 BASE</span>
                  <span className="val" style={{ color: selectedDossier.cvss_score >= 9 ? 'var(--color-red)' : 'var(--color-yellow)' }}>
                    {selectedDossier.cvss_score} / 10.0
                  </span>
                </div>
                <div className="cvss-metric-box">
                  <span className="label">ATTACK VECTOR</span>
                  <span className="val">Network (AV:N)</span>
                </div>
                <div className="cvss-metric-box">
                  <span className="label">COMPLEXITY</span>
                  <span className="val">Low (AC:L)</span>
                </div>
                <div className="cvss-metric-box">
                  <span className="label">PRIVILEGES</span>
                  <span className="val">None (PR:N)</span>
                </div>
                <div className="cvss-metric-box">
                  <span className="label">USER INTERACTION</span>
                  <span className="val">None (UI:N)</span>
                </div>
              </div>

              {/* CVSS Vector String */}
              <div>
                <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)', textTransform: 'uppercase' }}>CVSS v3.1 Vector String</span>
                <div style={{ background: '#05060f', border: '1px solid var(--border-color)', padding: '8px 12px', borderRadius: '4px', marginTop: '5px', fontSize: '0.8rem', color: 'var(--color-cyan)', fontFamily: 'var(--font-mono)' }}>
                  {selectedDossier.cvss_vector}
                </div>
              </div>

              {/* Evidence / PoC block */}
              <div>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '6px' }}>
                  <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Audited Evidence / Finding Response</span>
                  <button 
                    onClick={() => handleCopyText(selectedDossier.desc, 'Evidence Copied to Clipboard!')}
                    className="filter-pill-btn"
                    style={{ fontSize: '0.7rem', padding: '2px 8px' }}
                  >
                    <Copy size={11} style={{ marginRight: '4px' }} /> Copy Finding
                  </button>
                </div>
                <div className="code-preview-box">
                  {Array.isArray(selectedDossier.desc) ? (
                    selectedDossier.desc.map((d, i) => (
                      <div key={i} style={{ marginBottom: '4px' }}>
                        {typeof d === 'object' ? JSON.stringify(d, null, 2) : d}
                      </div>
                    ))
                  ) : typeof selectedDossier.desc === 'object' ? (
                    JSON.stringify(selectedDossier.desc, null, 2)
                  ) : (
                    selectedDossier.desc || 'No payload triggered.'
                  )}
                </div>
              </div>

              {/* Developer Remediation Advice */}
              <div style={{ background: 'rgba(0, 210, 255, 0.05)', border: '1px solid rgba(0, 210, 255, 0.2)', padding: '14px', borderRadius: '6px' }}>
                <h4 style={{ color: 'var(--color-cyan)', fontSize: '0.9rem', marginBottom: '6px' }}>
                  🛡️ DEVELOPER REMEDIATION DIRECTIVE
                </h4>
                <p style={{ color: 'var(--text-primary)', fontSize: '0.85rem', lineHeight: '1.5' }}>
                  {selectedDossier.remediation}
                </p>
              </div>

              {/* ModSecurity Virtual Patch Rule */}
              <div>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '6px' }}>
                  <span style={{ fontSize: '0.75rem', color: 'var(--color-yellow)', textTransform: 'uppercase' }}>⚡ Automated ModSecurity Virtual Defense Patch</span>
                  <button 
                    onClick={() => handleCopyText(selectedDossier.virtual_patch, 'ModSecurity Patch Copied to Clipboard!')}
                    className="filter-pill-btn"
                    style={{ fontSize: '0.7rem', padding: '2px 8px', borderColor: 'var(--color-yellow)', color: 'var(--color-yellow)' }}
                  >
                    <Copy size={11} style={{ marginRight: '4px' }} /> Copy Rule
                  </button>
                </div>
                <div className="code-preview-box" style={{ color: 'var(--color-green)' }}>
                  {selectedDossier.virtual_patch}
                </div>
              </div>

              {copyToast && (
                <div style={{ textAlign: 'center', padding: '6px', background: 'rgba(0, 255, 65, 0.15)', border: '1px solid var(--color-green)', color: 'var(--color-green)', borderRadius: '4px', fontSize: '0.8rem' }}>
                  ✓ {copyToast}
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
