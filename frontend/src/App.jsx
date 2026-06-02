import React, { useState, useEffect, useRef } from 'react';
import { 
  Shield, Activity, Terminal, AlertTriangle, Cpu, Globe, 
  Database, FileText, CheckSquare, Download, Play, RefreshCw, CheckCircle2, AlertCircle, Info, ExternalLink
} from 'lucide-react';
import { 
  ResponsiveContainer, AreaChart, Area, BarChart, Bar, XAxis, YAxis, Tooltip, CartesianGrid 
} from 'recharts';
import { scannerApi } from './api/scanner';
import './App.css';

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
  
  const terminalEndRef = useRef(null);

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
      appendLog('INITIALIZE', `Acquiring target lock on: ${targetUrl}`);
      
      const response = await scannerApi.startScan(targetUrl);
      setScanState({
        status: 'scanning',
        url: targetUrl,
        results: null,
        error: null
      });
      setLoading(false);
      appendLog('INITIALIZE', 'Scan launched. Background execution threads spawned.');
    } catch (err) {
      setLoading(false);
      appendLog('ERROR', err.message);
      alert(err.message);
    }
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
    
    // Categorize by severity
    let critical = 0;
    let high = 0;
    let medium = 0;
    let low = 0;
    let info = 0;

    const vulns = results.vulnerabilities;
    
    // Simple rules for parsing categories
    Object.keys(vulns).forEach(key => {
      const details = vulns[key];
      const isVulnerable = Array.isArray(details) 
        ? details.length > 0 && !details[0]?.toString().includes("No ") && !details[0]?.toString().includes("Secure")
        : details && !details.toString().includes("No ") && !details.toString().includes("Protected");
      
      if (isVulnerable) {
        if (key.includes('CRITICAL') || key.includes('SSTI') || key.includes('Secrets')) critical++;
        else if (key.includes('A03') || key.includes('Injection') || key.includes('Command')) high++;
        else if (key.includes('A01') || key.includes('A02') || key.includes('Access')) medium++;
        else if (key.includes('A05') || key.includes('A06') || key.includes('Headers')) low++;
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
              <Play size={18} /> TARGET ACQUIRE
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
            <h3 style={{ color: 'var(--color-cyan)', marginBottom: '15px' }}>OWASP TOP 10 DANGER GRID</h3>
            <div className="cyber-grid-2">
              {[
                { 
                  id: 'A01_Broken_Access_Control', 
                  title: 'A01: Broken Access Control', 
                  desc: results.vulnerabilities.A01_Broken_Access_Control 
                },
                { 
                  id: 'A02_Cryptographic_Failures', 
                  title: 'A02: Cryptographic Failures', 
                  desc: results.vulnerabilities.A02_Cryptographic_Failures 
                },
                { 
                  id: 'A03_Injection', 
                  title: 'A03: SQL Injection Risks', 
                  desc: results.vulnerabilities.A03_Injection 
                },
                { 
                  id: 'A03_Command_Injection', 
                  title: 'A03: OS Command Injection', 
                  desc: results.vulnerabilities.A03_Command_Injection 
                },
                { 
                  id: 'A05_Security_Misconfig_Headers', 
                  title: 'A05: Security Misconfigurations (Missing Headers)', 
                  desc: results.vulnerabilities.A05_Security_Misconfig_Headers?.missing 
                },
                { 
                  id: 'A06_Vulnerable_Components', 
                  title: 'A06: Vulnerable Third-Party Components', 
                  desc: results.vulnerabilities.A06_Vulnerable_Components 
                },
                { 
                  id: 'A07_XSS', 
                  title: 'A07: Reflected Cross-Site Scripting (XSS)', 
                  desc: results.vulnerabilities.A07_XSS 
                },
                { 
                  id: 'CRITICAL_Hardcoded_Secrets', 
                  title: 'CRITICAL: Hardcoded API Keys / Secrets', 
                  desc: results.vulnerabilities.CRITICAL_Hardcoded_Secrets 
                }
              ].map(vuln => {
                const isSafe = Array.isArray(vuln.desc)
                  ? vuln.desc.length === 0 || vuln.desc[0]?.toString().includes("No ") || vuln.desc[0]?.toString().includes("Secure")
                  : !vuln.desc || 
                    (typeof vuln.desc === 'object' 
                      ? Object.keys(vuln.desc).length === 0 
                      : vuln.desc.toString().includes("No ") || vuln.desc.toString().includes("Protected"));
                  
                return (
                  <div key={vuln.id} className={`cyber-card ${isSafe ? 'success' : 'critical'}`}>
                    <h4 style={{ color: isSafe ? 'var(--color-green)' : 'var(--color-red)', display: 'flex', alignItems: 'center', gap: '8px' }}>
                      {isSafe ? <CheckCircle2 size={18} /> : <AlertTriangle size={18} />} {vuln.title}
                    </h4>
                    <div style={{ marginTop: '10px', fontSize: '0.9rem' }}>
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
                  desc: 'Set the Secure and HttpOnly flags on all cookies parsed by backend sessions.', 
                  priority: 'MEDIUM', 
                  triggered: results.vulnerabilities.A02_Cryptographic_Failures?.some(x => x.includes('Cookie')) 
                }
              ].map((fix, idx) => (
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
    </div>
  );
}
