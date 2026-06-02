const API_BASE = import.meta.env.VITE_API_BASE_URL?.replace(/\/$/, '') || 'http://localhost:8000';

export const scannerApi = {
  async startScan(url) {
    const response = await fetch(`${API_BASE}/api/scan`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ url }),
    });
    if (!response.ok) {
      const err = await response.json();
      throw new Error(err.detail || 'Failed to start scan.');
    }
    return response.json();
  },

  async getScanStatus() {
    const response = await fetch(`${API_BASE}/api/scan/status`);
    if (!response.ok) {
      throw new Error('Failed to retrieve scan status.');
    }
    return response.json();
  },

  async getWafLogs() {
    const response = await fetch(`${API_BASE}/api/waf/logs`);
    if (!response.ok) {
      throw new Error('Failed to retrieve WAF logs.');
    }
    return response.json();
  },

  async getAiStatus() {
    const response = await fetch(`${API_BASE}/api/ai/status`);
    if (!response.ok) {
      throw new Error('Failed to retrieve AI Firewall status.');
    }
    return response.json();
  },

  async getWafConfig() {
    const response = await fetch(`${API_BASE}/api/waf/config`);
    if (!response.ok) {
      throw new Error('Failed to retrieve WAF configuration.');
    }
    return response.json();
  },

  async addBlacklist(ip) {
    const response = await fetch(`${API_BASE}/api/waf/config/blacklist`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ ip }),
    });
    if (!response.ok) {
      throw new Error('Failed to add IP to blacklist.');
    }
    return response.json();
  },

  async addWhitelist(ip) {
    const response = await fetch(`${API_BASE}/api/waf/config/whitelist`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ ip }),
    });
    if (!response.ok) {
      throw new Error('Failed to add IP to whitelist.');
    }
    return response.json();
  },

  async removeBlacklist(ip) {
    const response = await fetch(`${API_BASE}/api/waf/config/blacklist/${ip}`, {
      method: 'DELETE',
    });
    if (!response.ok) {
      throw new Error('Failed to remove IP from blacklist.');
    }
    return response.json();
  },

  async removeWhitelist(ip) {
    const response = await fetch(`${API_BASE}/api/waf/config/whitelist/${ip}`, {
      method: 'DELETE',
    });
    if (!response.ok) {
      throw new Error('Failed to remove IP from whitelist.');
    }
    return response.json();
  },

  async resetAiModel() {
    const response = await fetch(`${API_BASE}/api/ai/config/reset`, {
      method: 'POST',
    });
    if (!response.ok) {
      throw new Error('Failed to reset AI model.');
    }
    return response.json();
  },

  getExportJsonUrl() {
    return `${API_BASE}/api/export/json`;
  },

  getExportCsvUrl() {
    return `${API_BASE}/api/export/csv`;
  },

  getExportPdfUrl() {
    return `${API_BASE}/api/export/pdf`;
  }
};
