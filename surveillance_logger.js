// HelioRa Professional Surveillance Logging System
// Forensic-grade logging for security investigations

'use strict';

class SurveillanceLogger {
  constructor() {
    this.logs = [];
    this.maxLogs = 1000;
    this.anonymizedMode = false;
    this.sessionId = this.generateSessionId();
    this.startTime = Date.now();
    
    this.loadSettings();
  }
  
  // Generate unique session ID
  generateSessionId() {
    return `session_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }
  
  // Load logging settings
  async loadSettings() {
    try {
      const result = await chrome.storage.local.get(['loggingSettings', 'surveillanceLog']);
      
      if (result.loggingSettings) {
        this.anonymizedMode = result.loggingSettings.anonymizedMode || false;
      }
      
      if (result.surveillanceLog) {
        this.logs = result.surveillanceLog;
      }
      
      console.log('[HelioRa Logger] Initialized:', {
        anonymizedMode: this.anonymizedMode,
        logCount: this.logs.length,
        sessionId: this.sessionId
      });
    } catch (error) {
      console.error('[HelioRa Logger] Failed to load settings:', error);
    }
  }
  
  // Log a surveillance attempt
  log(entry) {
    const timestamp = new Date().toISOString();
    
    // Build log entry according to schema
    const logEntry = {
      // Core fields
      timestamp,
      session_id: this.sessionId,
      
      // Threat information
      url: this.anonymizedMode ? this.anonymizeUrl(entry.url) : entry.url,
      domain: entry.domain,
      threat_type: entry.type,
      blocked: entry.blocked,
      
      // Risk assessment
      risk_score: this.calculateRiskScore(entry),
      action_taken: entry.blocked ? 'BLOCKED' : 'ALLOWED',
      
      // Additional context
      is_tunnel: entry.isTunnel || false,
      is_suspicious: entry.isSuspicious || false,
      referrer: this.anonymizedMode ? this.anonymizeDomain(entry.referrer) : entry.referrer,
      
      // Technical details
      constraints: entry.constraints,
      method: entry.method,
      user_agent: this.anonymizedMode ? 'REDACTED' : navigator.userAgent,
      
      // Custom metadata
      ...entry.metadata
    };
    
    // Add to logs
    this.logs.push(logEntry);
    
    // Keep only latest logs
    if (this.logs.length > this.maxLogs) {
      this.logs.shift();
    }
    
    // Save to storage
    this.saveLogs();
    
    // Console output with color coding
    const color = entry.blocked ? '#4CAF50' : '#FF9800';
    console.log(
      `%c[HelioRa Logger] ${entry.blocked ? '🛡️ BLOCKED' : '✅ ALLOWED'} ${entry.type}`,
      `color: ${color}; font-weight: bold`,
      logEntry
    );
    
    return logEntry;
  }
  
  // Calculate risk score based on entry
  calculateRiskScore(entry) {
    let score = 0;
    
    // High risk: Tunnel domains
    if (entry.isTunnel) score += 70;
    
    // High risk: Suspicious patterns
    if (entry.isSuspicious) score += 50;
    
    // Medium risk: Third-party data exfiltration
    if (entry.type === 'xhr-exfiltration' || entry.type === 'fetch-exfiltration') score += 80;
    
    // Medium risk: Clipboard access
    if (entry.type === 'clipboard.readText' || entry.type === 'clipboard.read') score += 40;
    
    // Medium risk: Screen capture
    if (entry.type === 'getDisplayMedia') score += 60;
    
    // High risk: Camera/Microphone
    if (entry.type === 'getUserMedia') {
      const hasVideo = entry.constraints?.video;
      const hasAudio = entry.constraints?.audio;
      
      if (hasVideo && hasAudio) score += 70;
      else if (hasVideo) score += 60;
      else if (hasAudio) score += 50;
    }
    
    // High risk: WebRTC on suspicious sites
    if (entry.type === 'RTCPeerConnection' && entry.isSuspicious) score += 65;
    
    // Medium risk: Geolocation
    if (entry.type === 'geolocation') score += 45;
    
    return Math.min(100, score);
  }
  
  // Anonymize URL (remove query params and path)
  anonymizeUrl(url) {
    if (!url) return 'REDACTED';
    
    try {
      const urlObj = new URL(url);
      return `${urlObj.protocol}//${urlObj.hostname}/`; // Keep only protocol and domain
    } catch {
      return 'INVALID_URL';
    }
  }
  
  // Anonymize domain (keep only TLD)
  anonymizeDomain(url) {
    if (!url) return 'REDACTED';
    
    try {
      const urlObj = new URL(url);
      const parts = urlObj.hostname.split('.');
      
      if (parts.length >= 2) {
        const tld = parts.slice(-2).join('.');
        return `*.${tld}`;
      }
      
      return urlObj.hostname;
    } catch {
      return 'REDACTED';
    }
  }
  
  // Save logs to storage
  async saveLogs() {
    try {
      await chrome.storage.local.set({
        surveillanceLog: this.logs,
        lastSaved: Date.now()
      });
    } catch (error) {
      console.error('[HelioRa Logger] Failed to save logs:', error);
    }
  }
  
  // Get all logs
  getAllLogs() {
    return [...this.logs]; // Return copy
  }
  
  // Get logs by threat type
  getLogsByType(type) {
    return this.logs.filter(log => log.threat_type === type);
  }
  
  // Get logs by domain
  getLogsByDomain(domain) {
    return this.logs.filter(log => log.domain === domain);
  }
  
  // Get blocked logs only
  getBlockedLogs() {
    return this.logs.filter(log => log.blocked);
  }
  
  // Get high-risk logs (score >= 60)
  getHighRiskLogs() {
    return this.logs.filter(log => log.risk_score >= 60);
  }
  
  // Get logs within time range
  getLogsByTimeRange(startTime, endTime) {
    return this.logs.filter(log => {
      const timestamp = new Date(log.timestamp).getTime();
      return timestamp >= startTime && timestamp <= endTime;
    });
  }
  
  // Get statistics
  getStatistics() {
    const total = this.logs.length;
    const blocked = this.logs.filter(log => log.blocked).length;
    const allowed = total - blocked;
    const highRisk = this.logs.filter(log => log.risk_score >= 60).length;
    
    // Count by threat type
    const byType = {};
    this.logs.forEach(log => {
      byType[log.threat_type] = (byType[log.threat_type] || 0) + 1;
    });
    
    // Count by domain
    const byDomain = {};
    this.logs.forEach(log => {
      byDomain[log.domain] = (byDomain[log.domain] || 0) + 1;
    });
    
    // Top domains by log count
    const topDomains = Object.entries(byDomain)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 10)
      .map(([domain, count]) => ({ domain, count }));
    
    return {
      total,
      blocked,
      allowed,
      highRisk,
      blockRate: total > 0 ? ((blocked / total) * 100).toFixed(1) : 0,
      byType,
      topDomains,
      sessionId: this.sessionId,
      sessionDuration: Date.now() - this.startTime,
      anonymizedMode: this.anonymizedMode
    };
  }
  
  // Export logs as JSON
  exportJSON() {
    const exportData = {
      metadata: {
        exportedAt: new Date().toISOString(),
        version: '5.0.0',
        sessionId: this.sessionId,
        sessionDuration: Date.now() - this.startTime,
        anonymizedMode: this.anonymizedMode,
        logCount: this.logs.length
      },
      statistics: this.getStatistics(),
      logs: this.logs
    };
    
    return JSON.stringify(exportData, null, 2);
  }
  
  // Export logs as CSV
  exportCSV() {
    const headers = [
      'Timestamp',
      'Session ID',
      'Domain',
      'Threat Type',
      'Risk Score',
      'Action Taken',
      'Is Tunnel',
      'Is Suspicious',
      'URL'
    ];
    
    const rows = this.logs.map(log => [
      log.timestamp,
      log.session_id,
      log.domain,
      log.threat_type,
      log.risk_score,
      log.action_taken,
      log.is_tunnel,
      log.is_suspicious,
      log.url
    ]);
    
    const csvContent = [
      headers.join(','),
      ...rows.map(row => row.map(cell => `"${cell}"`).join(','))
    ].join('\n');
    
    return csvContent;
  }
  
  // Export forensic report (text format)
  exportForensicReport() {
    const stats = this.getStatistics();
    
    let report = `
╔════════════════════════════════════════════════════════════════╗
║          HELIORA SURVEILLANCE FORENSIC REPORT                 ║
╚════════════════════════════════════════════════════════════════╝

Generated: ${new Date().toISOString()}
Session ID: ${this.sessionId}
Session Duration: ${Math.round(stats.sessionDuration / 1000 / 60)} minutes
Anonymized Mode: ${this.anonymizedMode ? 'ENABLED' : 'DISABLED'}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

📊 SUMMARY STATISTICS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Total Surveillance Attempts:  ${stats.total}
Blocked:                      ${stats.blocked} (${stats.blockRate}%)
Allowed:                      ${stats.allowed}
High Risk (Score >= 60):      ${stats.highRisk}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

🎯 THREATS BY TYPE
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

`;
    
    Object.entries(stats.byType).forEach(([type, count]) => {
      report += `• ${type.padEnd(30)} ${count}\n`;
    });
    
    report += `\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n`;
    report += `🔝 TOP DOMAINS BY ACTIVITY\n`;
    report += `━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n`;
    
    stats.topDomains.forEach((item, i) => {
      report += `${i + 1}. ${item.domain.padEnd(40)} ${item.count} attempts\n`;
    });
    
    // High-risk events
    const highRiskLogs = this.getHighRiskLogs();
    
    report += `\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n`;
    report += `⚠️  HIGH-RISK EVENTS (${highRiskLogs.length} total)\n`;
    report += `━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n`;
    
    if (highRiskLogs.length === 0) {
      report += `✓ No high-risk surveillance attempts detected.\n`;
    } else {
      highRiskLogs.slice(0, 20).forEach((log, i) => {
        report += `${i + 1}. ${log.domain}\n`;
        report += `   Time:        ${new Date(log.timestamp).toLocaleString()}\n`;
        report += `   Type:        ${log.threat_type}\n`;
        report += `   Risk Score:  ${log.risk_score}/100\n`;
        report += `   Action:      ${log.action_taken}\n`;
        report += `   Tunnel:      ${log.is_tunnel ? 'YES ⚠️' : 'NO'}\n`;
        report += `   Suspicious:  ${log.is_suspicious ? 'YES ⚠️' : 'NO'}\n`;
        report += `\n`;
      });
      
      if (highRiskLogs.length > 20) {
        report += `... and ${highRiskLogs.length - 20} more high-risk events.\n\n`;
      }
    }
    
    report += `━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n`;
    report += `📝 ANALYSIS NOTES\n`;
    report += `━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n`;
    report += `This forensic report documents all surveillance API usage detected\n`;
    report += `during your browsing session. This data can be used as evidence for\n`;
    report += `security investigations or law enforcement reporting.\n\n`;
    report += `KEY INDICATORS:\n`;
    report += `• Tunnel domains (ngrok, cloudflare tunnel): CamPhish-style attacks\n`;
    report += `• getUserMedia on suspicious sites: Unauthorized camera/mic access\n`;
    report += `• getDisplayMedia: Screen capture attempts\n`;
    report += `• RTCPeerConnection: WebRTC IP leak attempts\n`;
    report += `• clipboard.readText: Password/data stealing\n`;
    report += `• xhr/fetch-exfiltration: Credential theft to third-party servers\n\n`;
    report += `PRIVACY NOTICE:\n`;
    report += `${this.anonymizedMode ? 
      '✓ This report uses anonymized URLs (paths and query params removed).\n' :
      '⚠️  This report contains full URLs. Enable Privacy Mode for anonymized logs.\n'
    }\n`;
    report += `━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n`;
    report += `Generated by HelioRa Security Platform v5.0.0\n`;
    report += `Created by Anshul Saxena\n`;
    report += `GitHub: github.com/AnshulAlgoS/HelioRa\n\n`;
    report += `━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n`;
    report += `END OF FORENSIC REPORT\n`;
    
    return report;
  }
  
  // Toggle anonymized mode
  async setAnonymizedMode(enabled) {
    this.anonymizedMode = enabled;
    
    await chrome.storage.local.set({
      loggingSettings: {
        anonymizedMode: enabled
      }
    });
    
    console.log('[HelioRa Logger] Anonymized mode:', enabled ? 'ENABLED' : 'DISABLED');
  }
  
  // Clear all logs
  async clearLogs() {
    this.logs = [];
    await chrome.storage.local.set({
      surveillanceLog: []
    });
    
    console.log('[HelioRa Logger] All logs cleared');
  }
  
  // Clear old logs (older than X days)
  async clearOldLogs(days = 30) {
    const cutoffTime = Date.now() - (days * 24 * 60 * 60 * 1000);
    
    this.logs = this.logs.filter(log => {
      const logTime = new Date(log.timestamp).getTime();
      return logTime >= cutoffTime;
    });
    
    await this.saveLogs();
    
    console.log('[HelioRa Logger] Cleared logs older than', days, 'days');
  }
}

// Export for use in service worker
if (typeof module !== 'undefined' && module.exports) {
  module.exports = SurveillanceLogger;
}
