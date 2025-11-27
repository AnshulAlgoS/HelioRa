'use strict';

console.log('[HelioRa Popup] Initializing...');

// Get elements
const elements = {
  statusTitle: document.getElementById('statusTitle'),
  statusDomain: document.getElementById('statusDomain'),
  statusDescription: document.getElementById('statusDescription'),
  statusIcon: document.getElementById('statusIcon'),
  riskScore: document.getElementById('riskScoreLarge'),
  adsBlocked: document.getElementById('adsBlocked'),
  trackersBlocked: document.getElementById('trackersBlocked'),
  threatsBlocked: document.getElementById('threatsBlocked'),
  timeline: document.getElementById('timelineList'),
  timelineSection: document.getElementById('timelineSection'),
  securityStatus: document.getElementById('securityStatus'),
  firewallSelect: document.getElementById('firewallRuleSelect'),
  blacklistContainer: document.getElementById('blacklistContainer'),
  aiAnalysis: document.getElementById('aiAnalysis'),
  aiAnalysisText: document.getElementById('aiAnalysisText')
};

let currentDomain = null;
let currentAiAnalysis = null; // Store AI analysis to prevent reloading

// Load data immediately when popup opens
document.addEventListener('DOMContentLoaded', async () => {
  console.log('[HelioRa Popup] DOM loaded, loading data...');
  await loadAllData();
  setupEventListeners();
  
  // Auto-refresh stats only (not AI analysis) every 5 seconds
  setInterval(async () => {
    try {
      const [statsResponse] = await Promise.all([
        chrome.runtime.sendMessage({ action: 'getStats' })
      ]);
      
      if (statsResponse?.stats) {
        updateStats(statsResponse.stats);
      }
    } catch (error) {
      console.error('[HelioRa Popup] Error refreshing stats:', error);
    }
  }, 5000);
});

async function loadAllData() {
  try {
    // Get all data in parallel
    const [domainInfo, statsResponse, settings] = await Promise.all([
      chrome.runtime.sendMessage({ action: 'getDomainInfo' }),
      chrome.runtime.sendMessage({ action: 'getStats' }),
      chrome.runtime.sendMessage({ action: 'getSettings' })
    ]);
    
    console.log('[HelioRa Popup] Data loaded:', { domainInfo, statsResponse, settings });
    
    // Update UI
    if (domainInfo) {
      currentDomain = domainInfo.domain;
      updateDomainInfo(domainInfo);
      await loadFirewallRule(domainInfo.domain);
    }
    
    if (statsResponse?.stats) {
      updateStats(statsResponse.stats);
    }
    
    if (settings?.settings) {
      updateSettingsUI(settings.settings);
    }
    
    // Load blacklist
    await loadBlacklist();
    
  } catch (error) {
    console.error('[HelioRa Popup] Error loading data:', error);
  }
}

function updateDomainInfo(data) {
  if (!data) return;
  
  console.log('[HelioRa Popup] Updating domain info:', data);
  
  // Check fraud history
  checkFraudHistory(data.domain);
  
  // Update domain name
  if (elements.statusDomain) {
    elements.statusDomain.textContent = data.domain || 'Unknown';
  }
  
  // Update risk score (use fraud score if higher)
  if (elements.riskScore) {
    const displayScore = Math.max(data.riskScore || 0, data.fraudScore || 0);
    elements.riskScore.textContent = displayScore;
  }
  
  // Update status
  const statusMap = {
    dangerous: {
      title: '⚠️ Dangerous Site',
      icon: '✕',
      class: 'status-dangerous',
      desc: 'High risk detected'
    },
    suspicious: {
      title: '⚠ Suspicious Site',
      icon: '!',
      class: 'status-suspicious',
      desc: 'Potentially unsafe'
    },
    safe: {
      title: '✓ Secure Site',
      icon: '✓',
      class: 'status-safe',
      desc: 'No threats detected'
    }
  };
  
  const config = statusMap[data.status] || statusMap.safe;
  
  if (elements.statusTitle) {
    elements.statusTitle.textContent = config.title;
  }
  
  if (elements.statusIcon) {
    elements.statusIcon.textContent = config.icon;
  }
  
  if (elements.statusDescription) {
    if (data.threats && data.threats.length > 0) {
      elements.statusDescription.textContent = data.threats[0];
    } else {
      elements.statusDescription.textContent = config.desc;
    }
  }
  
  if (elements.securityStatus) {
    elements.securityStatus.className = `security-status ${config.class}`;
  }
  
  // Update AI Analysis (only if changed to prevent flickering)
  if (data.aiAnalysis && data.aiAnalysis !== currentAiAnalysis && elements.aiAnalysis && elements.aiAnalysisText) {
    currentAiAnalysis = data.aiAnalysis;
    
    // Clean up the AI response text
    let analysisText = data.aiAnalysis.trim();
    
    // Remove any markdown or formatting
    analysisText = analysisText.replace(/\*\*/g, '');
    analysisText = analysisText.replace(/\*/g, '');
    analysisText = analysisText.replace(/#{1,6}\s/g, '');
    
    // Make it more user-friendly
    if (analysisText.length > 200) {
      analysisText = analysisText.substring(0, 200) + '...';
    }
    
    // Show analysis with animation
    elements.aiAnalysis.style.display = 'block';
    elements.aiAnalysis.classList.add('active');
    
    // Show thinking animation first
    const thinkingEl = document.getElementById('aiThinking');
    if (thinkingEl) {
      thinkingEl.style.display = 'flex';
      elements.aiAnalysisText.style.display = 'none';
      
      // After 1 second, show the actual response
      setTimeout(() => {
        thinkingEl.style.display = 'none';
        elements.aiAnalysisText.style.display = 'block';
        elements.aiAnalysisText.textContent = analysisText;
      }, 1000);
    } else {
      elements.aiAnalysisText.textContent = analysisText;
      elements.aiAnalysisText.style.display = 'block';
    }
  } else if (!data.aiAnalysis && elements.aiAnalysis) {
    elements.aiAnalysis.style.display = 'none';
    elements.aiAnalysis.classList.remove('active');
    currentAiAnalysis = null;
  }
  
  // Update timeline
  if (data.events && elements.timeline) {
    elements.timeline.innerHTML = '';
    
    if (data.events.length === 0) {
      elements.timeline.innerHTML = '<div class="empty-state"><p>No events recorded</p></div>';
    } else {
      data.events.forEach(event => {
        const div = document.createElement('div');
        div.className = `timeline-item ${event.severity}`;
        div.innerHTML = `
          <div class="timeline-time">${event.time}</div>
          <div><strong>${event.type}:</strong> ${event.description}</div>
        `;
        elements.timeline.appendChild(div);
      });
    }
  }
}

function updateStats(stats) {
  console.log('[HelioRa Popup] Updating stats:', stats);
  
  if (elements.adsBlocked) {
    elements.adsBlocked.textContent = stats.adsBlocked || 0;
  }
  
  if (elements.trackersBlocked) {
    elements.trackersBlocked.textContent = stats.trackersBlocked || 0;
  }
  
  if (elements.threatsBlocked) {
    elements.threatsBlocked.textContent = stats.threatsBlocked || 0;
  }
}

function updateSettingsUI(settings) {
  const toggles = {
    threatDetectionToggle: settings.threatDetection,
    behaviorDetectionToggle: settings.behaviorDetection,
    firewallToggle: settings.networkFirewall,
    autoBlockToggle: settings.autoBlock,
    autoCookieDeclineToggle: settings.autoCookieDecline !== false,
    blockCookiesToggle: settings.blockCookies,
    blockThirdPartyCookiesToggle: settings.blockThirdPartyCookies !== false
  };
  
  for (const [id, value] of Object.entries(toggles)) {
    const toggle = document.getElementById(id);
    if (toggle) {
      toggle.checked = value !== false;
    }
  }
}

async function loadFirewallRule(domain) {
  try {
    const response = await chrome.runtime.sendMessage({ 
      action: 'getFirewallRule',
      domain: domain
    });
    
    if (response?.rule && elements.firewallSelect) {
      elements.firewallSelect.value = response.rule;
      console.log('[HelioRa Popup] Loaded firewall rule:', domain, response.rule);
    }
  } catch (error) {
    console.error('[HelioRa Popup] Error loading firewall rule:', error);
  }
}

async function loadBlacklist() {
  try {
    const response = await chrome.runtime.sendMessage({ action: 'getBlockedDomains' });
    
    if (response?.domains && elements.blacklistContainer) {
      if (response.domains.length === 0) {
        elements.blacklistContainer.innerHTML = '<div class="empty-state"><p>No blacklisted domains</p></div>';
      } else {
        elements.blacklistContainer.innerHTML = '';
        response.domains.forEach(domain => {
          const div = document.createElement('div');
          div.className = 'domain-item';
          div.innerHTML = `
            <span class="domain-name">${domain}</span>
            <button class="btn-remove" data-domain="${domain}">×</button>
          `;
          elements.blacklistContainer.appendChild(div);
          
          // Add remove handler
          const removeBtn = div.querySelector('.btn-remove');
          removeBtn.addEventListener('click', async () => {
            await chrome.runtime.sendMessage({
              action: 'unblockDomain',
              domain: domain
            });
            await loadBlacklist();
          });
        });
      }
    }
  } catch (error) {
    console.error('[HelioRa Popup] Error loading blacklist:', error);
  }
}

function setupEventListeners() {
  // Timeline toggle button
  const timelineBtn = document.getElementById('viewTimelineBtn');
  if (timelineBtn) {
    timelineBtn.addEventListener('click', () => {
      elements.timelineSection?.classList.toggle('active');
    });
  }
  
  // Clear timeline button
  const clearTimelineBtn = document.getElementById('clearTimelineBtn');
  if (clearTimelineBtn) {
    clearTimelineBtn.addEventListener('click', async () => {
      await loadAllData();
    });
  }
  
  // Export report button
  const exportBtn = document.getElementById('exportReportBtn');
  if (exportBtn) {
    exportBtn.addEventListener('click', async () => {
      try {
        const response = await chrome.runtime.sendMessage({ action: 'exportReport' });
        if (response?.success) {
          const blob = new Blob([response.data], { type: 'application/json' });
          const url = URL.createObjectURL(blob);
          const a = document.createElement('a');
          a.href = url;
          a.download = response.filename;
          a.click();
          URL.revokeObjectURL(url);
          
          // Show success notification
          showNotification('Report exported successfully!', 'success');
        }
      } catch (error) {
        console.error('[HelioRa Popup] Export error:', error);
        showNotification('Failed to export report', 'error');
      }
    });
  }
  
  // Privacy Lockdown button
  const privacyLockdownBtn = document.getElementById('privacyLockdownBtn');
  if (privacyLockdownBtn) {
    privacyLockdownBtn.addEventListener('click', async () => {
      try {
        const response = await chrome.runtime.sendMessage({
          action: 'togglePrivacyLockdown'
        });
        
        if (response?.success) {
          const status = response.enabled ? 'ENABLED' : 'DISABLED';
          privacyLockdownBtn.classList.toggle('active', response.enabled);
          privacyLockdownBtn.style.background = response.enabled ? 
            'linear-gradient(135deg, #c62828 0%, #b71c1c 100%)' : '';
          showNotification(`Privacy Lockdown ${status}`, 'success');
        }
      } catch (error) {
        console.error('[HelioRa Popup] Lockdown error:', error);
        showNotification('Failed to toggle lockdown', 'error');
      }
    });
  }
  
  // Blacklist button
  const blacklistBtn = document.getElementById('blacklistBtn');
  if (blacklistBtn) {
    blacklistBtn.addEventListener('click', async () => {
      if (!currentDomain) {
        showNotification('No domain to block', 'error');
        return;
      }
      
      try {
        const response = await chrome.runtime.sendMessage({
          action: 'blockDomain',
          domain: currentDomain
        });
        
        if (response?.success) {
          showNotification(`✓ ${currentDomain} blocked!`, 'success');
          await loadAllData();
        } else {
          showNotification(response?.message || 'Failed to block domain', 'error');
        }
      } catch (error) {
        console.error('[HelioRa Popup] Block error:', error);
        showNotification('Failed to block domain', 'error');
      }
    });
  }
  
  // Firewall rule selector
  if (elements.firewallSelect) {
    elements.firewallSelect.addEventListener('change', async (e) => {
      const rule = e.target.value;
      if (currentDomain) {
        try {
          await chrome.runtime.sendMessage({
            action: 'setFirewallRule',
            domain: currentDomain,
            rule: rule
          });
          
          console.log('[HelioRa Popup] Firewall rule saved:', currentDomain, rule);
          showNotification(`Firewall rule applied: ${rule}`, 'success');
        } catch (error) {
          console.error('[HelioRa Popup] Error saving firewall rule:', error);
          showNotification('Failed to save firewall rule', 'error');
        }
      }
    });
  }
  
  // Settings toggles
  const toggles = [
    'threatDetectionToggle', 
    'behaviorDetectionToggle', 
    'firewallToggle', 
    'autoBlockToggle',
    'autoCookieDeclineToggle',
    'blockCookiesToggle',
    'blockThirdPartyCookiesToggle'
  ];
  
  toggles.forEach(toggleId => {
    const toggle = document.getElementById(toggleId);
    if (toggle) {
      toggle.addEventListener('change', async (e) => {
        const settingName = toggleId.replace('Toggle', '');
        const settings = {};
        settings[settingName] = e.target.checked;
        
        await chrome.runtime.sendMessage({
          action: 'updateSettings',
          settings: settings
        });
        
        console.log('[HelioRa Popup] Setting updated:', settingName, e.target.checked);
        
        // Show notification for cookie settings
        if (settingName.includes('cookie') || settingName.includes('Cookie')) {
          showNotification(`Cookie settings updated: ${settingName}`, 'success');
        }
      });
    }
  });
  
  // Reset stats button
  const resetStatsBtn = document.getElementById('resetStatsBtn');
  if (resetStatsBtn) {
    resetStatsBtn.addEventListener('click', async () => {
      if (confirm('Reset all statistics? This cannot be undone.')) {
        await chrome.runtime.sendMessage({ action: 'resetStats' });
        await loadAllData();
        showNotification('Statistics reset', 'success');
      }
    });
  }
  
  // Reset settings button
  const resetSettingsBtn = document.getElementById('resetSettingsBtn');
  if (resetSettingsBtn) {
    resetSettingsBtn.addEventListener('click', async () => {
      if (confirm('Reset all settings to default? This cannot be undone.')) {
        const defaultSettings = {
          threatDetection: true,
          behaviorDetection: true,
          networkFirewall: true,
          autoBlock: true
        };
        
        await chrome.runtime.sendMessage({
          action: 'updateSettings',
          settings: defaultSettings
        });
        
        await loadAllData();
        showNotification('Settings reset to default', 'success');
      }
    });
  }
  
  // Tab buttons
  document.querySelectorAll('.tab-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      // Remove active class from all tabs
      document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
      document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
      
      // Add active class to clicked tab
      btn.classList.add('active');
      const tabContent = document.getElementById(`tab-${btn.dataset.tab}`);
      if (tabContent) {
        tabContent.classList.add('active');
      }
    });
  });
}

function showNotification(message, type = 'info') {
  // Create notification element
  const notification = document.createElement('div');
  notification.className = `notification notification-${type}`;
  notification.textContent = message;
  notification.style.cssText = `
    position: fixed;
    top: 20px;
    right: 20px;
    background: ${type === 'success' ? '#4CAF50' : type === 'error' ? '#F44336' : '#2196F3'};
    color: white;
    padding: 12px 20px;
    border-radius: 4px;
    box-shadow: 0 2px 8px rgba(0,0,0,0.2);
    z-index: 10000;
    animation: slideIn 0.3s ease;
  `;
  
  document.body.appendChild(notification);
  
  // Remove after 3 seconds
  setTimeout(() => {
    notification.style.animation = 'slideOut 0.3s ease';
    setTimeout(() => notification.remove(), 300);
  }, 3000);
}

async function checkFraudHistory(domain) {
  try {
    const response = await chrome.runtime.sendMessage({
      action: 'checkFraudHistory',
      domain: domain
    });
    
    if (response?.hasHistory) {
      const history = response.history[0];
      showNotification(
        `⚠️ WARNING: You previously encountered fraud on this domain! (${history.threats.length} threats detected on ${new Date(history.timestamp).toLocaleDateString()})`,
        'error'
      );
    }
  } catch (error) {
    console.error('[HelioRa Popup] Error checking fraud history:', error);
  }
}

console.log('[HelioRa Popup] Ready!');
