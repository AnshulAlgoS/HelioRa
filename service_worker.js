'use strict';

console.log('[HelioRa] Service Worker Starting...');

// NVIDIA API Configuration
const NVIDIA_API_KEY = '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';
const NVIDIA_API_URL = 'https://integrate.api.nvidia.com/v1/chat/completions';

// Statistics with proper tracking
let stats = {
  adsBlocked: 0,
  trackersBlocked: 0,
  threatsBlocked: 0,
  scriptsBlocked: 0
};

// Blocked domains list
let blockedDomains = [];

// Firewall rules storage
let firewallRules = {};

// Domain data cache
let domainDataCache = new Map();

// Settings
let settings = {
  threatDetection: true,
  behaviorDetection: true,
  networkFirewall: true,
  autoBlock: true
};

// Dynamic rule ID counter
let dynamicRuleIdCounter = 10000;

// Known threat patterns
const THREAT_PATTERNS = {
  malware: ['malware', 'virus', 'trojan', 'hack', 'crack', 'keygen', 'warez', 'infected'],
  phishing: ['verify-account', 'secure-login', 'update-payment', 'suspended-account', 'unusual-activity', 'confirm-identity'],
  suspicious: ['free-download', 'click-here', 'winner', 'prize', 'urgent', 'limited-time', 'act-now'],
  dangerous: ['phishing', 'scam', 'fraud', 'fake', 'counterfeit', 'stolen']
};

// Popular domains for typosquatting detection
const POPULAR_DOMAINS = {
  'google': 'google.com',
  'facebook': 'facebook.com', 
  'paypal': 'paypal.com',
  'amazon': 'amazon.com',
  'apple': 'apple.com',
  'microsoft': 'microsoft.com',
  'netflix': 'netflix.com',
  'instagram': 'instagram.com',
  'twitter': 'twitter.com',
  'linkedin': 'linkedin.com'
};

// Known ad/tracker domains
const AD_TRACKER_DOMAINS = [
  'doubleclick.net',
  'googlesyndication.com',
  'googleadservices.com',
  'google-analytics.com',
  'googletagmanager.com',
  'facebook.com/tr',
  'facebook.net',
  'scorecardresearch.com',
  'adnxs.com',
  'advertising.com',
  'quantserve.com',
  'outbrain.com',
  'taboola.com',
  'criteo.com',
  'rubiconproject.com'
];

// Initialize extension
chrome.runtime.onInstalled.addListener(async () => {
  console.log('[HelioRa] Extension installed/updated');
  
  // Load saved data
  const saved = await chrome.storage.local.get(['stats', 'blockedDomains', 'firewallRules', 'settings']);
  
  if (saved.stats) {
    stats = saved.stats;
  }
  if (saved.blockedDomains) {
    blockedDomains = saved.blockedDomains;
  }
  if (saved.firewallRules) {
    firewallRules = saved.firewallRules;
  }
  if (saved.settings) {
    settings = saved.settings;
  }
  
  // Save initial state
  await chrome.storage.local.set({ stats, blockedDomains, firewallRules, settings });
  
  console.log('[HelioRa] Initialized:', { stats, blockedDomains: blockedDomains.length });
});

// Load data on startup
chrome.storage.local.get(['stats', 'blockedDomains', 'firewallRules', 'settings', 'dynamicRuleIdCounter']).then(async result => {
  if (result.stats) stats = result.stats;
  if (result.blockedDomains) blockedDomains = result.blockedDomains;
  if (result.firewallRules) firewallRules = result.firewallRules;
  if (result.settings) settings = result.settings;
  if (result.dynamicRuleIdCounter) dynamicRuleIdCounter = result.dynamicRuleIdCounter;
  
  console.log('[HelioRa] Loaded data:', { 
    stats, 
    blockedDomains: blockedDomains.length,
    firewallRules: Object.keys(firewallRules).length 
  });
  
  // Reapply all firewall rules and blocked domains
  for (const domain of blockedDomains) {
    await blockDomainCompletely(domain);
  }
  
  for (const [domain, rule] of Object.entries(firewallRules)) {
    if (rule !== 'allow') {
      await applyFirewallRules(domain, rule);
    }
  }
  
  console.log('[HelioRa] Firewall rules reapplied');
});

// Track network requests for ad/tracker blocking
chrome.webRequest.onBeforeRequest.addListener(
  (details) => {
    const url = details.url.toLowerCase();
    
    // Check if request is to an ad/tracker domain
    const isAdTracker = AD_TRACKER_DOMAINS.some(domain => url.includes(domain));
    
    if (isAdTracker) {
      // Increment counters
      if (url.includes('analytics') || url.includes('tracking') || url.includes('/tr/')) {
        stats.trackersBlocked++;
      } else {
        stats.adsBlocked++;
      }
      
      // Save stats periodically (throttled)
      if ((stats.adsBlocked + stats.trackersBlocked) % 5 === 0) {
        chrome.storage.local.set({ stats });
      }
      
      console.log('[HelioRa] Blocked:', url.substring(0, 60) + '...');
    }
    
    return { cancel: false }; // Let declarativeNetRequest handle actual blocking
  },
  { urls: ["<all_urls>"] },
  []
);

// Track when rules match (for debugging)
if (chrome.declarativeNetRequest.onRuleMatchedDebug) {
  chrome.declarativeNetRequest.onRuleMatchedDebug.addListener((details) => {
    console.log('[HelioRa] Rule matched:', details.request.url);
  });
}

// Analyze page when tab updates
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === 'complete' && tab.url) {
    analyzePage(tab.url, tabId);
  }
});

// Analyze page when tab is activated
chrome.tabs.onActivated.addListener(async (activeInfo) => {
  const tab = await chrome.tabs.get(activeInfo.tabId);
  if (tab.url) {
    analyzePage(tab.url, activeInfo.tabId);
  }
});

// NVIDIA AI Analysis
async function getNVIDIAAnalysis(domain, url, detectedThreats) {
  try {
    const prompt = `Analyze this website for security threats:
Domain: ${domain}
URL: ${url}
Detected patterns: ${detectedThreats.join(', ')}

Provide a brief security analysis in 1-2 sentences. Focus on: phishing risk, malware indicators, typosquatting, suspicious patterns.`;

    const response = await fetch(NVIDIA_API_URL, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${NVIDIA_API_KEY}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        model: 'meta/llama-3.1-8b-instruct',
        messages: [
          {
            role: 'user',
            content: prompt
          }
        ],
        temperature: 0.2,
        max_tokens: 150
      })
    });

    if (response.ok) {
      const data = await response.json();
      return data.choices[0]?.message?.content || 'Analysis unavailable';
    }
  } catch (error) {
    console.error('[HelioRa] NVIDIA API error:', error);
  }
  return null;
}

// Main page analysis function
async function analyzePage(url, tabId) {
  if (!settings.threatDetection) return;
  
  try {
    if (!url || url.startsWith('chrome://') || url.startsWith('chrome-extension://') || url.startsWith('about:')) {
      return;
    }
    
    const urlObj = new URL(url);
    const domain = urlObj.hostname.replace('www.', '');
    const fullUrl = url.toLowerCase();
    
    let riskScore = 0;
    let threats = [];
    let status = 'safe';
    let detectionReasons = [];
    
    // 1. Check if domain is blocked by user
    if (blockedDomains.includes(domain)) {
      riskScore = 100;
      status = 'dangerous';
      threats.push('Domain blocked by user');
      detectionReasons.push('User blacklisted');
    } else {
      // 2. Check for malware patterns (HIGH RISK +60)
      THREAT_PATTERNS.malware.forEach(pattern => {
        if (domain.includes(pattern) || fullUrl.includes(pattern)) {
          riskScore += 60;
          threats.push(`Malware keyword: ${pattern}`);
          detectionReasons.push(`Malware pattern: ${pattern}`);
        }
      });
      
      // 3. Check for dangerous patterns (HIGH RISK +70)
      THREAT_PATTERNS.dangerous.forEach(pattern => {
        if (domain.includes(pattern) || fullUrl.includes(pattern)) {
          riskScore += 70;
          threats.push(`Dangerous keyword: ${pattern}`);
          detectionReasons.push(`Dangerous pattern: ${pattern}`);
        }
      });
      
      // 4. Check for phishing patterns (MEDIUM-HIGH RISK +40)
      THREAT_PATTERNS.phishing.forEach(pattern => {
        if (fullUrl.includes(pattern)) {
          riskScore += 40;
          threats.push(`Phishing pattern: ${pattern}`);
          detectionReasons.push(`Phishing pattern: ${pattern}`);
        }
      });
      
      // 5. Check for suspicious patterns (LOW-MEDIUM RISK +20)
      THREAT_PATTERNS.suspicious.forEach(pattern => {
        if (fullUrl.includes(pattern)) {
          riskScore += 20;
          threats.push(`Suspicious pattern: ${pattern}`);
          detectionReasons.push(`Suspicious pattern: ${pattern}`);
        }
      });
      
      // 6. Typosquatting detection (HIGH RISK +50)
      for (const [brand, legitimate] of Object.entries(POPULAR_DOMAINS)) {
        if (domain.includes(brand) && domain !== legitimate) {
          if (!domain.endsWith(legitimate)) {
            riskScore += 50;
            threats.push(`Possible typosquatting of ${legitimate}`);
            detectionReasons.push(`Typosquatting: ${legitimate}`);
          }
        }
      }
      
      // 7. Check protocol security (LOW RISK +10)
      if (url.startsWith('http://') && !url.startsWith('https://')) {
        riskScore += 10;
        threats.push('Insecure HTTP connection');
        detectionReasons.push('No HTTPS');
      }
      
      // 8. Suspicious TLD check (MEDIUM RISK +30)
      const suspiciousTLDs = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.pw'];
      if (suspiciousTLDs.some(tld => domain.endsWith(tld))) {
        riskScore += 30;
        threats.push('Suspicious domain extension');
        detectionReasons.push('Suspicious TLD');
      }
      
      // 9. Excessive subdomains (LOW RISK +15)
      const subdomains = domain.split('.');
      if (subdomains.length > 4) {
        riskScore += 15;
        threats.push('Excessive subdomains');
        detectionReasons.push('Many subdomains');
      }
      
      // 10. Check for IP address in domain (MEDIUM RISK +35)
      if (/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(domain)) {
        riskScore += 35;
        threats.push('IP address instead of domain name');
        detectionReasons.push('IP address domain');
      }
    }
    
    // Cap risk score at 100
    riskScore = Math.min(100, Math.round(riskScore));
    
    // Determine status based on risk score
    if (riskScore >= 60) {
      status = 'dangerous';
      stats.threatsBlocked++;
    } else if (riskScore >= 30) {
      status = 'suspicious';
    } else {
      status = 'safe';
    }
    
    // Get AI analysis for suspicious/dangerous sites
    let aiAnalysis = null;
    if (riskScore >= 30 && detectionReasons.length > 0) {
      aiAnalysis = await getNVIDIAAnalysis(domain, url, detectionReasons);
    }
    
    // Create domain data
    const domainData = {
      domain,
      url,
      riskScore,
      status,
      threats,
      detectionReasons,
      aiAnalysis,
      timestamp: Date.now(),
      events: [
        {
          time: new Date().toLocaleTimeString(),
          type: 'security-scan',
          description: `Risk assessment: ${riskScore}/100 - ${status.toUpperCase()}`,
          severity: status === 'dangerous' ? 'critical' : status === 'suspicious' ? 'medium' : 'low'
        }
      ]
    };
    
    // Add AI analysis event if available
    if (aiAnalysis) {
      domainData.events.push({
        time: new Date().toLocaleTimeString(),
        type: 'ai-analysis',
        description: aiAnalysis,
        severity: 'medium'
      });
    }
    
    // Add threat events
    if (threats.length > 0) {
      threats.forEach(threat => {
        domainData.events.push({
          time: new Date().toLocaleTimeString(),
          type: 'threat-detected',
          description: threat,
          severity: riskScore >= 60 ? 'critical' : 'medium'
        });
      });
    }
    
    // Store in cache
    domainDataCache.set(domain, domainData);
    
    // Update badge
    updateBadge(tabId, status, riskScore);
    
    // Save stats
    chrome.storage.local.set({ stats });
    
    console.log('[HelioRa] Analysis:', {
      domain,
      riskScore,
      status,
      threats: threats.length
    });
    
    // Show notification for dangerous sites
    if (status === 'dangerous' && riskScore >= 70) {
      chrome.notifications.create({
        type: 'basic',
        iconUrl: 'icons/icon128.png',
        title: '⚠️ HelioRa Security Alert',
        message: `Dangerous site detected!\n${domain}\nRisk Score: ${riskScore}/100`,
        priority: 2
      });
    }
    
  } catch (error) {
    console.error('[HelioRa] Analysis error:', error);
  }
}

// Update badge
function updateBadge(tabId, status, score) {
  const colors = {
    safe: '#4CAF50',
    suspicious: '#FF9800',
    dangerous: '#F44336'
  };
  
  const color = colors[status] || colors.safe;
  const text = score > 0 ? String(score) : '✓';
  
  chrome.action.setBadgeBackgroundColor({ color, tabId });
  chrome.action.setBadgeText({ text, tabId });
}

// Apply firewall rules for a domain
async function applyFirewallRules(domain, rule) {
  if (!settings.networkFirewall) return;
  
  // Save the rule
  firewallRules[domain] = rule;
  await chrome.storage.local.set({ firewallRules });
  
  console.log('[HelioRa] Firewall rule saved:', domain, rule);
  
  // Remove existing rules for this domain
  const existingRules = await chrome.declarativeNetRequest.getDynamicRules();
  const rulesToRemove = existingRules
    .filter(r => r.condition?.requestDomains?.includes(domain))
    .map(r => r.id);
  
  if (rulesToRemove.length > 0) {
    await chrome.declarativeNetRequest.updateDynamicRules({
      removeRuleIds: rulesToRemove
    });
  }
  
  // Apply new rule
  if (rule !== 'allow') {
    const newRules = [];
    const ruleId = dynamicRuleIdCounter++;
    
    if (rule === 'block-all') {
      // Block everything from this domain
      newRules.push({
        id: ruleId,
        priority: 2,
        action: { type: 'block' },
        condition: {
          requestDomains: [domain],
          resourceTypes: ['main_frame', 'sub_frame', 'stylesheet', 'script', 'image', 'font', 'object', 'xmlhttprequest', 'ping', 'media', 'websocket', 'other']
        }
      });
    } else if (rule === 'block-tracking') {
      // Block tracking and analytics
      newRules.push({
        id: ruleId,
        priority: 2,
        action: { type: 'block' },
        condition: {
          requestDomains: [domain],
          resourceTypes: ['xmlhttprequest', 'ping'],
          urlFilter: '*analytics*|*tracking*|*tracker*'
        }
      });
    } else if (rule === 'block-xhr') {
      // Block all XHR/Fetch requests
      newRules.push({
        id: ruleId,
        priority: 2,
        action: { type: 'block' },
        condition: {
          requestDomains: [domain],
          resourceTypes: ['xmlhttprequest', 'ping']
        }
      });
    } else if (rule === 'block-ads') {
      // Block ads and ad-related content
      newRules.push({
        id: ruleId,
        priority: 2,
        action: { type: 'block' },
        condition: {
          requestDomains: [domain],
          resourceTypes: ['script', 'image', 'sub_frame'],
          urlFilter: '*ad*|*banner*|*sponsor*'
        }
      });
    }
    
    if (newRules.length > 0) {
      await chrome.declarativeNetRequest.updateDynamicRules({
        addRules: newRules
      });
      console.log('[HelioRa] Applied firewall rule:', rule, 'for', domain);
    }
  }
}

// Block domain completely
async function blockDomainCompletely(domain) {
  // Add to blacklist
  if (!blockedDomains.includes(domain)) {
    blockedDomains.push(domain);
    await chrome.storage.local.set({ blockedDomains });
  }
  
  // Create blocking rule
  const ruleId = dynamicRuleIdCounter++;
  
  await chrome.declarativeNetRequest.updateDynamicRules({
    addRules: [{
      id: ruleId,
      priority: 10, // Higher priority
      action: { type: 'block' },
      condition: {
        requestDomains: [domain, `*.${domain}`],
        resourceTypes: ['main_frame', 'sub_frame']
      }
    }]
  });
  
  console.log('[HelioRa] Domain completely blocked:', domain);
  
  // Close all tabs with this domain
  const tabs = await chrome.tabs.query({});
  for (const tab of tabs) {
    if (tab.url && tab.url.includes(domain)) {
      chrome.tabs.remove(tab.id);
    }
  }
}

// Message handler
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  
  if (request.action === 'getDomainInfo') {
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      if (tabs[0]?.url) {
        try {
          const url = new URL(tabs[0].url);
          const domain = url.hostname.replace('www.', '');
          
          // Get cached data or create default
          let data = domainDataCache.get(domain);
          if (!data) {
            data = {
              domain,
              url: tabs[0].url,
              riskScore: 0,
              status: 'safe',
              threats: [],
              detectionReasons: [],
              events: [
                {
                  time: new Date().toLocaleTimeString(),
                  type: 'page-loaded',
                  description: 'Analyzing page security...',
                  severity: 'low'
                }
              ],
              timestamp: Date.now()
            };
          }
          
          sendResponse(data);
        } catch (e) {
          sendResponse({
            domain: 'System Page',
            url: tabs[0].url,
            riskScore: 0,
            status: 'safe',
            threats: [],
            events: [],
            timestamp: Date.now()
          });
        }
      } else {
        sendResponse(null);
      }
    });
    return true;
  }
  
  if (request.action === 'getStats') {
    sendResponse({ stats });
    return true;
  }
  
  if (request.action === 'resetStats') {
    stats = {
      adsBlocked: 0,
      trackersBlocked: 0,
      threatsBlocked: 0,
      scriptsBlocked: 0
    };
    chrome.storage.local.set({ stats });
    sendResponse({ success: true });
    return true;
  }
  
  if (request.action === 'blockDomain') {
    (async () => {
      const domain = request.domain;
      if (domain && !blockedDomains.includes(domain)) {
        await blockDomainCompletely(domain);
        
        stats.threatsBlocked++;
        await chrome.storage.local.set({ stats });
        
        // Show notification
        chrome.notifications.create({
          type: 'basic',
          iconUrl: 'icons/icon128.png',
          title: '🚫 Domain Blocked',
          message: `${domain} has been completely blocked and all tabs closed`,
          priority: 2
        });
        
        console.log('[HelioRa] Domain blocked:', domain);
        sendResponse({ success: true, message: `${domain} has been blocked` });
      } else {
        sendResponse({ success: false, message: 'Domain already blocked' });
      }
    })();
    return true;
  }
  
  if (request.action === 'unblockDomain') {
    (async () => {
      const domain = request.domain;
      blockedDomains = blockedDomains.filter(d => d !== domain);
      await chrome.storage.local.set({ blockedDomains });
      
      // Remove blocking rules
      const existingRules = await chrome.declarativeNetRequest.getDynamicRules();
      const rulesToRemove = existingRules
        .filter(r => r.condition?.requestDomains?.some(d => d === domain || d === `*.${domain}`))
        .map(r => r.id);
      
      if (rulesToRemove.length > 0) {
        await chrome.declarativeNetRequest.updateDynamicRules({
          removeRuleIds: rulesToRemove
        });
      }
      
      console.log('[HelioRa] Domain unblocked:', domain);
      sendResponse({ success: true });
    })();
    return true;
  }
  
  if (request.action === 'getBlockedDomains') {
    sendResponse({ domains: blockedDomains });
    return true;
  }
  
  if (request.action === 'setFirewallRule') {
    (async () => {
      await applyFirewallRules(request.domain, request.rule);
      sendResponse({ success: true });
    })();
    return true;
  }
  
  if (request.action === 'getFirewallRule') {
    const rule = firewallRules[request.domain] || 'allow';
    sendResponse({ rule });
    return true;
  }
  
  if (request.action === 'exportReport') {
    const allDomains = Array.from(domainDataCache.entries()).map(([domain, data]) => ({
      domain,
      riskScore: data.riskScore,
      status: data.status,
      threats: data.threats,
      timestamp: new Date(data.timestamp).toISOString()
    }));
    
    const report = {
      generatedAt: new Date().toISOString(),
      version: '4.0.0',
      statistics: stats,
      blockedDomains: blockedDomains,
      firewallRules: firewallRules,
      analyzedDomains: allDomains
    };
    
    sendResponse({
      success: true,
      data: JSON.stringify(report, null, 2),
      filename: `heliora-security-report-${Date.now()}.json`
    });
    return true;
  }
  
  if (request.action === 'addEvent') {
    const { domain, event } = request;
    const data = domainDataCache.get(domain);
    if (data) {
      data.events.push(event);
      if (data.events.length > 20) {
        data.events.shift();
      }
      domainDataCache.set(domain, data);
    }
    sendResponse({ success: true });
    return true;
  }
  
  if (request.action === 'updateSettings') {
    settings = { ...settings, ...request.settings };
    chrome.storage.local.set({ settings });
    sendResponse({ success: true });
    return true;
  }
  
  if (request.action === 'getSettings') {
    sendResponse({ settings });
    return true;
  }
});

// Save stats and counter periodically
setInterval(() => {
  chrome.storage.local.set({ stats, dynamicRuleIdCounter });
}, 30000); // Every 30 seconds

console.log('[HelioRa] Service Worker Ready!');
