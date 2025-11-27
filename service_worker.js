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

// Fraud memory - domains where user almost got scammed
let fraudMemory = [];

// Settings
let settings = {
  threatDetection: true,
  behaviorDetection: true,
  networkFirewall: true,
  autoBlock: true,
  autoCookieDecline: true, // Auto-decline cookie banners (enabled by default)
  blockCookies: false, // Block all cookies
  blockThirdPartyCookies: true, // Block third-party cookies only
  privacyLockdown: false // Global privacy lockdown - blocks all camera/mic/GPS
};

// Surveillance attempt logs (forensic evidence for law enforcement)
let surveillanceLog = [];
const MAX_SURVEILLANCE_LOGS = 1000;

// Dynamic rule ID counter
let dynamicRuleIdCounter = 10000;

// Known threat patterns
const THREAT_PATTERNS = {
  malware: ['malware', 'virus', 'trojan', 'hack', 'crack', 'keygen', 'warez', 'infected'],
  phishing: ['verify-account', 'secure-login', 'update-payment', 'suspended-account', 'unusual-activity', 'confirm-identity', 'verify-info', 'account-locked', 'security-alert', 'billing-problem', 'payment-failed'],
  suspicious: ['free-download', 'click-here', 'winner', 'prize', 'urgent', 'limited-time', 'act-now'],
  dangerous: ['phishing', 'scam', 'fraud', 'fake', 'counterfeit', 'stolen']
};

// Known phishing domains and patterns
const PHISHING_INDICATORS = {
  // Common phishing keywords in URLs
  keywords: [
    'login', 'signin', 'account', 'verify', 'update', 'secure', 'suspended',
    'confirm', 'banking', 'paypal', 'amazon', 'apple', 'microsoft', 'netflix',
    'wallet', 'crypto', 'bitcoin'
  ],
  // Suspicious URL patterns
  patterns: [
    /\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/, // IP addresses
    /-login\./i,
    /-signin\./i,
    /account-/i,
    /verify-/i,
    /secure-/i,
    /update-/i,
    /auth-/i,
    /www\d+\./i,
    /\w{20,}\./, // Very long subdomain
  ],
  // Dangerous TLDs commonly used for phishing
  dangerousTlds: ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.pw', '.cc', '.info', '.online', '.site', '.website', '.space', '.club']
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
chrome.storage.local.get(['stats', 'blockedDomains', 'firewallRules', 'settings', 'dynamicRuleIdCounter', 'fraudMemory']).then(async result => {
  if (result.stats) stats = result.stats;
  if (result.blockedDomains) blockedDomains = result.blockedDomains;
  if (result.firewallRules) firewallRules = result.firewallRules;
  if (result.settings) settings = result.settings;
  if (result.dynamicRuleIdCounter) dynamicRuleIdCounter = result.dynamicRuleIdCounter;
  if (result.fraudMemory) fraudMemory = result.fraudMemory;
  
  console.log('[HelioRa] Loaded data:', { 
    stats, 
    blockedDomains: blockedDomains.length,
    firewallRules: Object.keys(firewallRules).length,
    privacyLockdown: settings.privacyLockdown
  });
  
  // Broadcast lockdown state to all tabs
  if (settings.privacyLockdown) {
    chrome.tabs.query({}, (tabs) => {
      tabs.forEach(tab => {
        chrome.tabs.sendMessage(tab.id, {
          action: 'setPrivacyLockdown',
          enabled: true
        }).catch(() => {});
      });
    });
  }
  
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

// Analyze page before navigation (phishing protection)
chrome.webNavigation.onBeforeNavigate.addListener(async (details) => {
  if (details.frameId !== 0) return; // Only check main frame
  
  const url = details.url;
  if (!url || url.startsWith('chrome://') || url.startsWith('chrome-extension://')) {
    return;
  }
  
  // Quick phishing check
  const phishingCheck = await quickPhishingCheck(url);
  if (phishingCheck.isPhishing && phishingCheck.confidence >= 80) {
    // Block the navigation
    chrome.tabs.update(details.tabId, {
      url: chrome.runtime.getURL('warning.html') + '?url=' + encodeURIComponent(url) + '&reason=' + encodeURIComponent(phishingCheck.reason)
    });
    
    // Show notification
    chrome.notifications.create({
      type: 'basic',
      iconUrl: 'icons/icon128.png',
      title: '🛡️ Phishing Attack Blocked',
      message: `HelioRa blocked a phishing attempt:\n${new URL(url).hostname}\n\nReason: ${phishingCheck.reason}`,
      priority: 2,
      requireInteraction: true
    });
    
    stats.threatsBlocked++;
    chrome.storage.local.set({ stats });
    
    console.log('[HelioRa] Blocked phishing site:', url, phishingCheck);
  }
});

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

// Quick phishing detection (fast, before page loads)
async function quickPhishingCheck(url) {
  try {
    const urlObj = new URL(url);
    const domain = urlObj.hostname.replace('www.', '');
    const fullUrl = url.toLowerCase();
    
    let phishingScore = 0;
    let reasons = [];
    
    // 1. Check if already blacklisted
    if (blockedDomains.includes(domain)) {
      return {
        isPhishing: true,
        confidence: 100,
        reason: 'Domain is in your blacklist'
      };
    }
    
    // 2. Check for IP address instead of domain
    if (/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(domain)) {
      phishingScore += 50;
      reasons.push('Using IP address instead of domain name');
    }
    
    // 3. Check for dangerous TLDs
    const hasDangerousTld = PHISHING_INDICATORS.dangerousTlds.some(tld => domain.endsWith(tld));
    if (hasDangerousTld) {
      phishingScore += 40;
      reasons.push('Suspicious domain extension');
    }
    
    // 4. Check for typosquatting of popular brands
    for (const [brand, legitimate] of Object.entries(POPULAR_DOMAINS)) {
      if (domain.includes(brand) && domain !== legitimate && !domain.endsWith(legitimate)) {
        phishingScore += 60;
        reasons.push(`Potential typosquatting of ${legitimate}`);
        break;
      }
    }
    
    // 5. Check for phishing keywords in URL
    const phishingKeywordCount = PHISHING_INDICATORS.keywords.filter(kw => 
      fullUrl.includes(kw)
    ).length;
    
    if (phishingKeywordCount >= 2) {
      phishingScore += 30;
      reasons.push('Multiple phishing keywords detected');
    }
    
    // 6. Check for suspicious patterns
    const suspiciousPatternMatches = PHISHING_INDICATORS.patterns.filter(pattern => 
      pattern.test(fullUrl)
    ).length;
    
    if (suspiciousPatternMatches >= 2) {
      phishingScore += 25;
      reasons.push('Suspicious URL patterns detected');
    }
    
    // 7. Check for excessive subdomains (more than 3)
    const subdomains = domain.split('.');
    if (subdomains.length > 4) {
      phishingScore += 20;
      reasons.push('Excessive subdomains');
    }
    
    // 8. Check for no HTTPS on login/account pages
    if (url.startsWith('http://') && (fullUrl.includes('login') || fullUrl.includes('account') || fullUrl.includes('signin'))) {
      phishingScore += 40;
      reasons.push('Insecure connection on sensitive page');
    }
    
    // 9. Check for very long domain names (>30 chars = suspicious)
    if (domain.length > 30) {
      phishingScore += 15;
      reasons.push('Unusually long domain name');
    }
    
    // 10. Check for numbers in middle of domain (suspicious)
    if (/[a-z]\d{2,}[a-z]/.test(domain)) {
      phishingScore += 15;
      reasons.push('Numbers embedded in domain name');
    }
    
    const confidence = Math.min(100, phishingScore);
    const isPhishing = confidence >= 70; // Block if 70%+ confidence
    
    return {
      isPhishing,
      confidence,
      reason: reasons.join(', ') || 'No threats detected',
      score: phishingScore
    };
    
  } catch (error) {
    console.error('[HelioRa] Phishing check error:', error);
    return { isPhishing: false, confidence: 0, reason: 'Error during check' };
  }
}

// HelioAI Analysis (powered by NVIDIA)
async function getHelioAIAnalysis(domain, url, detectedThreats) {
  try {
    // If no threats, provide a simple safe message
    if (detectedThreats.length === 0) {
      return "This website looks secure! HelioAI found no suspicious patterns or security concerns.";
    }
    
    // Create a smart, context-aware prompt
    const prompt = `You are HelioAI, a security expert assistant. Analyze this website intelligently:

Domain: ${domain}
URL: ${url}
Security concerns detected: ${detectedThreats.join(', ')}

IMPORTANT: 
- Don't just repeat what's in the domain name (e.g., if domain has "phish" in it, that doesn't mean it's phishing)
- Look at the ACTUAL security patterns and behavior
- Consider if this could be a legitimate security-related website (like security blogs, security tools, etc.)
- Be smart about false positives
- Only raise concerns if there are REAL security risks

Provide a brief (1-2 sentences), user-friendly explanation of actual security risks. If it's likely a false positive (security blog, security tool, etc.), mention that it appears legitimate despite the security-related terms.`;

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
      const aiResponse = data.choices[0]?.message?.content;
      if (aiResponse) {
        console.log('[HelioRa] AI Analysis received:', aiResponse);
        return aiResponse;
      }
    } else {
      console.error('[HelioRa] API response not OK:', response.status, response.statusText);
    }
  } catch (error) {
    console.error('[HelioRa] NVIDIA API error:', error);
  }
  
  // Fallback message if API fails
  if (detectedThreats.length > 0) {
    return `HelioAI detected: ${detectedThreats[0]}. Exercise caution while browsing this site.`;
  }
  
  return "HelioAI is analyzing this website for security concerns...";
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
      // Whitelist legitimate security/tech domains and tools to avoid false positives
      const legitimateDomains = [
        'github.com', 'stackoverflow.com', 'security.org', 'owasp.org',
        'virustotal.com', 'malwarebytes.com', 'kaspersky.com', 'norton.com',
        'phish.report', 'haveibeenpwned.com', 'bleepingcomputer.com',
        'krebsonsecurity.com', 'threatpost.com', 'securityweek.com',
        'reddit.com', 'wikipedia.org', 'cloudflare.com', 'scamadviser.com',
        'expressvpn.com', 'nordvpn.com'
      ];
      
      // Whitelist legitimate tool patterns
      const legitimateTools = [
        'downloader', 'converter', 'generator', 'editor', 'viewer', 
        'reader', 'player', 'maker', 'creator', 'analyzer', 'checker',
        'scanner', 'validator'
      ];
      
      const isLegitimate = legitimateDomains.some(legit => 
        domain.endsWith(legit) || domain === legit
      );
      
      // Check if it's a legitimate tool website
      const isLegitimateTool = legitimateTools.some(tool => domain.includes(tool)) && 
                               (domain.includes('.com') || domain.includes('.net') || domain.includes('.org'));
      
      if (!isLegitimate && !isLegitimateTool) {
        // 2. Check for malware patterns (HIGH RISK +60) - only in main domain
        THREAT_PATTERNS.malware.forEach(pattern => {
          if (domain.includes(pattern)) {
            riskScore += 60;
            threats.push(`Malware keyword in domain: ${pattern}`);
            detectionReasons.push(`Malware pattern in domain: ${pattern}`);
          }
        });
        
        // 3. Check for dangerous patterns (HIGH RISK +70) - only in domain, not URL path
        // But exclude legitimate security/scam-checking sites
        const isSecurityChecker = domain.includes('scamadvis') || domain.includes('scamchecker') || 
                                   domain.includes('fraudcheck') || domain.includes('phishcheck');
        
        if (!isSecurityChecker) {
          THREAT_PATTERNS.dangerous.forEach(pattern => {
            if (domain.includes(pattern) && !urlObj.pathname.toLowerCase().includes(pattern)) {
              riskScore += 70;
              threats.push(`Dangerous keyword in domain: ${pattern}`);
              detectionReasons.push(`Dangerous pattern in domain: ${pattern}`);
            }
          });
        }
        
        // 4. Check for phishing patterns (MEDIUM-HIGH RISK +40) - only in suspicious contexts
        let phishingPatternCount = 0;
        THREAT_PATTERNS.phishing.forEach(pattern => {
          if (fullUrl.includes(pattern)) {
            phishingPatternCount++;
          }
        });
        
        // Only flag if multiple phishing patterns found
        if (phishingPatternCount >= 2) {
          riskScore += 40;
          threats.push(`Multiple phishing patterns detected`);
          detectionReasons.push(`${phishingPatternCount} phishing patterns found`);
        }
        
        // 5. Check for suspicious patterns (LOW-MEDIUM RISK +20) - only in URL parameters
        let suspiciousPatternCount = 0;
        THREAT_PATTERNS.suspicious.forEach(pattern => {
          if (urlObj.search.includes(pattern) || urlObj.pathname.includes(pattern)) {
            suspiciousPatternCount++;
          }
        });
        
        if (suspiciousPatternCount >= 2) {
          riskScore += 20;
          threats.push(`Suspicious patterns in URL`);
          detectionReasons.push(`${suspiciousPatternCount} suspicious patterns`);
        }
      }
      
      // 6. Typosquatting detection (HIGH RISK +50)
      // But exclude legitimate third-party tools that mention the brand
      for (const [brand, legitimate] of Object.entries(POPULAR_DOMAINS)) {
        if (domain.includes(brand) && domain !== legitimate) {
          if (!domain.endsWith(legitimate)) {
            // Check if it's a legitimate tool site (downloader, converter, etc)
            const isToolSite = legitimateTools.some(tool => domain.includes(tool));
            
            // Only flag if it's NOT a tool site AND looks suspicious
            if (!isToolSite || domain.length < 15) {
              riskScore += 50;
              threats.push(`Possible typosquatting of ${legitimate}`);
              detectionReasons.push(`Typosquatting: ${legitimate}`);
            }
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
    
    // Get AI analysis for ALL sites
    let aiAnalysis = await getHelioAIAnalysis(domain, url, detectionReasons);
    
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
  
  if (request.action === 'cookieBannerBlocked') {
    // Track cookie banners blocked
    console.log('[HelioRa] Cookie banner blocked on:', sender.url);
    return true;
  }
  
  if (request.action === 'getCookiesBlocked') {
    sendResponse({ count: getCookiesBlockedCount() });
    return true;
  }
  
  if (request.action === 'logSurveillanceAttempt') {
    const logEntry = request.data;
    surveillanceLog.push(logEntry);
    
    // Keep only last 1000 entries
    if (surveillanceLog.length > MAX_SURVEILLANCE_LOGS) {
      surveillanceLog.shift();
    }
    
    // Save to storage for forensic analysis
    chrome.storage.local.set({ surveillanceLog });
    
    console.log('[HelioRa Surveillance] Logged attempt:', logEntry);
    
    // Show notification if blocked
    if (logEntry.blocked) {
      chrome.notifications.create({
        type: 'basic',
        iconUrl: 'icons/icon128.png',
        title: 'Surveillance Attack Blocked',
        message: `HelioRa blocked ${logEntry.type} access on ${logEntry.domain}`,
        priority: 2
      });
      
      stats.threatsBlocked++;
    }
    
    sendResponse({ success: true });
    return true;
  }
  
  if (request.action === 'highThreatSite') {
    const { domain, url, threatScore } = request.data;
    
    console.error('[HelioRa Surveillance] HIGH THREAT SITE:', domain, threatScore);
    
    chrome.notifications.create({
      type: 'basic',
      iconUrl: 'icons/icon128.png',
      title: 'High Threat Site Detected',
      message: `${domain} has threat score of ${threatScore}. Be careful!`,
      priority: 2
    });
    
    sendResponse({ success: true });
    return true;
  }
  
  if (request.action === 'criticalSurveillanceThreat') {
    const { domain, permissions } = request.data;
    
    console.error('[HelioRa Surveillance] CRITICAL THREAT - Multiple permissions requested:', permissions);
    
    chrome.notifications.create({
      type: 'basic',
      iconUrl: 'icons/icon128.png',
      title: 'CRITICAL: Surveillance Attack',
      message: `${domain} is attempting CamPhish-style attack. Close the tab!`,
      priority: 2,
      requireInteraction: true
    });
    
    stats.threatsBlocked++;
    
    sendResponse({ success: true });
    return true;
  }
  
  if (request.action === 'togglePrivacyLockdown') {
    settings.privacyLockdown = !settings.privacyLockdown;
    chrome.storage.local.set({ settings });
    
    // Notify all tabs
    chrome.tabs.query({}, (tabs) => {
      tabs.forEach(tab => {
        chrome.tabs.sendMessage(tab.id, {
          action: 'setPrivacyLockdown',
          enabled: settings.privacyLockdown
        }).catch(() => {});
      });
    });
    
    chrome.notifications.create({
      type: 'basic',
      iconUrl: 'icons/icon128.png',
      title: 'Privacy Lockdown ' + (settings.privacyLockdown ? 'ENABLED' : 'DISABLED'),
      message: settings.privacyLockdown ? 
        'All camera, microphone, and GPS access blocked across browser' :
        'Privacy lockdown disabled',
      priority: 2
    });
    
    sendResponse({ success: true, enabled: settings.privacyLockdown });
    return true;
  }
  
  if (request.action === 'getSurveillanceLog') {
    sendResponse({ log: surveillanceLog });
    return true;
  }
  
  if (request.action === 'fraudDetected') {
    const { domain, fraudScore, threats, isPaymentPage } = request;
    
    console.log('[HelioRa] FRAUD DETECTED:', {
      domain,
      fraudScore,
      threats: threats.length,
      isPaymentPage
    });
    
    // Update domain data with fraud info
    const domainData = domainDataCache.get(domain);
    if (domainData) {
      domainData.fraudScore = fraudScore;
      domainData.fraudThreats = threats;
      domainData.riskScore = Math.max(domainData.riskScore || 0, fraudScore);
      
      if (fraudScore >= 70) {
        domainData.status = 'dangerous';
      } else if (fraudScore >= 40) {
        domainData.status = 'suspicious';
      }
      
      // Add fraud events
      threats.forEach(threat => {
        domainData.events.push({
          time: new Date().toLocaleTimeString(),
          type: 'fraud-detected',
          description: threat,
          severity: 'critical'
        });
      });
      
      domainDataCache.set(domain, domainData);
    }
    
    // Show notification for critical fraud
    if (fraudScore >= 70) {
      chrome.notifications.create({
        type: 'basic',
        iconUrl: 'icons/icon128.png',
        title: '🚨 CRITICAL FRAUD ALERT',
        message: `HelioRa detected ${threats.length} fraud indicators on ${domain}\n\n${threats[0] || 'High risk site'}`,
        priority: 2,
        requireInteraction: true
      });
      
      // Add to fraud memory
      if (!fraudMemory.find(f => f.domain === domain)) {
        fraudMemory.push({
          domain,
          fraudScore,
          threats,
          timestamp: Date.now(),
          firstSeen: new Date().toISOString()
        });
        
        // Keep only last 100 fraud attempts
        if (fraudMemory.length > 100) {
          fraudMemory.shift();
        }
        
        chrome.storage.local.set({ fraudMemory });
      }
      
      stats.threatsBlocked++;
      chrome.storage.local.set({ stats });
    }
    
    sendResponse({ success: true });
    return true;
  }
  
  if (request.action === 'getFraudMemory') {
    sendResponse({ fraudMemory });
    return true;
  }
  
  if (request.action === 'checkFraudHistory') {
    const { domain } = request;
    const history = fraudMemory.filter(f => f.domain === domain);
    sendResponse({ history, hasHistory: history.length > 0 });
    return true;
  }
  
  if (request.action === 'analyzeBrandImpersonation') {
    (async () => {
      const { domain, url, brandClaims, pageTitle, hasLoginForm } = request;
      
      // Use AI to analyze if this is really brand impersonation
      const brandName = brandClaims[0]?.brand;
      const legitimateDomains = brandClaims[0]?.legitimateDomains.join(', ');
      
      const prompt = `Analyze if this is a phishing/impersonation attempt:

Website: ${domain}
Page Title: ${pageTitle}
Claims to be: ${brandName}
Legitimate domains: ${legitimateDomains}
Has login form: ${hasLoginForm}

Is this likely a fraud attempt impersonating ${brandName}? Answer with ONLY "YES" or "NO" and a brief reason (one sentence).`;

      try {
        const aiResponse = await fetch(NVIDIA_API_URL, {
          method: 'POST',
          headers: {
            'Authorization': `Bearer ${NVIDIA_API_KEY}`,
            'Content-Type': 'application/json'
          },
          body: JSON.stringify({
            model: 'meta/llama-3.1-8b-instruct',
            messages: [{ role: 'user', content: prompt }],
            temperature: 0.1,
            max_tokens: 100
          })
        });
        
        if (aiResponse.ok) {
          const data = await aiResponse.json();
          const analysis = data.choices[0]?.message?.content || '';
          
          if (analysis.startsWith('YES')) {
            sendResponse({
              isFraud: true,
              message: `BRAND IMPERSONATION: This page imitates ${brandName.toUpperCase()} but is hosted on an untrusted domain`
            });
          } else {
            sendResponse({ isFraud: false });
          }
        } else {
          sendResponse({ isFraud: false });
        }
      } catch (error) {
        console.error('[HelioRa] Brand impersonation analysis error:', error);
        sendResponse({ isFraud: false });
      }
    })();
    return true;
  }
});

// Cookie Management Functions
let cookiesBlocked = 0;

// Block cookies based on settings
chrome.cookies.onChanged.addListener(async (changeInfo) => {
  if (!changeInfo.removed && changeInfo.cookie) {
    const cookie = changeInfo.cookie;
    
    // Block all cookies if enabled
    if (settings.blockCookies) {
      try {
        await chrome.cookies.remove({
          url: `http${cookie.secure ? 's' : ''}://${cookie.domain}${cookie.path}`,
          name: cookie.name,
          storeId: cookie.storeId
        });
        cookiesBlocked++;
        console.log('[HelioRa] Blocked cookie:', cookie.name, 'from', cookie.domain);
      } catch (error) {
        console.error('[HelioRa] Error blocking cookie:', error);
      }
    }
    // Block only third-party cookies if enabled
    else if (settings.blockThirdPartyCookies && !cookie.domain.startsWith('.') && cookie.domain !== cookie.hostOnly) {
      try {
        await chrome.cookies.remove({
          url: `http${cookie.secure ? 's' : ''}://${cookie.domain}${cookie.path}`,
          name: cookie.name,
          storeId: cookie.storeId
        });
        cookiesBlocked++;
        console.log('[HelioRa] Blocked third-party cookie:', cookie.name, 'from', cookie.domain);
      } catch (error) {
        console.error('[HelioRa] Error blocking third-party cookie:', error);
      }
    }
  }
});

// Get cookies blocked count
function getCookiesBlockedCount() {
  return cookiesBlocked;
}

// Reset cookies blocked count
function resetCookiesBlocked() {
  cookiesBlocked = 0;
}

// Save stats and counter periodically
setInterval(() => {
  chrome.storage.local.set({ stats, dynamicRuleIdCounter });
}, 30000); // Every 30 seconds

console.log('[HelioRa] Service Worker Ready!');
