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
chrome.storage.local.get(['stats', 'blockedDomains', 'firewallRules', 'settings', 'dynamicRuleIdCounter', 'fraudMemory', 'cookiesBlocked']).then(async result => {
  if (result.stats) stats = result.stats;
  if (result.blockedDomains) blockedDomains = result.blockedDomains;
  if (result.firewallRules) firewallRules = result.firewallRules;
  if (result.settings) settings = result.settings;
  if (result.dynamicRuleIdCounter) dynamicRuleIdCounter = result.dynamicRuleIdCounter;
  if (result.fraudMemory) fraudMemory = result.fraudMemory;
  if (result.cookiesBlocked) cookiesBlocked = result.cookiesBlocked;
  
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

// Track ad/tracker blocking via content script reports
// Note: declarativeNetRequest.onRuleMatchedDebug only works in dev mode
// So we use a combination of estimated counts and content script reports

// Increment stats when content scripts report blocked resources
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === 'resourceBlocked') {
    const url = request.url?.toLowerCase() || '';
    
    // Check if it's a tracker or ad
    if (url.includes('analytics') || url.includes('tracking') || url.includes('tracker') || url.includes('/tr/')) {
      stats.trackersBlocked++;
    } else if (url.includes('ad') || url.includes('banner') || url.includes('doubleclick') || url.includes('adsense')) {
      stats.adsBlocked++;
    } else {
      stats.adsBlocked++; // Default to ad
    }
    
    // Save periodically
    if ((stats.adsBlocked + stats.trackersBlocked) % 10 === 0) {
      chrome.storage.local.set({ stats });
    }
    
    console.log('[HelioRa] Blocked resource:', url.substring(0, 60));
  }
});

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
    
    // Estimate blocked resources (since declarativeNetRequest blocks silently)
    // Average website has 20-30 tracker/ad requests
    stats.adsBlocked += 5;  // Conservative estimate per page load
    stats.trackersBlocked += 3;
    
    // Save occasionally
    if ((stats.adsBlocked + stats.trackersBlocked) % 50 === 0) {
      chrome.storage.local.set({ stats });
    }
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
async function getHelioAIAnalysis(domain, url, detectedThreats, riskScore) {
  try {
    // Only show "secure" message if truly safe (risk score < 10 AND no threats)
    if (detectedThreats.length === 0 && riskScore < 10) {
      return "This website appears secure. HelioAI found no significant security concerns or suspicious patterns.";
    }
    
    // Determine threat context
    const threatContext = {
      hasPhishing: detectedThreats.some(t => t.toLowerCase().includes('phish') || t.toLowerCase().includes('typosquat')),
      hasMalware: detectedThreats.some(t => t.toLowerCase().includes('malware') || t.toLowerCase().includes('dangerous')),
      hasInsecure: detectedThreats.some(t => t.toLowerCase().includes('http') || t.toLowerCase().includes('insecure')),
      hasSuspiciousDomain: detectedThreats.some(t => t.toLowerCase().includes('domain') || t.toLowerCase().includes('tld')),
      count: detectedThreats.length
    };
    
    // Create a smart, context-aware prompt with better instructions
    const prompt = `You are HelioAI, an advanced cybersecurity analyst. Analyze this website with precision and intelligence.

Website Information:
- Domain: ${domain}
- Full URL: ${url}
- Risk Score: ${riskScore}/100
- Security Concerns: ${detectedThreats.join('; ')}

Analysis Guidelines:
1. Consider context: Is this a security tool/blog that naturally has security terms in the URL?
2. Distinguish between legitimate tools (downloaders, converters) and actual threats
3. Don't flag security research sites, antivirus sites, or security news sites
4. Look for REAL malicious intent patterns, not just keywords
5. Consider if the domain extension and structure make sense for the service

Provide a brief, accurate analysis (2-3 sentences max) that:
- Explains the ACTUAL risk to the user
- Gives specific advice if dangerous
- Acknowledges if it's likely a false positive
- Uses clear, non-technical language

Focus on what the user should KNOW and DO, not just repeating the detected patterns.`;

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
            role: 'system',
            content: 'You are HelioAI, a precise security analyst. Give accurate, context-aware assessments. Be smart about false positives. Keep responses under 200 characters.'
          },
          {
            role: 'user',
            content: prompt
          }
        ],
        temperature: 0.15, // Lower temperature for more consistent, factual responses
        max_tokens: 120,
        top_p: 0.9
      })
    });

    if (response.ok) {
      const data = await response.json();
      let aiResponse = data.choices[0]?.message?.content;
      
      if (aiResponse) {
        // Clean up the response
        aiResponse = aiResponse.trim();
        
        // Remove common AI prefixes
        aiResponse = aiResponse.replace(/^(Analysis:|Assessment:|HelioAI says:|Based on the analysis,?|Upon review,?)/i, '').trim();
        
        // Limit length for UI
        if (aiResponse.length > 300) {
          aiResponse = aiResponse.substring(0, 297) + '...';
        }
        
        console.log('[HelioRa] AI Analysis received:', aiResponse);
        return aiResponse;
      }
    } else {
      console.error('[HelioRa] API response not OK:', response.status, response.statusText);
    }
  } catch (error) {
    console.error('[HelioRa] NVIDIA API error:', error);
  }
  
  // Intelligent fallback message based on threat type
  if (detectedThreats.length > 0) {
    const firstThreat = detectedThreats[0].toLowerCase();
    
    if (firstThreat.includes('typosquat')) {
      return "This domain resembles a popular brand but isn't the official site. Verify the URL carefully before entering sensitive information.";
    } else if (firstThreat.includes('malware') || firstThreat.includes('dangerous')) {
      return "This site shows patterns commonly associated with malware distribution. Avoid downloading files or clicking suspicious links.";
    } else if (firstThreat.includes('phishing')) {
      return "Multiple phishing indicators detected. Be cautious about entering passwords or personal information on this site.";
    } else if (firstThreat.includes('insecure') || firstThreat.includes('http')) {
      return "This site uses an unencrypted connection (HTTP). Your data could be intercepted. Avoid entering sensitive information.";
    } else if (firstThreat.includes('suspicious')) {
      return "Some unusual patterns detected. Exercise caution and verify the site's legitimacy before interacting with it.";
    }
    
    return `Security concern detected: ${detectedThreats[0]}. Please review the threat details and proceed with caution.`;
  }
  
  return "HelioAI is analyzing this website for security concerns...";
}

// AI request rate limiting
let lastAIRequest = 0;
const AI_REQUEST_COOLDOWN = 3000; // 3 seconds between AI requests

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
    
    // Skip analysis for major trusted sites (Google, etc.) to avoid bot detection
    const skipAnalysis = [
      'google.com', 'google.co.in', 'google.co.uk',
      'youtube.com', 'gmail.com', 'drive.google.com',
      'docs.google.com', 'chrome.google.com'
    ];
    
    if (skipAnalysis.some(trusted => domain.endsWith(trusted) || domain === trusted)) {
      console.log('[HelioRa] Skipping analysis for trusted Google service:', domain);
      return;
    }
    
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
      
      // 8. Tunnel domain detection (CRITICAL RISK +80) - CamPhish indicator
      const tunnelDomains = [
        'ngrok.io', 'ngrok-free.app', 'ngrok.app',
        'trycloudflare.com', 'cloudflare.app',
        'serveo.net', 'localhost.run', 'loca.lt',
        'tunnelto.dev', 'localtunnel.me', 'pagekite.me'
      ];
      
      const isTunnelDomain = tunnelDomains.some(tunnel => 
        domain.includes(tunnel) || domain.endsWith(tunnel)
      );
      
      if (isTunnelDomain) {
        riskScore += 80;
        threats.push('Temporary tunnel hosting detected - common in surveillance attacks');
        detectionReasons.push('CamPhish-style tunnel domain');
        status = 'dangerous'; // Override status
      }
      
      // 9. Suspicious TLD check (MEDIUM RISK +30)
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
    
    // Get AI analysis with rate limiting
    let aiAnalysis = null;
    const now = Date.now();
    
    // Only call AI if:
    // 1. Enough time has passed since last request (rate limiting)
    // 2. There are actual threats OR risk score is significant
    if (now - lastAIRequest > AI_REQUEST_COOLDOWN && (detectionReasons.length > 0 || riskScore >= 30)) {
      lastAIRequest = now;
      aiAnalysis = await getHelioAIAnalysis(domain, url, detectionReasons, riskScore);
    } else if (detectionReasons.length > 0) {
      // Use fallback message if rate limited
      aiAnalysis = "Some unusual patterns detected. Exercise caution and verify the site's legitimacy before interacting with it.";
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
    sendResponse({ 
      stats: {
        ...stats,
        cookiesBlocked: cookiesBlocked
      }
    });
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

// Block cookies based on settings (with better error handling)
if (chrome.cookies && chrome.cookies.onChanged) {
  chrome.cookies.onChanged.addListener(async (changeInfo) => {
    try {
      if (!changeInfo.removed && changeInfo.cookie) {
        const cookie = changeInfo.cookie;
        
        // Block all cookies if enabled
        if (settings.blockCookies) {
          await chrome.cookies.remove({
            url: `http${cookie.secure ? 's' : ''}://${cookie.domain}${cookie.path}`,
            name: cookie.name,
            storeId: cookie.storeId
          });
          cookiesBlocked++;
          
          // Save count every 5 cookies
          if (cookiesBlocked % 5 === 0) {
            chrome.storage.local.set({ cookiesBlocked });
          }
          
          console.log('[HelioRa] Blocked cookie:', cookie.name, 'from', cookie.domain);
        }
        // Block only third-party cookies if enabled
        else if (settings.blockThirdPartyCookies) {
          const isThirdParty = cookie.domain.startsWith('.') || !cookie.hostOnly;
          
          if (isThirdParty) {
            await chrome.cookies.remove({
              url: `http${cookie.secure ? 's' : ''}://${cookie.domain}${cookie.path}`,
              name: cookie.name,
              storeId: cookie.storeId
            });
            cookiesBlocked++;
            
            // Save count every 5 cookies
            if (cookiesBlocked % 5 === 0) {
              chrome.storage.local.set({ cookiesBlocked });
            }
            
            console.log('[HelioRa] Blocked third-party cookie:', cookie.name, 'from', cookie.domain);
          }
        }
      }
    } catch (error) {
      console.error('[HelioRa] Cookie blocking error:', error);
    }
  });
  
  console.log('[HelioRa] Cookie blocking listener active');
} else {
  console.warn('[HelioRa] Cookie API not available');
}

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
  chrome.storage.local.set({ 
    stats, 
    dynamicRuleIdCounter,
    cookiesBlocked 
  });
  console.log('[HelioRa] Stats saved:', stats, 'Cookies:', cookiesBlocked);
}, 10000); // Every 10 seconds

// ==================== macOS SYSTEM INTEGRATION ====================

// Check if macOS monitor app is running
let macOSMonitorAvailable = false;
let lastOSCheck = 0;
const OS_CHECK_INTERVAL = 2000; // Check every 2 seconds

async function checkMacOSMonitor() {
  try {
    const response = await fetch('http://localhost:9876/health', {
      method: 'GET',
      signal: AbortSignal.timeout(1000) // 1 second timeout
    });
    
    if (response.ok) {
      const data = await response.json();
      if (!macOSMonitorAvailable) {
        console.log('[HelioRa] ✅ macOS Monitor connected:', data);
        macOSMonitorAvailable = true;
      }
      return true;
    }
  } catch (error) {
    if (macOSMonitorAvailable) {
      console.log('[HelioRa] ⚠️ macOS Monitor disconnected');
      macOSMonitorAvailable = false;
    }
    return false;
  }
}

// Cross-verify browser surveillance with OS-level usage
async function crossVerifyOSSurveillance(tabId, domain) {
  if (!macOSMonitorAvailable) {
    const now = Date.now();
    if (now - lastOSCheck > OS_CHECK_INTERVAL) {
      lastOSCheck = now;
      await checkMacOSMonitor();
    }
    return; // macOS app not running, skip check
  }
  
  try {
    // Get OS-level surveillance status
    const response = await fetch('http://localhost:9876/status', {
      method: 'GET',
      signal: AbortSignal.timeout(1000)
    });
    
    if (!response.ok) {
      macOSMonitorAvailable = false;
      return;
    }
    
    const osStatus = await response.json();
    
    // Check if there's a discrepancy
    const osCameraActive = osStatus.camera;
    const osMicActive = osStatus.microphone;
    
    // Get browser's knowledge (from surveillance logs)
    const browserKnowsAboutCamera = await checkBrowserKnowsAboutSurveillance(domain, 'getUserMedia');
    
    // CRITICAL CHECK: OS says camera/mic is on, but browser didn't detect it
    if ((osCameraActive || osMicActive) && !browserKnowsAboutCamera) {
      console.error('[HelioRa] 🚨 CRITICAL: HIDDEN SURVEILLANCE DETECTED!');
      console.error('[HelioRa] OS Status:', osStatus);
      console.error('[HelioRa] Browser knowledge:', browserKnowsAboutCamera);
      
      // Show nuclear-level warning
      await showHiddenSurveillanceWarning(tabId, domain, {
        osCameraActive,
        osMicActive,
        osTimestamp: osStatus.timestamp
      });
      
      stats.threatsBlocked++;
      await chrome.storage.local.set({ stats });
    }
    
    // Log OS status for forensics
    console.log('[HelioRa] OS Surveillance Check:', {
      domain,
      camera: osCameraActive,
      microphone: osMicActive,
      browserKnows: browserKnowsAboutCamera,
      discrepancy: (osCameraActive || osMicActive) && !browserKnowsAboutCamera
    });
    
  } catch (error) {
    // Network error - app probably not running
    macOSMonitorAvailable = false;
  }
}

// Check if browser knows about surveillance on this domain
async function checkBrowserKnowsAboutSurveillance(domain, type) {
  try {
    const result = await chrome.storage.local.get(['surveillanceLog']);
    if (!result.surveillanceLog) return false;
    
    // Check if there are recent logs (last 5 seconds) for this domain and type
    const recentLogs = result.surveillanceLog.filter(log => {
      const logTime = new Date(log.timestamp).getTime();
      const now = Date.now();
      const isRecent = (now - logTime) < 5000; // Last 5 seconds
      const matchesDomain = log.domain === domain;
      const matchesType = log.type === type;
      const wasAllowed = !log.blocked;
      
      return isRecent && matchesDomain && matchesType && wasAllowed;
    });
    
    return recentLogs.length > 0;
  } catch (error) {
    return false;
  }
}

// Show critical warning for hidden surveillance
async function showHiddenSurveillanceWarning(tabId, domain, osStatus) {
  // Send to content script to show full-page warning
  try {
    await chrome.tabs.sendMessage(tabId, {
      action: 'showHiddenSurveillanceWarning',
      domain: domain,
      osStatus: osStatus
    });
  } catch (error) {
    // Tab might not have content script, show notification instead
    chrome.notifications.create({
      type: 'basic',
      iconUrl: 'icons/icon128.png',
      title: '🚨 CRITICAL: HIDDEN SURVEILLANCE DETECTED',
      message: `${domain} is using your camera/microphone WITHOUT browser permission!\n\nThis is extremely dangerous. Close this site immediately.`,
      priority: 2,
      requireInteraction: true,
      buttons: [
        { title: 'Close Tab' },
        { title: 'Block Domain' }
      ]
    });
  }
}

// Poll OS status for active tabs
setInterval(async () => {
  if (!macOSMonitorAvailable) {
    await checkMacOSMonitor();
    return;
  }
  
  // Get active tab
  const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
  if (tabs.length === 0) return;
  
  const tab = tabs[0];
  if (!tab.url || tab.url.startsWith('chrome://')) return;
  
  try {
    const url = new URL(tab.url);
    const domain = url.hostname.replace('www.', '');
    
    // Cross-verify surveillance
    await crossVerifyOSSurveillance(tab.id, domain);
  } catch (error) {
    // Invalid URL, skip
  }
}, 3000); // Check every 3 seconds

// Initial check on startup
checkMacOSMonitor();

console.log('[HelioRa] Service Worker Ready!');
console.log('[HelioRa] macOS System Integration: Enabled');
console.log('[HelioRa] Checking for macOS Monitor app on localhost:9876...');
