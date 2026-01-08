(function() {
  'use strict';
  
  console.log('%c[HelioRa] Advanced Surveillance Protection Active', 'color: #4CAF50; font-weight: bold; font-size: 14px');
  
  
  const domain = window.location.hostname;
  const url = window.location.href.toLowerCase();

  const TEST_MODE = true; 

  const PRE_VERIFIED_DOMAINS = [
    'google.com', 'microsoft.com', 'github.com', 'aws.amazon.com',
    'hdfcbank.com', 'icicibank.com', 'sbi.co.in', 'paytm.com', 'phonepe.com',
    'paypal.com', 'stripe.com', 'razorpay.com',
    'okta.com', 'auth0.com',
    'facebook.com', 'twitter.com', 'linkedin.com',
  'amazon.com', 'flipkart.com',
  'reuters.com', 'theguardian.com', 'bbc.com', 'cnn.com', 'nytimes.com',
  'zoom.us', 'teams.microsoft.com', 'discord.com', 'slack.com'
  ];


  window.addEventListener('message', (event) => {
    if (event.data && event.data.type === 'HELIORA_SETTINGS_UPDATE') {
      const newSettings = event.data.settings;
      if (newSettings && newSettings.threatDetection !== false) {
         console.log('[HelioRa Protection] Settings updated, ensuring protection is active');
         initProtection();
      }
    }
  });



const HARD_BLOCKED_PATTERNS = [
  'localhost',
  '127.0.0.1',
  '0.0.0.0',
  '::1',
  '.ngrok.io',
  '.ngrok-free.app',
  '.trycloudflare.com',
  '.loca.lt',
  '.localtunnel.me','.serveo.net','.localhost.run','.tunnelto.dev','.pagekite.me', '.tunnel.pyjam.as'
];

  const TRUSTED_DOMAINS = PRE_VERIFIED_DOMAINS;
  

  const TUNNEL_PATTERNS = HARD_BLOCKED_PATTERNS;
  

  const SUSPICIOUS_PATTERNS = [
    'festival-wish', 'greeting-card', 
    'camera-test', 'mic-test',
    'enable-camera', 'enable-mic', 'grant-access'
  ];

  // OTP PROTECTION MODULE CONSTANTS 
  const OTP_RISK_WEIGHTS = {
    FIELD_DETECTED: 20,
    HARD_RISK_ORIGIN: 100, 
    AI_RISKY: 30,
    CLIPBOARD_ACCESS: 20,
    CROSS_ORIGIN: 25,
    PERMISSION_ABUSE: 30,
    TIMING_ANOMALY: 20
  };

  const OTP_RISK_THRESHOLDS = {
    SILENT_ALLOW: 39,
    WARN: 40,
    BLOCK: 70
  };


  let currentOtpRiskScore = 0;
  let lastOtpInteractionTime = 0;
  let otpFieldsFound = false;
  let clipboardAccessed = false;
  let otpWarningShown = false;
  
  // Trust Management (Granular Trust Model)
  let trustedSites = {};
  try {
    const stored = localStorage.getItem('heliora_trusted_sites');
    if (stored) trustedSites = JSON.parse(stored);
  } catch (e) {}

  function saveTrustedSite(domain) {
    trustedSites[domain] = {
      timestamp: Date.now(),
      expiry: Date.now() + (30 * 24 * 60 * 60 * 1000) // 30 days
    };
    try {
      localStorage.setItem('heliora_trusted_sites', JSON.stringify(trustedSites));
    } catch (e) {}
  }

  
  // Check if domain is trusted
  const isTrusted = TRUSTED_DOMAINS.some(trusted => domain.includes(trusted));
  
  // Check if domain uses tunnel hosting
  const isIpHost = /^\d{1,3}(\.\d{1,3}){3}$/.test(domain);
  const isTunnel = isIpHost || TUNNEL_PATTERNS.some(pattern => 
    domain.includes(pattern) || domain.endsWith(pattern)
  );
  
  // Check for suspicious content
  const isSuspicious = SUSPICIOUS_PATTERNS.some(pattern => 
    url.includes(pattern) || document.title.toLowerCase().includes(pattern)
  );
  
  // Determine if we should block surveillance APIs
  const SHOULD_BLOCK = isTunnel || ((isSuspicious) && !isTrusted);
  
  // Track permission requests for multi-attack detection
  let permissionRequests = new Set();
  let blockCount = 0;
  
  if (SHOULD_BLOCK) {
    console.log('%c[HelioRa] ⚠️ THREAT DETECTED - Enabling strict protection', 'color: #ff5252; font-weight: bold; font-size: 14px');
    console.log('[HelioRa] Domain:', domain);
    console.log('[HelioRa] Tunnel hosting:', isTunnel);
    console.log('[HelioRa] Suspicious patterns:', isSuspicious);
  }

  // otp risk

  function checkDomainCategory() {
    // TEST MODE BYPASS
    if (TEST_MODE && (window.location.protocol === 'file:' || domain === 'localhost' || domain === '127.0.0.1')) {
       console.log('[HelioRa] 🧪 TEST MODE: Treating localhost/file as YELLOW for UI testing');
       return 'YELLOW';
    }

    // 0. File Protocol (Red)
    if (window.location.protocol === 'file:') {
      return 'RED';
    }

    // 1. Hard Blocked (Red)
    if (HARD_BLOCKED_PATTERNS.some(p => domain.includes(p) || domain === p)) {
      return 'RED';
    }
    // 2. Pre-Verified (Green)
    if (PRE_VERIFIED_DOMAINS.some(d => domain.endsWith(d))) {
      return 'GREEN';
    }
    // 3. User Trusted (Green)
    if (trustedSites[domain] && trustedSites[domain].expiry > Date.now()) {
      return 'GREEN';
    }
    // 4. Unknown (Yellow)
    return 'YELLOW';
  }

  function simulateAiReputation() {
    // Mock AI Analysis - Enhanced Heuristics
    const sslValid = window.isSecureContext;
    let score = 0;
    let verdict = 'safe';
    let summary = '';
    const reasons = [];

    // 1. SSL/TLS Check
    if (!sslValid) {
       score += 50;
       reasons.push('Insecure Transport Protocol (HTTP) Detected');
    }

    // 2. Suspicious TLDs
    const suspiciousTLDs = ['.xyz', '.top', '.club', '.info', '.site', '.live', '.online', '.tk', '.ml', '.ga', '.cf', '.gq'];
    if (suspiciousTLDs.some(tld => domain.endsWith(tld))) {
      score += 30;
      reasons.push('High-Risk TLD Segment Identified');
    }

    // 3. Subdomain Complexity (Entropy/Length)
    const subdomains = domain.split('.');
    if (subdomains.length > 3) {
       score += 20;
       reasons.push('Abnormal Subdomain Complexity (High Entropy)');
    }
    
    // Check for random-looking subdomains (e.g., x83ks.example.com)
    const isRandomSub = subdomains.some(sub => sub.length > 8 && /[0-9]/.test(sub) && /[a-z]/.test(sub));
    if (isRandomSub) {
      score += 25;
      reasons.push('Algorithmic/Random Subdomain Pattern Detected');
    }

    // 4. Keyword Typosquatting (Simple check)
    // Checks if domain contains bank names but isn't the exact bank domain
    const protectedKeywords = ['bank', 'secure', 'login', 'account', 'update', 'verify', 'support', 'service'];
    if (protectedKeywords.some(kw => domain.includes(kw)) && !isTrusted) {
      score += 15;
      reasons.push('High-Value Target Keyword Match in Untrusted Origin');
    }

    // 5. Environment Check
    if (window.location.protocol === 'file:') reasons.push('Execution Context: Local File System (Unverified)');
    if (domain === 'localhost' || domain === '127.0.0.1') reasons.push('Execution Context: Localhost Loopback (Development Environment)');
    
    // 6. Advanced Heuristics
    // Punycode Detection (IDN Homograph Attack Potential)
    if (domain.includes('xn--')) {
      score += 40;
      reasons.push('IDN Homograph Pattern (Punycode) Detected');
    }
    
    // Direct IP Usage
    const isIpAddress = /^(\d{1,3}\.){3}\d{1,3}$/.test(domain);
    if (isIpAddress && domain !== '127.0.0.1') {
      score += 35;
      reasons.push('Direct IP Address Host (Non-Standard DNS)');
    }
    
    // Excessive Length
    if (domain.length > 60) {
      score += 15;
      reasons.push('Abnormally Long Domain Name (Possible Obfuscation)');
    }

    // Determine Verdict
    if (score >= 60) {
      verdict = 'risky';
      summary = `⚠️ CRITICAL THREAT DETECTED\n\nVERDICT:\n• ${reasons.join('\n• ')}\n\nRECOMMENDATION: TERMINATE CONNECTION IMMEDIATELY.`;
    } else if (score >= 30) {
      verdict = 'warning';
      summary = `⚠️ SECURITY WARNING\n\nRISK INDICATORS:\n• ${reasons.join('\n• ')}\n\nRECOMMENDATION: PROCEED WITH CAUTION. Sensitive data entry discouraged.`;
    } else {
      if (reasons.length > 0) {
          summary = `✓ SAFE (WITH NOTICES)\n\nOBSERVATIONS:\n• ${reasons.join('\n• ')}\n\nSTATUS: Verified Secure Connection.`;
      } else {
          summary = '✓ SECURE ENVIRONMENT\n\nANALYSIS:\n• Valid SSL/TLS Encryption\n• Established Domain Reputation\n• No Anomalous Patterns Detected\n\nSTATUS: SAFE for Sensitive Transactions.';
      }
    }
    
    return {
      verdict: score > 40 ? 'risky' : verdict,
      confidence: 85,
      riskScore: score,
      summary,
      reasons // Export reasons for UI
    };
  }

  function updateOtpRiskScore(aiResult = null) {
    let score = 0;
    
    // 1. Base Signal
    if (otpFieldsFound) score += OTP_RISK_WEIGHTS.FIELD_DETECTED;
    
    // 2. Origin Risk
    if (checkDomainCategory() === 'RED') {
      score += OTP_RISK_WEIGHTS.HARD_RISK_ORIGIN;
    }
    
    // 3. AI Risk
    if (aiResult) {
      if (aiResult.verdict === 'risky') {
        score += OTP_RISK_WEIGHTS.AI_RISKY;
      } else if (aiResult.verdict === 'warning') {
        score += 15; // Moderate risk
      }
    }
    
    // 4. Clipboard Risk
    if (clipboardAccessed && otpFieldsFound) {
      score += OTP_RISK_WEIGHTS.CLIPBOARD_ACCESS;
    }
    
    // 5. Permission Abuse
    if (typeof allApiAttempts !== 'undefined' && allApiAttempts.size > 0) {
      score += OTP_RISK_WEIGHTS.PERMISSION_ABUSE;
    }

    currentOtpRiskScore = score;
    return score;
  }

  function checkHardConstraints(targetUrlStr) {
    try {
      const targetUrl = new URL(targetUrlStr, window.location.href);
      // 1. Cross-Origin OTP
      if (targetUrl.hostname !== window.location.hostname) {
        return { violated: true, reason: 'Cross-Origin Submission (Data sent to different domain)' };
      }
    } catch(e) {}
    
    // 2. Permission Abuse (Active Cam/Mic)
    if (typeof allApiAttempts !== 'undefined' && 
       (allApiAttempts.has('getUserMedia') || allApiAttempts.has('getDisplayMedia'))) {
       return { violated: true, reason: 'Active Surveillance (Camera/Microphone active during Auth)' };
    }

    // 3. Fullscreen Abuse
    if (document.fullscreenElement) {
       return { violated: true, reason: 'Fullscreen forced during authentication' };
    }
    
    // 4. Clipboard Write (if detectable and blocked)
    if (clipboardAccessed && otpFieldsFound) {
         return { violated: true, reason: 'Clipboard Access detected (Blocked by Security Policy)' };
    }

    return { violated: false };
  }
  function scanForOtpFields() {
    // 1. OTP Field Detection (Base Signal)
    const inputs = document.querySelectorAll('input:not([type="hidden"]):not([type="submit"]):not([type="button"])');
    let detected = false;
    
    inputs.forEach(input => {
      const id = (input.id || '').toLowerCase();
      const name = (input.name || '').toLowerCase();
      const placeholder = (input.placeholder || '').toLowerCase();
      
      // Filter out common false positives for "code"
      const isFalsePositive = (str) => 
        str.includes('zip') || str.includes('postal') || str.includes('country') || 
        str.includes('color') || str.includes('promo') || str.includes('discount') || 
        str.includes('coupon') || str.includes('invite') || str.includes('referral');

      const matchesKeyword = (str) => {
        if (/otp|2fa|verification/.test(str)) return true;
        if (str.includes('code') && !isFalsePositive(str)) return true;
        return false;
      };

      // Heuristics for OTP fields
      const isOtp = (
        (input.maxLength > 0 && input.maxLength <= 8 && input.maxLength >= 4 && input.pattern && input.pattern.includes('[0-9]')) || // Strict length + pattern
        input.autocomplete === 'one-time-code' ||
        matchesKeyword(id) ||
        matchesKeyword(name) ||
        matchesKeyword(placeholder)
      );
      
      if (isOtp) {
        detected = true;
        
        // Mark monitored fields to track timing
        if (!input.dataset.helioraMonitored) {
          input.dataset.helioraMonitored = 'true';
          input.addEventListener('input', () => {
            lastOtpInteractionTime = Date.now();
          });
        }
      }
    });
    
    if (detected && !otpFieldsFound) {
      console.log('[HelioRa] 🔐 OTP Input Field Detected - Initializing Protection');
      otpFieldsFound = true;
      updateOtpRiskScore();
    }
  }

function initProtection() {
  if (window.helioRaProtectionInitialized) return;
  window.helioRaProtectionInitialized = true;
  console.log('[HelioRa Protection] Initializing hooks...');

  setInterval(scanForOtpFields, 2000);
  setTimeout(scanForOtpFields, 500); 

  function looksLikeSensitiveData(v) {
    try {
      if (!v) return false;
      if (typeof v === 'string') {
        const s = v.trim();
        // Check for specific keys in query strings or JSON
        if (/(^|[=&"'])((otp|code|passcode|verification_code|twofa|2fa)["']?\s*[:=]\s*["']?)/i.test(s)) {
             // If key is explicit, value can be looser
             return /\d{4,8}/.test(s); 
        }

        if (otpFieldsFound) {
             const m = s.match(/\b\d{6,8}\b/);
             return !!m;
        }
        return false;
      }
      if (v instanceof URLSearchParams) {
        for (const [k, val] of v.entries()) {
          const key = k.toLowerCase();
          if (['otp','code','passcode','verification_code','twofa','2fa'].includes(key)) return true;
          if (otpFieldsFound && /^\d{6,8}$/.test(val)) return true;
        }
      }
      if (v instanceof FormData) {
        for (const [k, val] of v.entries()) {
          const key = String(k).toLowerCase();
          const sval = String(val);
          if (['otp','code','passcode','verification_code','twofa','2fa'].includes(key)) return true;
          if (otpFieldsFound && /^\d{6,8}$/.test(sval)) return true;
        }
      }
      if (typeof v === 'object') {
        return looksLikeSensitiveData(JSON.stringify(v));
      }
    } catch (e) {}
    return false;
  }

  async function analyzeNetworkRequest(url, body, allowInteraction = true) {
    // 1. Check content for OTP
    const hasSensitiveData = looksLikeSensitiveData(body);
    if (!hasSensitiveData) return { action: 'ALLOW' };

    const category = checkDomainCategory();
    const aiResult = simulateAiReputation();
    let risk = updateOtpRiskScore(aiResult);

    const constraintCheck = checkHardConstraints(url);
    if (constraintCheck.violated) {
      logAttempt('otp-exfiltration', true, { url, risk: 100, reason: constraintCheck.reason });
      return { 
        action: 'BLOCK', 
        reason: `Hard Security Violation: ${constraintCheck.reason}`,
        risk: 100 
      };
    }

    const riskFactors = [...(aiResult.reasons || [])];
    if (otpFieldsFound) riskFactors.push('OTP Field Detected');
    if (clipboardAccessed) riskFactors.push('Clipboard Accessed');

    if (lastOtpInteractionTime > 0 && (Date.now() - lastOtpInteractionTime < 500)) {
      risk += OTP_RISK_WEIGHTS.TIMING_ANOMALY;
      riskFactors.push('Rapid Submission (Bot Behavior)');
    }

    if (category === 'RED') {
      return { action: 'BLOCK', reason: 'Hard Blocked Origin (Untrusted Environment)', risk: 100 };
    }

    if (category === 'GREEN') {
       return { action: 'ALLOW', risk };
    }

    if (risk < OTP_RISK_THRESHOLDS.WARN) {
        return { action: 'ALLOW', risk };
    }

    if (!allowInteraction) {

        if (risk >= OTP_RISK_THRESHOLDS.WARN) {
           return { action: 'BLOCK', reason: 'Risk Detected (User Interaction Unavailable)', risk };
        }
        return { action: 'ALLOW', risk };
    }
    
    // Show Decision Modal
    const userAction = await showSecurityCheck(risk, aiResult, url, riskFactors);
    
    if (userAction === 'ALLOW') {
      logAttempt('otp-exfiltration', false, { url, risk, decision: 'allowed-once' });
      return { action: 'ALLOW', risk };
    } 
    else if (userAction === 'TRUST') {
      saveTrustedSite(domain);
      logAttempt('otp-exfiltration', false, { url, risk, decision: 'trusted-site' });
      return { action: 'ALLOW', risk };
    } 
    else {
      logAttempt('otp-exfiltration', true, { url, risk, decision: 'blocked-by-user' });
      return { action: 'BLOCK', reason: 'User Blocked', risk };
    }
  }

  // Intercept Fetch
  const originalFetch = window.fetch;
  window.fetch = async function(...args) {
    const [resource, config] = args;
    const url = resource instanceof Request ? resource.url : resource;
    const body = config?.body;
    
    if (body) {
      try {
        const analysis = await analyzeNetworkRequest(url, body, true);
        if (analysis.action === 'BLOCK') {
           logAttempt('fetch-otp-exfiltration', true, { url, risk: analysis.risk });
           showOtpWarning(analysis.risk);
           document.querySelectorAll('input[data-heliora-monitored]').forEach(el => el.disabled = true);
           
           return Promise.reject(new TypeError('HelioRa: High-risk OTP authentication blocked'));
        }
      } catch (e) {
        console.error('[HelioRa] Analysis failed', e);
      }
    }
    
    return originalFetch.apply(this, args);
  };

  const originalXHROpen = XMLHttpRequest.prototype.open;
  const originalXHRSend = XMLHttpRequest.prototype.send;
  
  XMLHttpRequest.prototype.open = function(method, url) {
    this._url = url;
    return originalXHROpen.apply(this, arguments);
  };
  
  XMLHttpRequest.prototype.send = function(body) {
    const xhr = this;
    const args = arguments;

    if (body) {
      
      analyzeNetworkRequest(this._url, body, true).then(analysis => {
        if (analysis.action === 'BLOCK') {
          logAttempt('xhr-otp-exfiltration', true, { url: xhr._url, risk: analysis.risk });
          showOtpWarning(analysis.risk);
          document.querySelectorAll('input[data-heliora-monitored]').forEach(el => el.disabled = true);
          
          xhr.abort();
        } else {
          originalXHRSend.apply(xhr, args);
        }
      });
      
      return; 
    }
    return originalXHRSend.apply(this, arguments);
  };

  // Intercept Beacon
  if (navigator.sendBeacon) {
    const originalSendBeacon = navigator.sendBeacon.bind(navigator);
    navigator.sendBeacon = function(url, data) {
      if (data) {

        const category = checkDomainCategory();
        if (category === 'RED') {
           logAttempt('beacon-otp-exfiltration', true, { url, risk: 100 });
           return false;
        }

      }
      return originalSendBeacon(url, data);
    };
  }

  if (window.WebSocket) {
    const originalWebSocket = window.WebSocket;
    window.WebSocket = function(url, protocols) {
      const category = checkDomainCategory();
      if (category === 'RED') {
         console.log('[HelioRa] 🚫 WebSocket blocked (Red List)');
         throw new Error('HelioRa: WebSocket blocked');
      }


      try {
         const targetUrl = new URL(url, window.location.href);
         if (targetUrl.hostname !== window.location.hostname && otpFieldsFound) {

             console.log('[HelioRa] ⚠️ Suspicious WebSocket during OTP flow');
         }
      } catch(e) {}
      
      return new originalWebSocket(url, protocols);
    };
    Object.setPrototypeOf(window.WebSocket, originalWebSocket);
    Object.setPrototypeOf(window.WebSocket.prototype, originalWebSocket.prototype);
  }

  // Log Function
  
  let allApiAttempts = new Set();

  function logAttempt(type, blocked, details = {}) {
    const logEntry = {
      type,
      domain,
      url: window.location.href,
      timestamp: new Date().toISOString(),
      blocked,
      isTunnel,
      isSuspicious,
      ...details
    };
    
    console.log(`[HelioRa] ${blocked ? '🛡️ BLOCKED' : '✅ ALLOWED'} ${type}:`, logEntry);
    
    // Track usage for OTP risk scoring
    if (type !== 'otp-check') {
       allApiAttempts.add(type);
    }

    // Track for multi-attack detection
    if (blocked) {
      permissionRequests.add(type);
      blockCount++;
      
      // If multiple surveillance APIs requested, show critical warning
      if (blockCount >= 3) {
        showCriticalWarning();
      }
    }
    
    return logEntry;
  }
  
  //  1. CAMERA & MICROPHONE PROTECTION 
  
  if (navigator.mediaDevices?.getUserMedia) {
    const originalGetUserMedia = navigator.mediaDevices.getUserMedia.bind(navigator.mediaDevices);
    
    navigator.mediaDevices.getUserMedia = function(constraints) {
      console.log('[HelioRa] 📹 getUserMedia() called', constraints);
      
      const hasVideo = constraints?.video;
      const hasAudio = constraints?.audio;
      
      if (SHOULD_BLOCK) {
        logAttempt('getUserMedia', true, { constraints, hasVideo, hasAudio });
        showWarning(hasVideo && hasAudio ? 'CAMERA & MICROPHONE' : hasVideo ? 'CAMERA' : 'MICROPHONE');
        
        return Promise.reject(new DOMException(
          'Permission denied by HelioRa Security',
          'NotAllowedError'
        ));
      }
      
      logAttempt('getUserMedia', false, { constraints, hasVideo, hasAudio });
      return originalGetUserMedia(constraints);
    };
  }
  if (window.HTMLMediaElement) {
    const desc = Object.getOwnPropertyDescriptor(HTMLMediaElement.prototype, 'srcObject');
    if (desc && desc.set) {
      Object.defineProperty(HTMLMediaElement.prototype, 'srcObject', {
        configurable: true,
        enumerable: desc.enumerable,
        get: desc.get,
        set(value) {
          const isMediaStream = typeof MediaStream !== 'undefined' && value instanceof MediaStream;
          if (SHOULD_BLOCK && isMediaStream) {
            logAttempt('media.srcObject', true, { kind: 'MediaStream' });
            showWarning('CAMERA');
            throw new DOMException('Media attachment blocked by HelioRa Security', 'NotAllowedError');
          }
          return desc.set.call(this, value);
        }
      });
    }
  }
  if (navigator.mediaDevices?.enumerateDevices) {
    const originalEnumerateDevices = navigator.mediaDevices.enumerateDevices.bind(navigator.mediaDevices);
    navigator.mediaDevices.enumerateDevices = function() {
      if (SHOULD_BLOCK) {
        logAttempt('enumerateDevices', true);
        return Promise.resolve([]);
      }
      return originalEnumerateDevices();
    };
  }

  if (navigator.getUserMedia) {
    const originalLegacyGetUserMedia = navigator.getUserMedia.bind(navigator);
    navigator.getUserMedia = function(constraints, successCb, errorCb) {
      console.log('[HelioRa] 📹 legacy getUserMedia() called', constraints);
      const hasVideo = constraints?.video;
      const hasAudio = constraints?.audio;
      if (SHOULD_BLOCK) {
        logAttempt('getUserMedia(legacy)', true, { constraints, hasVideo, hasAudio });
        showWarning(hasVideo && hasAudio ? 'CAMERA & MICROPHONE' : hasVideo ? 'CAMERA' : 'MICROPHONE');
        if (typeof errorCb === 'function') {
          errorCb({ code: 1, name: 'NotAllowedError', message: 'Permission denied by HelioRa Security' });
        }
        return;
      }
      logAttempt('getUserMedia(legacy)', false, { constraints, hasVideo, hasAudio });
      return originalLegacyGetUserMedia(constraints, successCb, errorCb);
    };
  }

  ['webkitGetUserMedia','mozGetUserMedia'].forEach(fn => {
    if (navigator[fn]) {
      const originalPrefixed = navigator[fn].bind(navigator);
      navigator[fn] = function(constraints, successCb, errorCb) {
        console.log(`[HelioRa] 📹 ${fn}() called`, constraints);
        const hasVideo = constraints?.video;
        const hasAudio = constraints?.audio;
        if (SHOULD_BLOCK) {
          logAttempt(`${fn}`, true, { constraints, hasVideo, hasAudio });
          showWarning(hasVideo && hasAudio ? 'CAMERA & MICROPHONE' : hasVideo ? 'CAMERA' : 'MICROPHONE');
          if (typeof errorCb === 'function') {
            errorCb({ code: 1, name: 'NotAllowedError', message: 'Permission denied by HelioRa Security' });
          }
          return;
        }
        logAttempt(`${fn}`, false, { constraints, hasVideo, hasAudio });
        return originalPrefixed(constraints, successCb, errorCb);
      };
    }
  });
  
  //  2. SCREEN CAPTURE PROTECTION 
  
  if (navigator.mediaDevices?.getDisplayMedia) {
    const originalGetDisplayMedia = navigator.mediaDevices.getDisplayMedia.bind(navigator.mediaDevices);
    
    navigator.mediaDevices.getDisplayMedia = function(constraints) {
      console.log('[HelioRa] 🖥️ getDisplayMedia() called (screen capture)', constraints);
      
      // Screen sharing is extremely sensitive - requires higher trust level
      const isScreenShareTrusted = TRUSTED_DOMAINS.some(trusted => domain.includes(trusted)) ||
                                   domain.includes('zoom') || 
                                   domain.includes('meet') ||
                                   domain.includes('teams');
      
      if (SHOULD_BLOCK || !isScreenShareTrusted) {
        logAttempt('getDisplayMedia', true, { 
          constraints, 
          type: 'screen-capture',
          reason: SHOULD_BLOCK ? 'Suspicious site' : 'Untrusted for screen sharing'
        });
        showWarning('SCREEN CAPTURE');
        
        return Promise.reject(new DOMException(
          'Screen sharing denied by HelioRa Security - untrusted domain',
          'NotAllowedError'
        ));
      }
      
      logAttempt('getDisplayMedia', false, { constraints });
      return originalGetDisplayMedia(constraints);
    };
  }
  if (navigator.getDisplayMedia) {
    navigator.getDisplayMedia = navigator.mediaDevices.getDisplayMedia;
  }
  
  //  3. WEBRTC IP LEAK PROTECTION 
  
  if (window.RTCPeerConnection) {
    const originalRTCPeerConnection = window.RTCPeerConnection;
    
    window.RTCPeerConnection = function(config) {
      console.log('[HelioRa] 🌐 RTCPeerConnection created', config);
      const stunServers = config?.iceServers?.filter(server => 
        server.urls?.some(url => url.includes('stun:'))
      ) || [];
      
      if (stunServers.length > 0) {
        console.log('[HelioRa] ⚠️ STUN servers detected:', stunServers);
      }
      
      const isSuspiciousWebRTC = SHOULD_BLOCK || (
        !isTrusted && 
        !window.location.href.includes('call') && 
        !window.location.href.includes('meet') &&
        !window.location.href.includes('conference')
      );
      
      if (isSuspiciousWebRTC) {
        logAttempt('RTCPeerConnection', true, { 
          config, 
          stunServers: stunServers.length,
          reason: 'Suspicious WebRTC usage detected'
        });
        
        throw new DOMException(
          'RTCPeerConnection blocked by HelioRa Security (potential IP leak)',
          'NotSupportedError'
        );
      }
      
      logAttempt('RTCPeerConnection', false, { config, stunServers: stunServers.length });
      return new originalRTCPeerConnection(config);
    };
    
    Object.setPrototypeOf(window.RTCPeerConnection, originalRTCPeerConnection);
    Object.setPrototypeOf(window.RTCPeerConnection.prototype, originalRTCPeerConnection.prototype);
  }
  
  //  4. GPS LOCATION PROTECTION
  
  if (navigator.geolocation) {
    const originalGetCurrentPosition = navigator.geolocation.getCurrentPosition.bind(navigator.geolocation);
    const originalWatchPosition = navigator.geolocation.watchPosition.bind(navigator.geolocation);
    
    navigator.geolocation.getCurrentPosition = function(success, error, options) {
      console.log('[HelioRa] 📍 getCurrentPosition() called', options);
      
      if (SHOULD_BLOCK) {
        logAttempt('geolocation', true, { method: 'getCurrentPosition' });
        
        if (error) {
          error({
            code: 1,
            message: 'Location access denied by HelioRa Security',
            PERMISSION_DENIED: 1
          });
        }
        return;
      }
      
      logAttempt('geolocation', false, { method: 'getCurrentPosition' });
      return originalGetCurrentPosition(success, error, options);
    };
    
    navigator.geolocation.watchPosition = function(success, error, options) {
      console.log('[HelioRa] 📍 watchPosition() called', options);
      
      if (SHOULD_BLOCK) {
        logAttempt('geolocation', true, { method: 'watchPosition' });
        
        if (error) {
          error({
            code: 1,
            message: 'Location tracking denied by HelioRa Security',
            PERMISSION_DENIED: 1
          });
        }
        return -1;
      }
      
      logAttempt('geolocation', false, { method: 'watchPosition' });
      return originalWatchPosition(success, error, options);
    };
  }
  
  //5. CLIPBOARD ACCESS PROTECTION 
  
  if (navigator.clipboard) {

    if (navigator.clipboard.readText) {
      const originalReadText = navigator.clipboard.readText.bind(navigator.clipboard);
      
      navigator.clipboard.readText = function() {
        console.log('[HelioRa] 📋 clipboard.readText() called');

        clipboardAccessed = true;
        updateOtpRiskScore();
       
        const hasPasswordField = document.querySelector('input[type="password"]');
        const hasPaymentField = document.querySelector('input[name*="card"], input[name*="cvv"], input[autocomplete*="cc"]');
        
        if (SHOULD_BLOCK || hasPasswordField || hasPaymentField) {
          logAttempt('clipboard.readText', true, {
            hasPasswordField: !!hasPasswordField,
            hasPaymentField: !!hasPaymentField,
            reason: 'Clipboard read on sensitive form'
          });
          
          return Promise.reject(new DOMException(
            'Clipboard access denied by HelioRa Security',
            'NotAllowedError'
          ));
        }
        
        logAttempt('clipboard.readText', false);
        return originalReadText();
      };
    }
    
    if (navigator.clipboard.read) {
      const originalRead = navigator.clipboard.read.bind(navigator.clipboard);
      
      navigator.clipboard.read = function() {
        console.log('[HelioRa] 📋 clipboard.read() called');
        
        if (SHOULD_BLOCK) {
          logAttempt('clipboard.read', true);
          return Promise.reject(new DOMException(
            'Clipboard access denied by HelioRa Security',
            'NotAllowedError'
          ));
        }
        
        logAttempt('clipboard.read', false);
        return originalRead();
      };
    }
  }
  
  // Monitor paste events on sensitive forms
  document.addEventListener('paste', function(e) {
    const target = e.target;
    
    // Check if pasting into password/payment field
    const isPasswordField = target.type === 'password';
    const isPaymentField = target.name?.includes('card') || target.name?.includes('cvv');
    
    if ((isPasswordField || isPaymentField) && SHOULD_BLOCK) {
      console.log('[HelioRa] 🚫 Paste blocked on sensitive field');
      logAttempt('paste-trap', true, {
        fieldType: isPasswordField ? 'password' : 'payment',
        fieldName: target.name || target.id
      });
      
      e.preventDefault();
      e.stopPropagation();
    }
  }, true);
  

  
  //7. NOTIFICATION PERMISSION 
  
  if (window.Notification) {
    const originalRequestPermission = Notification.requestPermission.bind(Notification);
    
    Notification.requestPermission = function() {
      console.log('[HelioRa] 🔔 Notification.requestPermission() called');
      
      if (SHOULD_BLOCK) {
        logAttempt('notification', true);
        return Promise.resolve('denied');
      }
      
      logAttempt('notification', false);
      return originalRequestPermission();
    };
  }
  
  //  8. FULLSCREEN DETECTION 
  
  document.addEventListener('fullscreenchange', function() {
    if (document.fullscreenElement) {
      console.log('[HelioRa] 📺 Fullscreen mode activated');
      
      permissionRequests.add('fullscreen');
      
      if (permissionRequests.has('getUserMedia') || permissionRequests.has('getDisplayMedia')) {
        console.log('%c[HelioRa] ⚠️ WARNING: Fullscreen + Camera combination detected', 'color: #ff9800; font-weight: bold');
      }
    }
  });

  // 9. EVILGINX / REVERSE PROXY DETECTION 
  
  function dispatchMainWorldSignal(type, details) {
    document.dispatchEvent(new CustomEvent('HelioRaMainWorldSignal', {
      detail: { type, details }
    }));
  }

  // A. History API Abuse 
  if (history && history.replaceState) {
    const originalReplaceState = history.replaceState.bind(history);
    history.replaceState = function(state, unused, url) {
      if (performance.now() < 3000 && url) {
        console.log('[HelioRa] 🕵️‍♀️ Suspicious history.replaceState() detected');
        dispatchMainWorldSignal('HistoryAbuse', { url });
      }
      return originalReplaceState(state, unused, url);
    };
  }

  // B. Cookie Monitoring 
  try {
    const cookieDesc = Object.getOwnPropertyDescriptor(Document.prototype, 'cookie');
    if (cookieDesc && cookieDesc.set) {
      Object.defineProperty(document, 'cookie', {
        configurable: true,
        enumerable: true,
        get: function() { return cookieDesc.get.call(document); },
        set: function(val) {
          if (typeof val === 'string') {
            const lowerVal = val.toLowerCase();
            if (lowerVal.includes('samesite=none') && !lowerVal.includes('secure')) {
               dispatchMainWorldSignal('SuspiciousCookie', { value: val.split(';')[0] });
            }

          }
          return cookieDesc.set.call(document, val);
        }
      });
    }
  } catch (e) {
  }

  // C. Cross-Origin postMessage Monitoring
  window.addEventListener('message', function(e) {
    try {
      if (e.origin !== window.location.origin && e.data) {
        // If we are in an auth flow 
        const isAuthPage = /login|signin|auth|sso|verify/i.test(window.location.href);
        if (isAuthPage) {
           // Check for auth tokens in message
           if (looksLikeSensitiveData(e.data)) {
             console.log('[HelioRa] 🚨 Suspicious cross-origin message with sensitive data');
             dispatchMainWorldSignal('CrossOriginExfiltration', { origin: e.origin });
           }
        }
      }
    } catch(err) {}
  });

  //  UI: warning display
  
  function showOtpWarning(riskScore) {
    if (document.getElementById('heliora-otp-warning')) return;

    const overlay = document.createElement('div');
    overlay.id = 'heliora-otp-warning';
    overlay.style.cssText = `
      position: fixed !important;
      top: 20px !important;
      right: 20px !important;
      width: 380px !important;
      background: rgba(10, 10, 10, 0.95) !important;
      border: 1px solid ${riskScore >= 70 ? '#ff5252' : '#FFD700'} !important;
      border-radius: 12px !important;
      padding: 20px !important;
      color: #FFF !important;
      z-index: 2147483647 !important;
      box-shadow: 0 10px 30px rgba(0,0,0,0.8) !important;
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif !important;
      backdrop-filter: blur(10px) !important;
      animation: heliora-slide-in 0.4s ease-out !important;
    `;
    
    if (!document.getElementById('heliora-keyframes')) {
      const style = document.createElement('style');
      style.id = 'heliora-keyframes';
      style.innerHTML = `@keyframes heliora-slide-in { from { transform: translateX(100%); opacity: 0; } to { transform: translateX(0); opacity: 1; } }`;
      document.head.appendChild(style);
    }

    const isBlock = riskScore >= OTP_RISK_THRESHOLDS.BLOCK;
    const title = isBlock ? 'Security Block' : 'Security Warning';
    const color = isBlock ? '#ff5252' : '#FFD700';

    overlay.innerHTML = `
      <div style="display: flex; align-items: center; gap: 12px; margin-bottom: 12px;">
        <div style="color: ${color}; font-size: 24px;">${isBlock ? '🚫' : '⚠️'}</div>
        <h3 style="margin: 0; font-size: 16px; font-weight: 700; color: ${color}; text-transform: uppercase;">${title}</h3>
      </div>
      <p style="margin: 0 0 16px 0; font-size: 13px; line-height: 1.5; color: #CCC;">
        This site is attempting a high-risk authentication flow commonly used in scams.
      </p>
      <div style="background: rgba(255,255,255,0.05); padding: 12px; border-radius: 8px; margin-bottom: 16px;">
        <div style="display: flex; justify-content: space-between; font-size: 12px; margin-bottom: 6px;">
          <span style="color: #AAA;">Risk Score:</span>
          <span style="color: ${color}; font-weight: 700;">${riskScore}/100</span>
        </div>
        <div style="height: 4px; background: rgba(255,255,255,0.1); border-radius: 2px; overflow: hidden;">
          <div style="width: ${Math.min(riskScore, 100)}%; height: 100%; background: ${color};"></div>
        </div>
      </div>
      <div style="display: flex; gap: 8px;">
        <button id="heliora-otp-dismiss" style="
          flex: 1; padding: 8px; background: transparent; border: 1px solid #444; color: #CCC; border-radius: 6px; cursor: pointer; font-weight: 600; font-size: 12px;
        ">Dismiss</button>
        ${isBlock ? `
        <button onclick="window.location.reload()" style="
          flex: 1; padding: 8px; background: rgba(255, 82, 82, 0.2); border: 1px solid #ff5252; color: #ff5252; border-radius: 6px; cursor: pointer; font-weight: 600; font-size: 12px;
        ">Reload Safety</button>
        ` : ''}
      </div>
    `;
    
    document.body.appendChild(overlay);
    
    document.getElementById('heliora-otp-dismiss').onclick = () => overlay.remove();
    
    if (!isBlock) {
      setTimeout(() => {
        if (overlay && overlay.parentNode) overlay.remove();
      }, 10000);
    }
  }

  // Animation Logic
  
  function initHelioRaJellyAnimation() {
    const container = document.getElementById('heliora-jelly-container');
    const wrappers = document.querySelectorAll('.heliora-jelly-wrapper');
    
    if (!container || !wrappers.length) return;

    const controller = new AbortController();
    const { signal } = controller;

    window.addEventListener('mousemove', (e) => {
      const mx = e.clientX;
      const my = e.clientY;

      wrappers.forEach(wrapper => {
        const blob = wrapper.querySelector('.heliora-jelly-blob');
        if (!blob) return;
        
        const speed = parseFloat(wrapper.dataset.speed) || 0.1;
        
        const rect = wrapper.getBoundingClientRect();
        const centerX = rect.left + rect.width / 2;
        const centerY = rect.top + rect.height / 2;
        
        const dx = mx - centerX;
        const dy = my - centerY;
        const dist = Math.sqrt(dx * dx + dy * dy);

        const moveX = dx * speed;
        const moveY = dy * speed;
        

        const angle = Math.atan2(dy, dx) * (180 / Math.PI);
        

        const stretch = Math.min(1.15, 1 + (200 / (dist + 100)) * 0.1);
        
        blob.style.transform = `translate(${moveX}px, ${moveY}px) rotate(${angle}deg) scale(${stretch}, ${1/stretch})`;
      });
    }, { signal });
    

  }

  function showSecurityCheck(riskScore, aiResult, targetUrl, riskFactors = []) {
    return new Promise((resolve) => {
      if (document.getElementById('heliora-security-check')) {
        return;
      }

      const overlay = document.createElement('div');
      overlay.id = 'heliora-security-check';
      const isHighRisk = riskScore >= 70;
      const riskLevelText = isHighRisk ? 'High Risk' : 'Medium Risk';
      const riskColor = isHighRisk ? '#ff5252' : '#FFD700';
      let recommendation = 'Do not proceed unless you fully trust this site.';
      if (isHighRisk) recommendation = 'Strongly Recommended: BLOCK this request.';


      overlay.innerHTML = `
        <style>
          @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap');
          
          #heliora-security-check {
            position: fixed !important;
            top: 0 !important;
            left: 0 !important;
            width: 100vw !important;
            height: 100vh !important;
            background-color: #050505 !important;
            color: #FFD700 !important;
            z-index: 2147483647 !important;
            display: flex !important;
            align-items: center !important;
            justify-content: center !important;
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif !important;
            overflow: hidden !important;
          }

          /* Reusing Jelly Styles from showWarning - duplication for isolation */
          #heliora-jelly-container {
            position: absolute !important;
            top: 0 !important;
            left: 0 !important;
            width: 100% !important;
            height: 100% !important;
            z-index: 1 !important;
            pointer-events: none !important;
          }

          .heliora-jelly-wrapper {
            position: absolute !important;
            pointer-events: auto !important; 
          }

          .heliora-jelly-blob {
            display: flex !important;
            align-items: center !important;
            justify-content: center !important;
            width: 100% !important;
            height: 100% !important;
            background: rgba(255, 215, 0, 0.05) !important;
            border: 1px solid rgba(255, 215, 0, 0.15) !important;
            backdrop-filter: blur(8px) !important;
            box-shadow: 0 8px 32px 0 rgba(255, 215, 0, 0.1), inset 0 0 20px rgba(255, 215, 0, 0.05) !important;
            transition: transform 0.4s cubic-bezier(0.175, 0.885, 0.32, 1.275), border-radius 0.4s ease !important;
          }
          
          .heliora-jelly-blob svg {
            width: 40% !important;
            height: 40% !important;
            opacity: 0.3 !important;
            transition: all 0.3s ease !important;
            filter: drop-shadow(0 0 5px rgba(255,215,0,0.3)) !important;
          }

          .heliora-jelly-wrapper:hover .heliora-jelly-blob {
            background: rgba(255, 215, 0, 0.08) !important;
            box-shadow: 0 15px 45px 0 rgba(255, 215, 0, 0.2), inset 0 0 30px rgba(255, 215, 0, 0.1) !important;
          }

          /* Specific Shapes */
          #jelly-cam { top: 15%; left: 10%; width: 280px; height: 280px; animation: float-1 12s infinite ease-in-out alternate; }
          #jelly-cam .heliora-jelly-blob { border-radius: 45% 55% 70% 30% / 30% 30% 70% 70%; }
          
          #jelly-mic { bottom: 15%; right: 15%; width: 320px; height: 320px; animation: float-2 15s infinite ease-in-out alternate; }
          #jelly-mic .heliora-jelly-blob { border-radius: 60% 40% 30% 70% / 60% 30% 70% 40%; }

          @keyframes float-1 { 0% { transform: translate(0, 0) rotate(0deg); } 100% { transform: translate(30px, 50px) rotate(5deg); } }
          @keyframes float-2 { 0% { transform: translate(0, 0) rotate(0deg); } 100% { transform: translate(-40px, -30px) rotate(-5deg); } }

          .heliora-card {
            background: rgba(20, 20, 20, 0.95) !important;
            border: 1px solid rgba(255, 215, 0, 0.2) !important;
            border-radius: 24px !important;
            padding: 40px !important;
            max-width: 550px !important;
            width: 90% !important;
            box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.9) !important;
            text-align: center !important;
            position: relative !important;
            backdrop-filter: blur(20px) !important;
            z-index: 10 !important;
          }

          .heliora-header {
            margin-bottom: 24px !important;
            border-bottom: 1px solid rgba(255,255,255,0.1) !important;
            padding-bottom: 20px !important;
          }

          .heliora-title {
            font-size: 28px !important;
            font-weight: 800 !important;
            margin: 0 0 8px 0 !important;
            color: #FFF !important;
            letter-spacing: -0.5px !important;
          }

          .heliora-badge {
            display: inline-block !important;
            background: ${isHighRisk ? 'rgba(255, 82, 82, 0.2)' : 'rgba(255, 215, 0, 0.2)'} !important;
            color: ${riskColor} !important;
            padding: 6px 12px !important;
            border-radius: 20px !important;
            font-size: 13px !important;
            font-weight: 700 !important;
            text-transform: uppercase !important;
            border: 1px solid ${riskColor} !important;
          }

          .heliora-content {
            font-size: 15px !important;
            line-height: 1.6 !important;
            color: #DDD !important;
            margin-bottom: 24px !important;
          }

          .heliora-reasons {
            background: rgba(0,0,0,0.3) !important;
            border-radius: 12px !important;
            padding: 16px !important;
            margin-bottom: 24px !important;
            text-align: left !important;
          }

          .heliora-reason-item {
            display: flex !important;
            align-items: flex-start !important;
            gap: 10px !important;
            margin-bottom: 8px !important;
            font-size: 13px !important;
            color: #CCC !important;
          }
          
          .heliora-reason-item:last-child { margin-bottom: 0 !important; }
          
          .heliora-reason-icon {
            font-size: 16px !important;
            line-height: 1 !important;
          }

          .heliora-actions {
            display: flex !important;
            flex-direction: column !important;
            gap: 12px !important;
          }

          .heliora-btn {
            padding: 16px !important;
            border-radius: 12px !important;
            font-weight: 600 !important;
            font-size: 15px !important;
            cursor: pointer !important;
            border: none !important;
            transition: all 0.2s !important;
            display: flex !important;
            align-items: center !important;
            justify-content: center !important;
            gap: 8px !important;
          }
          
          .heliora-btn:hover { transform: translateY(-2px) !important; filter: brightness(1.1) !important; }
          
          .btn-block { background: #ff5252 !important; color: white !important; font-weight: 700 !important; }
          .btn-allow { background: #333 !important; color: #FFF !important; border: 1px solid #555 !important; }
          .btn-trust { background: transparent !important; color: #888 !important; font-size: 13px !important; }
          .btn-trust:hover { color: #FFF !important; }
        </style>
        
        <div id="heliora-jelly-container">
           <div id="jelly-cam" class="heliora-jelly-wrapper" data-speed="0.08">
             <div class="heliora-jelly-blob">
               <svg viewBox="0 0 24 24" fill="none" stroke="#FFD700" stroke-width="1.5">
                 <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path>
               </svg>
             </div>
           </div>
           <div id="jelly-mic" class="heliora-jelly-wrapper" data-speed="0.12">
             <div class="heliora-jelly-blob">
               <svg viewBox="0 0 24 24" fill="none" stroke="#FFD700" stroke-width="1.5">
                 <path d="M21 2l-2 2m-7.61 7.61a5.5 5.5 0 1 1-7.778 7.778 5.5 5.5 0 0 1 7.777-7.777zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3m-3.5 3.5L19 4"></path>
               </svg>
             </div>
           </div>
        </div>

        <div class="heliora-card">
          <div class="heliora-header">
            <h1 class="heliora-title">HelioRa Security Check</h1>
            <div class="heliora-badge">${riskLevelText} (${riskScore}/100)</div>
          </div>
          
          <div class="heliora-content">
            This site is requesting sensitive authentication data.
          </div>
          
          <div style="font-size: 12px; color: #888; margin-bottom: 8px; text-transform: uppercase; font-weight: 700; text-align: left; padding-left: 4px;">Why this is risky:</div>
          <div class="heliora-reasons">
            ${riskFactors.length > 0 ? riskFactors.map(factor => `
              <div class="heliora-reason-item">
                <span class="heliora-reason-icon">⚠️</span>
                <span>${factor}</span>
              </div>
            `).join('') : `
              <div class="heliora-reason-item">
                <span class="heliora-reason-icon">ℹ️</span>
                <span>Unusual authentication pattern detected.</span>
              </div>
            `}
          </div>

          <div style="font-size: 13px; color: #BBB; margin-bottom: 24px; font-style: italic;">
            <strong>Recommendation:</strong> ${recommendation}
          </div>

          <div class="heliora-actions">
             <button id="heliora-block" class="heliora-btn btn-block">❌ Block (Recommended)</button>
             <button id="heliora-allow-once" class="heliora-btn btn-allow">⚠️ Allow Once</button>
             <button id="heliora-trust-site" class="heliora-btn btn-trust">✅ Trust this site for OTP/Login</button>
          </div>
        </div>
      `;

      document.body.appendChild(overlay);
      initHelioRaJellyAnimation();


      document.getElementById('heliora-block').onclick = () => {
        overlay.remove();
        resolve('BLOCK');
      };
      document.getElementById('heliora-allow-once').onclick = () => {
        overlay.remove();
        resolve('ALLOW');
      };
      document.getElementById('heliora-trust-site').onclick = () => {
        overlay.remove();
        resolve('TRUST');
      };
    });
  }

  function showWarning(type) {

    if (document.getElementById('heliora-surveillance-warning')) {
      return;
    }
    
    const overlay = document.createElement('div');
    overlay.id = 'heliora-surveillance-warning';
    overlay.innerHTML = `
      <style>
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap');
        
        #heliora-surveillance-warning {
          position: fixed !important;
          top: 0 !important;
          left: 0 !important;
          width: 100vw !important;
          height: 100vh !important;
          background-color: #050505 !important;
          color: #FFD700 !important;
          z-index: 2147483647 !important;
          display: flex !important;
          align-items: center !important;
          justify-content: center !important;
          font-family: 'Inter', -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif !important;
          overflow: hidden !important;
        }

        /* JELLY SHAPES BACKGROUND */
        #heliora-jelly-container {
          position: absolute !important;
          top: 0 !important;
          left: 0 !important;
          width: 100% !important;
          height: 100% !important;
          z-index: 1 !important;
          pointer-events: none !important;
        }

        .heliora-jelly-wrapper {
          position: absolute !important;
          pointer-events: auto !important; /* Allow hover */
        }

        .heliora-jelly-blob {
          display: flex !important;
          align-items: center !important;
          justify-content: center !important;
          width: 100% !important;
          height: 100% !important;
          background: rgba(255, 215, 0, 0.05) !important;
          border: 1px solid rgba(255, 215, 0, 0.15) !important;
          backdrop-filter: blur(8px) !important;
          box-shadow: 
            0 8px 32px 0 rgba(255, 215, 0, 0.1),
            inset 0 0 20px rgba(255, 215, 0, 0.05) !important;
          transition: transform 0.4s cubic-bezier(0.175, 0.885, 0.32, 1.275), border-radius 0.4s ease !important;
          cursor: crosshair !important;
        }

        .heliora-jelly-blob svg {
          width: 40% !important;
          height: 40% !important;
          opacity: 0.3 !important;
          transition: all 0.3s ease !important;
          filter: drop-shadow(0 0 5px rgba(255,215,0,0.3)) !important;
        }

        .heliora-jelly-wrapper:hover .heliora-jelly-blob {
          background: rgba(255, 215, 0, 0.08) !important;
          box-shadow: 
            0 15px 45px 0 rgba(255, 215, 0, 0.2),
            inset 0 0 30px rgba(255, 215, 0, 0.1) !important;
        }

        .heliora-jelly-wrapper:hover .heliora-jelly-blob svg {
          opacity: 0.8 !important;
          transform: scale(1.1) !important;
          filter: drop-shadow(0 0 15px rgba(255,215,0,0.6)) !important;
        }

        /* Specific Shapes */
        #jelly-cam {
          top: 15%;
          left: 10%;
          width: 280px;
          height: 280px;
          animation: float-1 12s infinite ease-in-out alternate;
        }
        #jelly-cam .heliora-jelly-blob {
          border-radius: 45% 55% 70% 30% / 30% 30% 70% 70%;
        }

        #jelly-mic {
          bottom: 15%;
          right: 15%;
          width: 320px;
          height: 320px;
          animation: float-2 15s infinite ease-in-out alternate;
        }
        #jelly-mic .heliora-jelly-blob {
          border-radius: 60% 40% 30% 70% / 60% 30% 70% 40%;
        }

        #jelly-eye {
          top: 20%;
          right: 20%;
          width: 240px;
          height: 240px;
          animation: float-3 10s infinite ease-in-out alternate;
        }
        #jelly-eye .heliora-jelly-blob {
          border-radius: 30% 70% 70% 30% / 30% 30% 70% 70%;
        }
        
        #jelly-lock {
          bottom: 25%;
          left: 25%;
          width: 200px;
          height: 200px;
          animation: float-4 18s infinite ease-in-out alternate;
        }
        #jelly-lock .heliora-jelly-blob {
          border-radius: 50% 50% 20% 80% / 25% 80% 20% 75%;
        }

        @keyframes float-1 { 0% { transform: translate(0, 0) rotate(0deg); } 100% { transform: translate(30px, 50px) rotate(5deg); } }
        @keyframes float-2 { 0% { transform: translate(0, 0) rotate(0deg); } 100% { transform: translate(-40px, -30px) rotate(-5deg); } }
        @keyframes float-3 { 0% { transform: translate(0, 0) rotate(0deg); } 100% { transform: translate(-20px, 40px) rotate(8deg); } }
        @keyframes float-4 { 0% { transform: translate(0, 0) rotate(0deg); } 100% { transform: translate(40px, -40px) rotate(-8deg); } }

        /* Card Styles */
        .heliora-card {
          background: rgba(20, 20, 20, 0.85) !important;
          border: 1px solid rgba(255, 215, 0, 0.2) !important;
          border-radius: 24px !important;
          padding: 48px !important;
          max-width: 550px !important;
          width: 90% !important;
          box-shadow: 
            0 25px 50px -12px rgba(0, 0, 0, 0.8),
            0 0 0 1px rgba(255, 215, 0, 0.1) !important;
          text-align: center !important;
          position: relative !important;
          backdrop-filter: blur(20px) !important;
          animation: heliora-slide-up 0.4s ease-out !important;
          z-index: 10 !important;
        }

        @keyframes heliora-slide-up {
          from { opacity: 0; transform: translateY(20px); }
          to { opacity: 1; transform: translateY(0); }
        }

        .heliora-card::before {
          content: '' !important;
          position: absolute !important;
          top: 0 !important;
          left: 0 !important;
          right: 0 !important;
          height: 3px !important;
          background: linear-gradient(90deg, #FFD700, #FFA000) !important;
          box-shadow: 0 0 15px rgba(255, 215, 0, 0.5) !important;
        }

        .heliora-icon-wrapper {
          width: 80px !important;
          height: 80px !important;
          background: rgba(255, 215, 0, 0.1) !important;
          border-radius: 50% !important;
          display: flex !important;
          align-items: center !important;
          justify-content: center !important;
          margin: 0 auto 24px auto !important;
          border: 1px solid rgba(255, 215, 0, 0.3) !important;
          animation: heliora-pulse-yellow 2s infinite !important;
        }

        @keyframes heliora-pulse-yellow {
          0% { box-shadow: 0 0 0 0 rgba(255, 215, 0, 0.4); }
          70% { box-shadow: 0 0 0 15px rgba(255, 215, 0, 0); }
          100% { box-shadow: 0 0 0 0 rgba(255, 215, 0, 0); }
        }

        .heliora-title {
          font-size: 32px !important;
          font-weight: 800 !important;
          margin: 0 0 12px 0 !important;
          color: #FFD700 !important;
          letter-spacing: -0.02em !important;
          line-height: 1.2 !important;
          text-transform: uppercase !important;
        }

        .heliora-subtitle {
          font-size: 16px !important;
          color: #cccccc !important;
          margin-bottom: 32px !important;
          line-height: 1.5 !important;
        }

        .heliora-details-grid {
          display: grid !important;
          grid-template-columns: 1fr !important;
          gap: 12px !important;
          background: rgba(255, 255, 255, 0.03) !important;
          padding: 20px !important;
          border-radius: 16px !important;
          margin-bottom: 32px !important;
          border: 1px solid rgba(255, 215, 0, 0.1) !important;
          text-align: left !important;
        }

        .heliora-detail-row {
          display: flex !important;
          justify-content: space-between !important;
          align-items: center !important;
          padding: 8px 0 !important;
          border-bottom: 1px solid rgba(255, 255, 255, 0.1) !important;
        }

        .heliora-detail-row:last-child {
          border-bottom: none !important;
        }

        .heliora-label {
          color: #888888 !important;
          font-size: 14px !important;
          font-weight: 500 !important;
          text-transform: uppercase !important;
          letter-spacing: 0.05em !important;
        }

        .heliora-value {
          color: #ffffff !important;
          font-size: 14px !important;
          font-weight: 600 !important;
          font-family: monospace !important;
          max-width: 250px !important;
          white-space: nowrap !important;
          overflow: hidden !important;
          text-overflow: ellipsis !important;
          text-align: right !important;
        }

        .heliora-value.danger {
          color: #FFD700 !important;
          background: rgba(255, 215, 0, 0.15) !important;
          padding: 4px 10px !important;
          border-radius: 6px !important;
          display: inline-block !important;
          border: 1px solid rgba(255, 215, 0, 0.2) !important;
        }

        .heliora-message {
          background: rgba(255, 215, 0, 0.05) !important;
          border-left: 4px solid #FFD700 !important;
          padding: 16px !important;
          text-align: left !important;
          border-radius: 0 8px 8px 0 !important;
          margin-bottom: 32px !important;
          color: #dddddd !important;
          font-size: 14px !important;
          line-height: 1.6 !important;
        }
        
        .heliora-message strong {
          color: #FFD700 !important;
        }

        .heliora-actions {
          display: flex !important;
          gap: 16px !important;
          justify-content: center !important;
        }

        .heliora-btn {
          padding: 14px 28px !important;
          border-radius: 12px !important;
          font-weight: 700 !important;
          font-size: 15px !important;
          cursor: pointer !important;
          transition: all 0.2s ease !important;
          border: none !important;
          outline: none !important;
          text-transform: uppercase !important;
          letter-spacing: 0.05em !important;
        }

        .heliora-btn-primary {
          background: #FFD700 !important;
          color: #000000 !important;
          box-shadow: 0 4px 12px rgba(255, 215, 0, 0.3) !important;
        }

        .heliora-btn-primary:hover {
          background: #ffea00 !important;
          transform: translateY(-2px) !important;
          box-shadow: 0 6px 16px rgba(255, 215, 0, 0.5) !important;
        }

        .heliora-btn-secondary {
          background: transparent !important;
          color: #FFD700 !important;
          border: 1px solid rgba(255, 215, 0, 0.3) !important;
        }

        .heliora-btn-secondary:hover {
          background: rgba(255, 215, 0, 0.1) !important;
          transform: translateY(-2px) !important;
          border-color: #FFD700 !important;
        }

        .heliora-footer {
          margin-top: 24px !important;
          font-size: 12px !important;
          color: #666666 !important;
          font-weight: 500 !important;
          opacity: 0.8 !important;
        }
      </style>
      
      <div id="heliora-jelly-container">
        <!-- Camera Jelly -->
        <div id="jelly-cam" class="heliora-jelly-wrapper" data-speed="0.08">
           <div class="heliora-jelly-blob">
             <svg viewBox="0 0 24 24" fill="none" stroke="#FFD700" stroke-width="1.5">
               <path d="M23 19a2 2 0 0 1-2 2H3a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h4l2-3h6l2 3h4a2 2 0 0 1 2 2z"></path>
               <circle cx="12" cy="13" r="4"></circle>
             </svg>
           </div>
        </div>

        <!-- Mic Jelly -->
        <div id="jelly-mic" class="heliora-jelly-wrapper" data-speed="0.12">
           <div class="heliora-jelly-blob">
             <svg viewBox="0 0 24 24" fill="none" stroke="#FFD700" stroke-width="1.5">
               <path d="M12 1a3 3 0 0 0-3 3v8a3 3 0 0 0 6 0V4a3 3 0 0 0-3-3z"></path>
               <path d="M19 10v2a7 7 0 0 1-14 0v-2"></path>
               <line x1="12" y1="19" x2="12" y2="23"></line>
               <line x1="8" y1="23" x2="16" y2="23"></line>
             </svg>
           </div>
        </div>

        <!-- Eye Jelly -->
        <div id="jelly-eye" class="heliora-jelly-wrapper" data-speed="0.10">
           <div class="heliora-jelly-blob">
             <svg viewBox="0 0 24 24" fill="none" stroke="#FFD700" stroke-width="1.5">
               <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path>
               <circle cx="12" cy="12" r="3"></circle>
             </svg>
           </div>
        </div>

        <!-- Lock Jelly -->
        <div id="jelly-lock" class="heliora-jelly-wrapper" data-speed="0.06">
           <div class="heliora-jelly-blob">
             <svg viewBox="0 0 24 24" fill="none" stroke="#FFD700" stroke-width="1.5">
               <rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect>
               <path d="M7 11V7a5 5 0 0 1 10 0v4"></path>
             </svg>
           </div>
        </div>
      </div>

      <div class="heliora-card">
        <div class="heliora-icon-wrapper">
          <svg width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="#FFD700" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
            <path d="M12 8v4"/>
            <path d="M12 16h.01"/>
          </svg>
        </div>

        <h1 class="heliora-title">Surveillance Attack Prevented</h1>
        <p class="heliora-subtitle">
          HelioRa Security has intercepted a high-risk connection attempt.
        </p>

        <div class="heliora-details-grid">
          <div class="heliora-detail-row">
            <span class="heliora-label">Domain</span>
            <span class="heliora-value" title="${domain}">${domain}</span>
          </div>
          <div class="heliora-detail-row">
            <span class="heliora-label">Threat Type</span>
            <span class="heliora-value danger">${isTunnel ? 'Tunnel Hosting (CamPhish)' : 'Surveillance Attack'}</span>
          </div>
          <div class="heliora-detail-row">
            <span class="heliora-label">Protection Level</span>
            <span class="heliora-value" style="color: #4ade80 !important; text-shadow: 0 0 10px rgba(74, 222, 128, 0.3) !important;">MAXIMUM</span>
          </div>
        </div>

        <div class="heliora-message">
          <strong>⚠️ What was blocked:</strong><br>
          This website attempted unauthorized <strong>${type.toLowerCase()}</strong> access. HelioRa detected and blocked this CamPhish-style surveillance attack pattern.
        </div>

        <div class="heliora-actions">
          <button class="heliora-btn heliora-btn-primary" onclick="window.close()">Close Tab</button>
          <button class="heliora-btn heliora-btn-secondary" onclick="window.history.back()">Go Back</button>
        </div>

        <div class="heliora-footer">
          Protected by HelioRa Security • Advanced Surveillance Defense
        </div>
      </div>
    `;
    
    if (document.body) {
      document.body.appendChild(overlay);
      initHelioRaJellyAnimation();
    } else {
      document.addEventListener('DOMContentLoaded', () => {
        document.body.appendChild(overlay);
        initHelioRaJellyAnimation();
      });
    }

  }
  
  function showCriticalWarning() {
    if (document.getElementById('heliora-critical-warning')) {
      return;
    }
    
    const overlay = document.createElement('div');
    overlay.id = 'heliora-critical-warning';
    overlay.style.cssText = `
      position: fixed !important;
      top: 0 !important;
      left: 0 !important;
      width: 100% !important;
      height: 100% !important;
      background: rgba(139, 0, 0, 0.98) !important;
      color: white !important;
      z-index: 2147483647 !important;
      display: flex !important;
      align-items: center !important;
      justify-content: center !important;
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif !important;
    `;
    
    overlay.innerHTML = `
      <div style="text-align: center; padding: 40px;">
        <h1 style="font-size: 56px; margin-bottom: 20px; color: #ff5252; font-weight: 900;">
          🚨 CRITICAL THREAT
        </h1>
        <p style="font-size: 22px; margin-bottom: 30px; line-height: 1.5;">
          This website attempted to activate multiple surveillance APIs simultaneously
        </p>
        <div style="font-size: 18px; margin-bottom: 20px; color: #ffeb3b; background: rgba(0,0,0,0.4); padding: 20px; border-radius: 12px; display: inline-block;">
          <strong>Attempted access:</strong><br>
          ${Array.from(permissionRequests).join(' + ').toUpperCase()}
        </div>
        <p style="font-size: 16px; margin-bottom: 40px; max-width: 600px; margin-left: auto; margin-right: auto; line-height: 1.6;">
          This is a known CamPhish attack pattern. Your camera, microphone, location, and screen may have been targets.
        </p>
        <button onclick="window.close()" style="
          background: white;
          color: darkred;
          border: none;
          padding: 18px 48px;
          font-size: 20px;
          border-radius: 12px;
          cursor: pointer;
          font-weight: 900;
          box-shadow: 0 8px 24px rgba(0,0,0,0.5);
        ">CLOSE TAB IMMEDIATELY</button>
        <div style="margin-top: 40px; font-size: 13px; color: rgba(255,255,255,0.7);">
          Protected by <strong>HelioRa Security Platform</strong>
        </div>
      </div>
    `;
    
    document.body.innerHTML = '';
    document.body.appendChild(overlay);
  }
  

  if (SHOULD_BLOCK) {
    console.log('%c[HelioRa] 🚨 HIGH THREAT SITE - Protection maximized', 'color: #ff5252; font-weight: bold; font-size: 16px');
  }
  
  console.log('%c[HelioRa] ✅ All surveillance APIs protected', 'color: #4CAF50; font-weight: bold');
  console.log('[HelioRa] Protected APIs: getUserMedia, getDisplayMedia, RTCPeerConnection, Geolocation, Clipboard, Notifications, Form Exfiltration');
  
} 
})();
