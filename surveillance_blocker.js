'use strict';

console.log('[HelioRa Surveillance Blocker] Initializing real-time defense system...');

// Track permission requests for forensics
const permissionLog = [];

// Detect CamPhish-style attack patterns
const ATTACK_PATTERNS = {
  // Fake page templates used by CamPhish
  fakeLivePages: [
    'festival', 'wish', 'greeting', 'celebration',
    'youtube.*live', 'live.*stream', 'watch.*live',
    'meeting', 'zoom', 'webinar', 'conference',
    'video.*call', 'chat.*room'
  ],
  
  // Tunnel hosting services (ngrok, cloudflare tunnel, serveo, etc.)
  tunnelDomains: [
    'ngrok.io', 'ngrok-free.app', 'loca.lt', 'localhost.run',
    'trycloudflare.com', '*.trycloudflare.com',
    'serveo.net', 'pagekite.me', 'tunnelto.dev',
    'localtunnel.me', 'tunnel.pyjam.as',
    'thingproxy.freeboard.io', 'burpcollaborator.net'
  ],
  
  // Suspicious URL patterns
  suspiciousPatterns: [
    /camera|webcam|cam-/i,
    /photo|selfie|picture/i,
    /live.*meeting|meeting.*live/i,
    /verify.*identity|identity.*verify/i,
    /security.*check|check.*security/i,
    /enable.*camera|camera.*enable/i,
    /grant.*access|access.*grant/i
  ],
  
  // Dangerous permission combinations (surveillance attack signature)
  dangerousCombo: ['camera', 'geolocation', 'notifications', 'fullscreen']
};

// Global privacy lockdown state
let privacyLockdown = false;

// Trusted domains (won't block permissions)
const TRUSTED_DOMAINS = [
  'meet.google.com', 'zoom.us', 'teams.microsoft.com',
  'discord.com', 'slack.com', 'webex.com',
  'whereby.com', 'jitsi.org'
];

// Check if domain is trusted
function isTrustedDomain(domain) {
  return TRUSTED_DOMAINS.some(trusted => domain.includes(trusted));
}

// Check if domain is a tunnel service
function isTunnelDomain(domain) {
  return ATTACK_PATTERNS.tunnelDomains.some(tunnel => {
    if (tunnel.startsWith('*.')) {
      const base = tunnel.substring(2);
      return domain.endsWith(base);
    }
    return domain.includes(tunnel);
  });
}

// Check for fake live page patterns
function isFakeLivePage() {
  const url = window.location.href.toLowerCase();
  const title = document.title.toLowerCase();
  const bodyText = document.body.innerText.toLowerCase();
  
  return ATTACK_PATTERNS.fakeLivePages.some(pattern => {
    const regex = new RegExp(pattern, 'i');
    return regex.test(url) || regex.test(title) || regex.test(bodyText);
  });
}

// Check for suspicious URL patterns
function hasSuspiciousPattern() {
  const url = window.location.href;
  return ATTACK_PATTERNS.suspiciousPatterns.some(pattern => pattern.test(url));
}

// Detect redirect chains (phishing trap indicator)
function detectRedirectChain() {
  const referrer = document.referrer;
  const currentUrl = window.location.href;
  
  if (referrer && new URL(referrer).hostname !== window.location.hostname) {
    console.log('[HelioRa Surveillance] Redirect detected:', referrer, '->', currentUrl);
    return true;
  }
  return false;
}

// Calculate threat score
function calculateThreatScore() {
  let score = 0;
  const domain = window.location.hostname;
  
  // Tunnel domain = HIGH RISK
  if (isTunnelDomain(domain)) {
    score += 70;
    console.log('[HelioRa Surveillance] THREAT: Tunnel domain detected');
  }
  
  // Fake live page = HIGH RISK
  if (isFakeLivePage()) {
    score += 60;
    console.log('[HelioRa Surveillance] THREAT: Fake live page pattern detected');
  }
  
  // Suspicious URL pattern
  if (hasSuspiciousPattern()) {
    score += 40;
    console.log('[HelioRa Surveillance] THREAT: Suspicious URL pattern');
  }
  
  // Redirect chain = MEDIUM RISK
  if (detectRedirectChain()) {
    score += 30;
    console.log('[HelioRa Surveillance] THREAT: Redirect chain detected');
  }
  
  // New/unknown domain (not in history)
  const domainAge = sessionStorage.getItem('domain_first_visit_' + domain);
  if (!domainAge) {
    score += 20;
    sessionStorage.setItem('domain_first_visit_' + domain, Date.now());
    console.log('[HelioRa Surveillance] THREAT: New/unknown domain');
  }
  
  return Math.min(score, 100);
}

// Override navigator.mediaDevices.getUserMedia (camera/mic access)
if (navigator.mediaDevices && navigator.mediaDevices.getUserMedia) {
  const originalGetUserMedia = navigator.mediaDevices.getUserMedia.bind(navigator.mediaDevices);
  
  navigator.mediaDevices.getUserMedia = async function(constraints) {
    const domain = window.location.hostname;
    const timestamp = new Date().toISOString();
    const threatScore = calculateThreatScore();
    
    console.log('[HelioRa Surveillance] Camera/Mic access requested by:', domain);
    console.log('[HelioRa Surveillance] Constraints:', constraints);
    console.log('[HelioRa Surveillance] Threat Score:', threatScore);
    
    // Log for forensics
    const logEntry = {
      type: 'getUserMedia',
      domain: domain,
      url: window.location.href,
      timestamp: timestamp,
      constraints: constraints,
      threatScore: threatScore,
      referrer: document.referrer,
      blocked: false
    };
    
    // Check if should block
    let shouldBlock = false;
    let blockReason = '';
    
    // Privacy lockdown mode - block everything
    if (privacyLockdown) {
      shouldBlock = true;
      blockReason = 'Privacy lockdown mode enabled';
    }
    // High threat score
    else if (threatScore >= 60) {
      shouldBlock = true;
      blockReason = 'High threat score: ' + threatScore;
    }
    // Untrusted domain
    else if (!isTrustedDomain(domain)) {
      shouldBlock = true;
      blockReason = 'Untrusted domain';
    }
    
    if (shouldBlock) {
      logEntry.blocked = true;
      logEntry.blockReason = blockReason;
      permissionLog.push(logEntry);
      
      // Send to background for logging
      chrome.runtime.sendMessage({
        action: 'logSurveillanceAttempt',
        data: logEntry
      });
      
      // Show warning
      showSurveillanceWarning(constraints, blockReason, threatScore);
      
      // Throw error to block access
      throw new DOMException('Permission denied by HelioRa Security', 'NotAllowedError');
    }
    
    // Allow but log
    logEntry.blocked = false;
    logEntry.blockReason = 'Trusted domain';
    permissionLog.push(logEntry);
    
    chrome.runtime.sendMessage({
      action: 'logSurveillanceAttempt',
      data: logEntry
    });
    
    return originalGetUserMedia(constraints);
  };
}

// Override navigator.geolocation.getCurrentPosition (GPS access)
if (navigator.geolocation) {
  const originalGetCurrentPosition = navigator.geolocation.getCurrentPosition.bind(navigator.geolocation);
  const originalWatchPosition = navigator.geolocation.watchPosition.bind(navigator.geolocation);
  
  navigator.geolocation.getCurrentPosition = function(success, error, options) {
    const domain = window.location.hostname;
    const timestamp = new Date().toISOString();
    const threatScore = calculateThreatScore();
    
    console.log('[HelioRa Surveillance] GPS location requested by:', domain);
    console.log('[HelioRa Surveillance] Threat Score:', threatScore);
    
    const logEntry = {
      type: 'geolocation',
      domain: domain,
      url: window.location.href,
      timestamp: timestamp,
      threatScore: threatScore,
      referrer: document.referrer,
      blocked: false
    };
    
    let shouldBlock = false;
    let blockReason = '';
    
    if (privacyLockdown) {
      shouldBlock = true;
      blockReason = 'Privacy lockdown mode enabled';
    } else if (threatScore >= 60) {
      shouldBlock = true;
      blockReason = 'High threat score: ' + threatScore;
    } else if (!isTrustedDomain(domain)) {
      shouldBlock = true;
      blockReason = 'Untrusted domain';
    }
    
    if (shouldBlock) {
      logEntry.blocked = true;
      logEntry.blockReason = blockReason;
      permissionLog.push(logEntry);
      
      chrome.runtime.sendMessage({
        action: 'logSurveillanceAttempt',
        data: logEntry
      });
      
      showSurveillanceWarning({ geolocation: true }, blockReason, threatScore);
      
      if (error) {
        error({ code: 1, message: 'User denied Geolocation' });
      }
      return;
    }
    
    logEntry.blocked = false;
    permissionLog.push(logEntry);
    
    chrome.runtime.sendMessage({
      action: 'logSurveillanceAttempt',
      data: logEntry
    });
    
    return originalGetCurrentPosition(success, error, options);
  };
  
  navigator.geolocation.watchPosition = function(success, error, options) {
    // Same logic as getCurrentPosition
    return navigator.geolocation.getCurrentPosition(success, error, options);
  };
}

// Override Notification.requestPermission (notification spam)
if (window.Notification) {
  const originalRequestPermission = Notification.requestPermission.bind(Notification);
  
  Notification.requestPermission = async function() {
    const domain = window.location.hostname;
    const threatScore = calculateThreatScore();
    
    console.log('[HelioRa Surveillance] Notification permission requested by:', domain);
    
    if (privacyLockdown || threatScore >= 60 || !isTrustedDomain(domain)) {
      console.log('[HelioRa Surveillance] BLOCKED notification permission');
      return 'denied';
    }
    
    return originalRequestPermission();
  };
}

// Detect dangerous permission combination requests
let requestedPermissions = new Set();

function trackPermissionRequest(type) {
  requestedPermissions.add(type);
  
  // Check if dangerous combo is being requested
  const hasDangerousCombo = ATTACK_PATTERNS.dangerousCombo.every(perm => 
    requestedPermissions.has(perm)
  );
  
  if (hasDangerousCombo) {
    console.error('[HelioRa Surveillance] CRITICAL: Dangerous permission combination detected!');
    console.error('[HelioRa Surveillance] Requested:', Array.from(requestedPermissions));
    
    showCriticalWarning();
    
    chrome.runtime.sendMessage({
      action: 'criticalSurveillanceThreat',
      data: {
        domain: window.location.hostname,
        url: window.location.href,
        permissions: Array.from(requestedPermissions),
        timestamp: new Date().toISOString()
      }
    });
  }
}

// Monitor fullscreen requests (used in combination with camera)
document.addEventListener('fullscreenchange', () => {
  if (document.fullscreenElement) {
    console.log('[HelioRa Surveillance] Fullscreen mode activated');
    trackPermissionRequest('fullscreen');
  }
});

// Show surveillance warning overlay
function showSurveillanceWarning(constraints, reason, threatScore) {
  const warning = document.createElement('div');
  warning.id = 'heliora-surveillance-warning';
  warning.style.cssText = `
    position: fixed;
    top: 50%;
    left: 50%;
    transform: translate(-50%, -50%);
    background: linear-gradient(135deg, #c62828 0%, #b71c1c 100%);
    color: white;
    padding: 30px;
    border-radius: 12px;
    box-shadow: 0 8px 32px rgba(0,0,0,0.5);
    z-index: 2147483647;
    max-width: 500px;
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
    border: 3px solid #ff5252;
  `;
  
  const requestType = constraints.video ? 'CAMERA' : constraints.audio ? 'MICROPHONE' : constraints.geolocation ? 'GPS LOCATION' : 'PERMISSIONS';
  
  warning.innerHTML = `
    <div style="text-align: center;">
      <svg width="60" height="60" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2">
        <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/>
        <line x1="12" y1="9" x2="12" y2="13"/>
        <line x1="12" y1="17" x2="12.01" y2="17"/>
      </svg>
      <h2 style="margin: 15px 0 10px 0; font-size: 22px; font-weight: bold;">
        SURVEILLANCE ATTACK BLOCKED
      </h2>
      <div style="background: rgba(0,0,0,0.3); padding: 15px; border-radius: 8px; margin: 15px 0;">
        <div style="font-size: 14px; margin-bottom: 8px; opacity: 0.9;">Request Type:</div>
        <div style="font-size: 18px; font-weight: bold; color: #ffeb3b;">${requestType} ACCESS</div>
      </div>
      <div style="text-align: left; margin: 15px 0; font-size: 14px; line-height: 1.6;">
        <div style="margin-bottom: 10px;">
          <strong>Domain:</strong> ${window.location.hostname}
        </div>
        <div style="margin-bottom: 10px;">
          <strong>Threat Score:</strong> ${threatScore}/100
        </div>
        <div style="margin-bottom: 10px;">
          <strong>Block Reason:</strong> ${reason}
        </div>
      </div>
      <div style="background: rgba(255,255,255,0.1); padding: 12px; border-radius: 6px; margin: 15px 0; font-size: 13px; line-height: 1.5;">
        <strong>Protected by HelioRa Security</strong><br>
        This site attempted to access your ${requestType.toLowerCase()} without authorization. 
        CamPhish-style surveillance attack prevented.
      </div>
      <button id="heliora-close-warning" style="
        background: white;
        color: #c62828;
        border: none;
        padding: 12px 30px;
        border-radius: 6px;
        font-size: 16px;
        font-weight: bold;
        cursor: pointer;
        margin-top: 10px;
      ">Close & Go Back</button>
    </div>
  `;
  
  document.body.appendChild(warning);
  
  document.getElementById('heliora-close-warning').addEventListener('click', () => {
    warning.remove();
    window.history.back();
  });
}

// Show critical warning for dangerous permission combinations
function showCriticalWarning() {
  const warning = document.createElement('div');
  warning.style.cssText = `
    position: fixed;
    top: 0;
    left: 0;
    width: 100%;
    height: 100%;
    background: rgba(139, 0, 0, 0.98);
    color: white;
    z-index: 2147483647;
    display: flex;
    align-items: center;
    justify-content: center;
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
  `;
  
  warning.innerHTML = `
    <div style="text-align: center; padding: 40px;">
      <h1 style="font-size: 48px; margin-bottom: 20px; color: #ff5252;">
        CRITICAL SURVEILLANCE THREAT
      </h1>
      <p style="font-size: 20px; margin-bottom: 30px;">
        This website is attempting to activate multiple surveillance permissions simultaneously.
      </p>
      <p style="font-size: 18px; margin-bottom: 20px; color: #ffeb3b;">
        Requested: Camera + GPS + Fullscreen + Notifications
      </p>
      <p style="font-size: 16px; margin-bottom: 30px;">
        This is a known attack pattern used by CamPhish and similar surveillance tools.
      </p>
      <button onclick="window.close()" style="
        background: white;
        color: darkred;
        border: none;
        padding: 15px 40px;
        font-size: 18px;
        border-radius: 8px;
        cursor: pointer;
        font-weight: bold;
      ">CLOSE TAB IMMEDIATELY</button>
    </div>
  `;
  
  document.body.innerHTML = '';
  document.body.appendChild(warning);
}

// Listen for privacy lockdown toggle
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === 'setPrivacyLockdown') {
    privacyLockdown = request.enabled;
    console.log('[HelioRa Surveillance] Privacy lockdown:', privacyLockdown ? 'ENABLED' : 'DISABLED');
    sendResponse({ success: true });
  }
});

// Initial threat assessment
const initialThreatScore = calculateThreatScore();
if (initialThreatScore >= 70) {
  console.error('[HelioRa Surveillance] HIGH THREAT SITE DETECTED');
  chrome.runtime.sendMessage({
    action: 'highThreatSite',
    data: {
      domain: window.location.hostname,
      url: window.location.href,
      threatScore: initialThreatScore,
      timestamp: new Date().toISOString()
    }
  });
}

console.log('[HelioRa Surveillance Blocker] Active - Protection enabled');
