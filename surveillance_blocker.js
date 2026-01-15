'use strict';

console.log('[HelioRa Surveillance Blocker] Initializing real-time defense system...');

// Track permission requests for forensics
const permissionLog = [];

// Detect CamPhish-style attack patterns
const ATTACK_PATTERNS = {
  fakeLivePages: [
    'festival', 'wish', 'greeting', 'celebration',
    'youtube.*live', 'live.*stream', 'watch.*live',
    'free.*gift', 'gift.*claim', 'reward.*claim',
    'verify.*account', 'secure.*account'
  ],

  tunnelDomains: [
    'ngrok.io', 'ngrok-free.app', 'loca.lt', 'localhost.run',
    'trycloudflare.com', '*.trycloudflare.com',
    'serveo.net', 'pagekite.me', 'tunnelto.dev',
    'localtunnel.me', 'tunnel.pyjam.as',
    'thingproxy.freeboard.io', 'burpcollaborator.net',
    'localhost', '127.0.0.1', '0.0.0.0'
  ],

  suspiciousPatterns: [
    /camera.*access|access.*camera/i,
    /enable.*webcam|webcam.*enable/i,
    /take.*photo|capture.*photo/i,
    /verify.*identity|identity.*verify/i,
    /secure.*login|login.*secure/i,
    /grant.*permission|permission.*grant/i
  ],

  dangerousCombo: ['camera', 'geolocation', 'notifications', 'fullscreen']
};

// Global privacy lockdown state
let privacyLockdown = false;

// Trusted domains that won't trigger blocks
const TRUSTED_DOMAINS = [
  'meet.google.com', 'zoom.us', 'teams.microsoft.com',
  'discord.com', 'slack.com', 'webex.com',
  'whereby.com', 'jitsi.org'
];

function isTrustedDomain(domain) {
  return TRUSTED_DOMAINS.some(trusted => domain.includes(trusted));
}

function isTunnelDomain(domain) {
  return ATTACK_PATTERNS.tunnelDomains.some(tunnel => {
    if (tunnel.startsWith('*.')) {
      const base = tunnel.substring(2);
      return domain.endsWith(base);
    }
    return domain.includes(tunnel);
  });
}

function isFakeLivePage() {
  const url = window.location.href.toLowerCase();
  const title = document.title.toLowerCase();
  const bodyText = document.body ? document.body.innerText.toLowerCase() : '';

  return ATTACK_PATTERNS.fakeLivePages.some(pattern => {
    const regex = new RegExp(pattern, 'i');
    return regex.test(url) || regex.test(title) || regex.test(bodyText);
  });
}

function hasSuspiciousPattern() {
  const url = window.location.href;
  return ATTACK_PATTERNS.suspiciousPatterns.some(pattern => pattern.test(url));
}

// Detect suspicious redirect chains
function detectRedirectChain() {
  const referrer = document.referrer;
  const currentUrl = window.location.href;

  if (referrer && new URL(referrer).hostname !== window.location.hostname) {
    console.log('[HelioRa Surveillance] Redirect detected:', referrer, '->', currentUrl);
    return true;
  }
  return false;
}

// Calculate comprehensive threat score based on domain and behavior
function calculateThreatScore() {
  let score = 0;
  const domain = window.location.hostname;

  if (isTunnelDomain(domain)) {
    score += 70;
    console.log('[HelioRa Surveillance] THREAT: Tunnel domain detected');
  }

  if (isFakeLivePage()) {
    score += 60;
    console.log('[HelioRa Surveillance] THREAT: Fake live page pattern detected');
  }

  if (hasSuspiciousPattern()) {
    score += 40;
    console.log('[HelioRa Surveillance] THREAT: Suspicious URL pattern');
  }

  if (detectRedirectChain()) {
    score += 30;
    console.log('[HelioRa Surveillance] THREAT: Redirect chain detected');
  }

  const domainAge = sessionStorage.getItem('domain_first_visit_' + domain);

  if (!domainAge && isTunnelDomain(domain)) {
    score += 20;
    sessionStorage.setItem('domain_first_visit_' + domain, Date.now());
    console.log('[HelioRa Surveillance] THREAT: New tunnel domain detected');
  }

  return Math.min(score, 100);
}

// Override navigator.mediaDevices.getUserMedia for surveillance protection
if (navigator.mediaDevices && navigator.mediaDevices.getUserMedia) {
  const originalGetUserMedia = navigator.mediaDevices.getUserMedia.bind(navigator.mediaDevices);

  navigator.mediaDevices.getUserMedia = async function (constraints) {
    const domain = window.location.hostname;
    const timestamp = new Date().toISOString();
    const threatScore = calculateThreatScore();

    console.log('[HelioRa Surveillance] Camera/Mic access requested by:', domain);
    console.log('[HelioRa Surveillance] Constraints:', constraints);
    console.log('[HelioRa Surveillance] Threat Score:', threatScore);

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

    let shouldBlock = false;
    let blockReason = '';

    if (privacyLockdown) {
      shouldBlock = true;
      blockReason = 'Privacy lockdown mode enabled';
    }
    else if (threatScore >= 60) {
      shouldBlock = true;
      blockReason = 'High threat score: ' + threatScore;
    }
    else if (!isTrustedDomain(domain) && threatScore >= 60) {
      shouldBlock = true;
      blockReason = 'Untrusted + High Threat';
    }

    if (shouldBlock) {
      logEntry.blocked = true;
      logEntry.blockReason = blockReason;
      permissionLog.push(logEntry);

      chrome.runtime.sendMessage({
        action: 'logSurveillanceAttempt',
        data: logEntry
      });

      showSurveillanceWarning(constraints, blockReason, threatScore);

      throw new DOMException('Permission denied by HelioRa Security', 'NotAllowedError');
    }

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

// Override navigator.geolocation.getCurrentPosition
if (navigator.geolocation) {
  const originalGetCurrentPosition = navigator.geolocation.getCurrentPosition.bind(navigator.geolocation);
  const originalWatchPosition = navigator.geolocation.watchPosition.bind(navigator.geolocation);

  navigator.geolocation.getCurrentPosition = function (success, error, options) {
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

  navigator.geolocation.watchPosition = function (success, error, options) {
    return navigator.geolocation.getCurrentPosition(success, error, options);
  };
}

// Override Notification.requestPermission
if (window.Notification) {
  const originalRequestPermission = Notification.requestPermission.bind(Notification);

  Notification.requestPermission = async function () {
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

// Monitor fullscreen requests
document.addEventListener('fullscreenchange', () => {
  if (document.fullscreenElement) {
    console.log('[HelioRa Surveillance] Fullscreen mode activated');
    trackPermissionRequest('fullscreen');
  }
});

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

// Show critical warning for dangerous permission combinations or high-threat sites
function showCriticalWarning(type = 'COMBO') {
  if (document.getElementById('heliora-critical-warning')) return;

  const overlay = document.createElement('div');
  overlay.id = 'heliora-critical-warning';
  
  let title = 'Surveillance Attack Prevented';
  let subtitle = 'HelioRa Security has intercepted a high-risk connection attempt.';
  let threatTypeLabel = 'Surveillance Attack';
  let messageContent = 'This website is attempting to activate multiple surveillance permissions simultaneously.';
  let subtext = 'Requested: Camera + GPS + Fullscreen + Notifications';
  
  if (type === 'TUNNEL') {
    title = 'CamPhish Tunnel Blocked';
    subtitle = 'HelioRa detected a known CamPhish hosting pattern.';
    threatTypeLabel = 'Tunnel Hosting (CamPhish)';
    messageContent = 'This website is hosted on a temporary tunneling service used by attackers.';
    subtext = 'Attackers use these ephemeral domains to bypass filters and steal camera/location data.';
  }

  const domain = window.location.hostname;

  overlay.innerHTML = `
    <style>
      @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap');
      
      #heliora-critical-warning {
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
        transition: transform 0.1s ease-out !important; 
      }

      .heliora-jelly-blob {
        width: 100% !important;
        height: 100% !important;
        background: rgba(255, 215, 0, 0.03) !important;
        border: 1px solid rgba(255, 215, 0, 0.15) !important;
        box-shadow: 0 0 30px rgba(255, 215, 0, 0.05) !important;
        backdrop-filter: blur(8px) !important;
        display: flex !important;
        align-items: center !important;
        justify-content: center !important;
        transition: all 0.3s ease !important;
        overflow: hidden !important;
      }
      
      .heliora-jelly-blob::after {
          content: '' !important;
          position: absolute !important;
          top: 0; left: 0; right: 0; bottom: 0;
          background: radial-gradient(circle at 30% 30%, rgba(255,255,255,0.1), transparent 60%) !important;
          border-radius: inherit !important;
          pointer-events: none !important;
      }

      .heliora-jelly-blob svg {
        width: 40% !important;
        height: 40% !important;
        opacity: 0.5 !important;
        transition: all 0.3s ease !important;
        filter: drop-shadow(0 0 10px rgba(255,215,0,0.3)) !important;
      }

      .heliora-jelly-wrapper:hover .heliora-jelly-blob {
          background: rgba(255, 215, 0, 0.08) !important;
          border-color: rgba(255, 215, 0, 0.4) !important;
          box-shadow: 
            0 0 50px rgba(255, 215, 0, 0.15),
            inset 0 0 30px rgba(255, 215, 0, 0.1) !important;
      }

      .heliora-jelly-wrapper:hover .heliora-jelly-blob svg {
        opacity: 0.8 !important;
        transform: scale(1.1) !important;
        filter: drop-shadow(0 0 15px rgba(255,215,0,0.6)) !important;
      }

      /* Specific Shapes */
      #jelly-cam {
        top: 15%; left: 10%; width: 280px; height: 280px;
        animation: float-1 12s infinite ease-in-out alternate;
      }
      #jelly-cam .heliora-jelly-blob { border-radius: 45% 55% 70% 30% / 30% 30% 70% 70%; }

      #jelly-mic {
        bottom: 15%; right: 15%; width: 320px; height: 320px;
        animation: float-2 15s infinite ease-in-out alternate;
      }
      #jelly-mic .heliora-jelly-blob { border-radius: 60% 40% 30% 70% / 60% 30% 70% 40%; }

      #jelly-eye {
        top: 20%; right: 20%; width: 240px; height: 240px;
        animation: float-3 10s infinite ease-in-out alternate;
      }
      #jelly-eye .heliora-jelly-blob { border-radius: 30% 70% 70% 30% / 30% 30% 70% 70%; }
      
      #jelly-lock {
        bottom: 25%; left: 25%; width: 200px; height: 200px;
        animation: float-4 18s infinite ease-in-out alternate;
      }
      #jelly-lock .heliora-jelly-blob { border-radius: 50% 50% 20% 80% / 25% 80% 20% 75%; }

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
        top: 0 !important; left: 0 !important; right: 0 !important;
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
      .heliora-detail-row:last-child { border-bottom: none !important; }

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
      
      .heliora-message strong { color: #FFD700 !important; }

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

      <h1 class="heliora-title">${title}</h1>
      <p class="heliora-subtitle">${subtitle}</p>

      <div class="heliora-details-grid">
        <div class="heliora-detail-row">
          <span class="heliora-label">Domain</span>
          <span class="heliora-value" title="${domain}">${domain}</span>
        </div>
        <div class="heliora-detail-row">
          <span class="heliora-label">Threat Type</span>
          <span class="heliora-value danger">${threatTypeLabel}</span>
        </div>
        <div class="heliora-detail-row">
          <span class="heliora-label">Protection Level</span>
          <span class="heliora-value" style="color: #4ade80 !important; text-shadow: 0 0 10px rgba(74, 222, 128, 0.3) !important;">MAXIMUM</span>
        </div>
      </div>

      <div class="heliora-message">
        <strong>⚠️ What was blocked:</strong><br>
        ${messageContent}<br>
        <span style="font-size: 13px; color: #aaa; margin-top: 5px; display: block;">${subtext}</span>
      </div>

      <div class="heliora-actions">
        <button id="heliora_kill_tab" class="heliora-btn heliora-btn-primary">CLOSE TAB</button>
        <button id="heliora_back_btn" class="heliora-btn heliora-btn-secondary">GO BACK</button>
      </div>

      <div class="heliora-footer">
        Protected by HelioRa Security • Advanced Surveillance Defense
      </div>
    </div>
  `;

  document.body.innerHTML = '';
  document.body.appendChild(overlay);
  
  initHelioRaJellyAnimation();
  
  document.getElementById('heliora_kill_tab').addEventListener('click', () => {
      window.close();
      window.location.href = "about:blank";
  });
  
  document.getElementById('heliora_back_btn').addEventListener('click', () => {
      window.history.back();
  });
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
const initialDomain = window.location.hostname;

if (isTunnelDomain(initialDomain) || initialThreatScore >= 70) {
  console.error('[HelioRa Surveillance] HIGH THREAT SITE DETECTED');

  if (isTunnelDomain(initialDomain)) {
    console.log('[HelioRa Surveillance] 🚨 BLOCKING CAMPHISH TUNNEL IMMEDIATELY');
    showCriticalWarning('TUNNEL');
  }

  chrome.runtime.sendMessage({
    action: 'highThreatSite',
    data: {
      domain: initialDomain,
      url: window.location.href,
      threatScore: initialThreatScore,
      timestamp: new Date().toISOString()
    }
  });
}

console.log('[HelioRa Surveillance Blocker] Active - Protection enabled');
