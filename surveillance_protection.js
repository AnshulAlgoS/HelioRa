// HelioRa Advanced Surveillance Protection System
// Runs in MAIN world context (page's JavaScript environment)
// MUST execute before any page scripts to override APIs

(function() {
  'use strict';
  
  console.log('%c[HelioRa] Advanced Surveillance Protection Active', 'color: #4CAF50; font-weight: bold; font-size: 14px');
  
  // ==================== CONFIGURATION ====================
  
  const domain = window.location.hostname;
  const url = window.location.href.toLowerCase();
  
  // Trusted domains (won't block surveillance APIs)
  const TRUSTED_DOMAINS = [
    'meet.google.com', 'zoom.us', 'teams.microsoft.com',
    'discord.com', 'slack.com', 'webex.com',
    'whereby.com', 'jitsi.org', 'gather.town'
  ];
  
  // Tunnel/temporary hosting patterns (HIGH RISK - CamPhish indicators)
  const TUNNEL_PATTERNS = [
    'ngrok.io', 'ngrok-free.app', 'ngrok.app', 'loca.lt',
    'trycloudflare.com', '.trycloudflare.com',
    'serveo.net', 'localhost.run', 'tunnelto.dev',
    'localtunnel.me', 'pagekite.me', 'tunnel.pyjam.as',
    'cloudflare.app', 'ngrok.com'
  ];
  
  // Suspicious page patterns
  const SUSPICIOUS_PATTERNS = [
    'festival', 'wish', 'greeting', 'live', 'meeting',
    'video-call', 'webcam', 'camera-test', 'mic-test',
    'enable-camera', 'enable-mic', 'grant-access'
  ];
  
  // Check if domain is trusted
  const isTrusted = TRUSTED_DOMAINS.some(trusted => domain.includes(trusted));
  
  // Check if domain uses tunnel hosting
  const isTunnel = TUNNEL_PATTERNS.some(pattern => 
    domain.includes(pattern) || domain.endsWith(pattern)
  );
  
  // Check for suspicious content
  const isSuspicious = SUSPICIOUS_PATTERNS.some(pattern => 
    url.includes(pattern) || document.title.toLowerCase().includes(pattern)
  );
  
  // Determine if we should block surveillance APIs
  const SHOULD_BLOCK = (isTunnel || isSuspicious) && !isTrusted;
  
  // Track permission requests for multi-attack detection
  let permissionRequests = new Set();
  let blockCount = 0;
  
  if (SHOULD_BLOCK) {
    console.log('%c[HelioRa] ⚠️ THREAT DETECTED - Enabling strict protection', 'color: #ff5252; font-weight: bold; font-size: 14px');
    console.log('[HelioRa] Domain:', domain);
    console.log('[HelioRa] Tunnel hosting:', isTunnel);
    console.log('[HelioRa] Suspicious patterns:', isSuspicious);
  }
  
  // ==================== LOG FUNCTION ====================
  
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
  
  // ==================== 1. CAMERA & MICROPHONE PROTECTION ====================
  
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
  
  // ==================== 2. SCREEN CAPTURE PROTECTION ====================
  
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
  
  // Also block getDisplayMedia aliases
  if (navigator.getDisplayMedia) {
    navigator.getDisplayMedia = navigator.mediaDevices.getDisplayMedia;
  }
  
  // ==================== 3. WEBRTC IP LEAK PROTECTION ====================
  
  if (window.RTCPeerConnection) {
    const originalRTCPeerConnection = window.RTCPeerConnection;
    
    window.RTCPeerConnection = function(config) {
      console.log('[HelioRa] 🌐 RTCPeerConnection created', config);
      
      // Detect STUN servers (used for IP leak attacks)
      const stunServers = config?.iceServers?.filter(server => 
        server.urls?.some(url => url.includes('stun:'))
      ) || [];
      
      if (stunServers.length > 0) {
        console.log('[HelioRa] ⚠️ STUN servers detected:', stunServers);
      }
      
      // Check for suspicious peer connection usage
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
        
        // Block by throwing error
        throw new DOMException(
          'RTCPeerConnection blocked by HelioRa Security (potential IP leak)',
          'NotSupportedError'
        );
      }
      
      logAttempt('RTCPeerConnection', false, { config, stunServers: stunServers.length });
      return new originalRTCPeerConnection(config);
    };
    
    // Copy static properties
    Object.setPrototypeOf(window.RTCPeerConnection, originalRTCPeerConnection);
    Object.setPrototypeOf(window.RTCPeerConnection.prototype, originalRTCPeerConnection.prototype);
  }
  
  // ==================== 4. GPS LOCATION PROTECTION ====================
  
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
  
  // ==================== 5. CLIPBOARD ACCESS PROTECTION ====================
  
  if (navigator.clipboard) {
    // Block clipboard.readText() - prevents password stealing
    if (navigator.clipboard.readText) {
      const originalReadText = navigator.clipboard.readText.bind(navigator.clipboard);
      
      navigator.clipboard.readText = function() {
        console.log('[HelioRa] 📋 clipboard.readText() called');
        
        // Always warn about clipboard read attempts on login/payment forms
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
    
    // Block clipboard.read() - prevents stealing of rich content
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
  
  // ==================== 6. FORM EXFILTRATION DETECTION ====================
  
  // Hook XMLHttpRequest
  const originalXMLHttpRequest = window.XMLHttpRequest;
  const XHRInstances = new WeakMap();
  
  window.XMLHttpRequest = function() {
    const xhr = new originalXMLHttpRequest();
    XHRInstances.set(this, xhr);
    
    // Store original send method
    const originalSend = xhr.send.bind(xhr);
    
    xhr.send = function(body) {
      const url = xhr._url || '';
      
      // Check if sending sensitive form data
      const isSensitiveData = body && (
        body.includes('password') ||
        body.includes('email') ||
        body.includes('otp') ||
        body.includes('ssn') ||
        body.includes('card') ||
        body.includes('cvv')
      );
      
      if (isSensitiveData) {
        const targetDomain = new URL(url, window.location.href).hostname;
        const isThirdParty = targetDomain !== window.location.hostname;
        
        console.log('[HelioRa] ⚠️ Sensitive data in XHR request to:', targetDomain);
        
        if (isThirdParty && SHOULD_BLOCK) {
          logAttempt('xhr-exfiltration', true, {
            targetDomain,
            currentDomain: window.location.hostname,
            reason: 'Sensitive data sent to third-party domain'
          });
          
          alert(`⚠️ HelioRa Security Warning\n\nThis website is attempting to send your credentials to:\n${targetDomain}\n\nThis request has been BLOCKED.`);
          
          throw new Error('HelioRa Security: Blocked credential exfiltration attempt');
        }
        
        logAttempt('xhr-sensitive-data', false, {
          targetDomain,
          isThirdParty
        });
      }
      
      return originalSend(body);
    };
    
    // Intercept open to get URL
    const originalOpen = xhr.open.bind(xhr);
    xhr.open = function(method, url, ...args) {
      xhr._url = url;
      return originalOpen(method, url, ...args);
    };
    
    return xhr;
  };
  
  // Copy XMLHttpRequest properties
  window.XMLHttpRequest.prototype = originalXMLHttpRequest.prototype;
  
  // Hook fetch API
  if (window.fetch) {
    const originalFetch = window.fetch.bind(window);
    
    window.fetch = function(url, options = {}) {
      // Check if sending sensitive data
      const body = options.body;
      const isSensitiveData = body && (
        body.includes?.('password') ||
        body.includes?.('email') ||
        body.includes?.('otp') ||
        body.includes?.('ssn') ||
        body.includes?.('card') ||
        body.includes?.('cvv')
      );
      
      if (isSensitiveData) {
        const targetDomain = new URL(url, window.location.href).hostname;
        const isThirdParty = targetDomain !== window.location.hostname;
        
        console.log('[HelioRa] ⚠️ Sensitive data in fetch request to:', targetDomain);
        
        if (isThirdParty && SHOULD_BLOCK) {
          logAttempt('fetch-exfiltration', true, {
            targetDomain,
            currentDomain: window.location.hostname,
            method: options.method || 'GET',
            reason: 'Sensitive data sent to third-party domain'
          });
          
          alert(`⚠️ HelioRa Security Warning\n\nThis website is attempting to send your credentials to:\n${targetDomain}\n\nThis request has been BLOCKED.`);
          
          return Promise.reject(new Error('HelioRa Security: Blocked credential exfiltration attempt'));
        }
        
        logAttempt('fetch-sensitive-data', false, {
          targetDomain,
          isThirdParty
        });
      }
      
      return originalFetch(url, options);
    };
  }
  
  // ==================== 7. NOTIFICATION PERMISSION ====================
  
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
  
  // ==================== 8. FULLSCREEN DETECTION ====================
  
  document.addEventListener('fullscreenchange', function() {
    if (document.fullscreenElement) {
      console.log('[HelioRa] 📺 Fullscreen mode activated');
      
      permissionRequests.add('fullscreen');
      
      // Warn if fullscreen + other surveillance APIs
      if (permissionRequests.has('getUserMedia') || permissionRequests.has('getDisplayMedia')) {
        console.log('%c[HelioRa] ⚠️ WARNING: Fullscreen + Camera combination detected', 'color: #ff9800; font-weight: bold');
      }
    }
  });
  
  // ==================== UI: WARNING OVERLAY ====================
  
  function showWarning(type) {
    // Prevent duplicate warnings
    if (document.getElementById('heliora-surveillance-warning')) {
      return;
    }
    
    const overlay = document.createElement('div');
    overlay.id = 'heliora-surveillance-warning';
    overlay.innerHTML = `
      <style>
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700;800&display=swap');
        
        #heliora-surveillance-warning {
          position: fixed !important;
          top: 0 !important;
          left: 0 !important;
          width: 100vw !important;
          height: 100vh !important;
          background: #0a0a0a !important;
          color: white !important;
          z-index: 2147483647 !important;
          display: flex !important;
          align-items: center !important;
          justify-content: center !important;
          font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif !important;
          overflow: hidden !important;
        }
        
        #heliora-surveillance-warning::before {
          content: '' !important;
          position: absolute !important;
          width: 200% !important;
          height: 200% !important;
          background: radial-gradient(circle at 50% 50%, rgba(220, 38, 38, 0.15) 0%, transparent 50%) !important;
          animation: pulse-bg 4s ease-in-out infinite !important;
        }
        
        @keyframes pulse-bg {
          0%, 100% { transform: scale(1); opacity: 0.5; }
          50% { transform: scale(1.1); opacity: 0.8; }
        }
        
        .heliora-warning-content {
          position: relative !important;
          text-align: center !important;
          padding: 60px 40px !important;
          max-width: 700px !important;
          background: rgba(20, 20, 20, 0.95) !important;
          border-radius: 24px !important;
          border: 1px solid rgba(220, 38, 38, 0.3) !important;
          box-shadow: 0 20px 60px rgba(0, 0, 0, 0.8), 
                      0 0 0 1px rgba(255, 255, 255, 0.05) inset !important;
          backdrop-filter: blur(20px) !important;
        }
        
        .heliora-shield {
          width: 120px !important;
          height: 120px !important;
          margin: 0 auto 30px !important;
          animation: shield-pulse 2s ease-in-out infinite !important;
        }
        
        @keyframes shield-pulse {
          0%, 100% { 
            transform: scale(1) rotate(0deg); 
            filter: drop-shadow(0 0 20px rgba(220, 38, 38, 0.6));
          }
          50% { 
            transform: scale(1.05) rotate(3deg); 
            filter: drop-shadow(0 0 30px rgba(220, 38, 38, 0.9));
          }
        }
        
        .heliora-warning-content h1 {
          font-size: 42px !important;
          font-weight: 800 !important;
          margin-bottom: 15px !important;
          color: #ffffff !important;
          letter-spacing: -0.5px !important;
          line-height: 1.2 !important;
        }
        
        .heliora-threat-badge {
          display: inline-block !important;
          background: linear-gradient(135deg, #dc2626 0%, #991b1b 100%) !important;
          padding: 12px 24px !important;
          border-radius: 50px !important;
          font-size: 15px !important;
          font-weight: 700 !important;
          margin-bottom: 30px !important;
          letter-spacing: 0.5px !important;
          text-transform: uppercase !important;
          box-shadow: 0 4px 12px rgba(220, 38, 38, 0.4) !important;
        }
        
        .heliora-info-grid {
          background: rgba(255, 255, 255, 0.03) !important;
          padding: 20px !important;
          border-radius: 12px !important;
          border: 1px solid rgba(255, 255, 255, 0.08) !important;
          margin: 25px 0 !important;
          text-align: left !important;
        }
        
        .heliora-info-item {
          display: flex !important;
          justify-content: space-between !important;
          padding: 10px 0 !important;
          border-bottom: 1px solid rgba(255, 255, 255, 0.05) !important;
          font-size: 14px !important;
        }
        
        .heliora-info-item:last-child {
          border-bottom: none !important;
        }
        
        .heliora-info-label {
          color: rgba(255, 255, 255, 0.6) !important;
          font-weight: 600 !important;
        }
        
        .heliora-info-value {
          color: #ffffff !important;
          font-weight: 700 !important;
          word-break: break-all !important;
        }
        
        .heliora-warning-text {
          background: rgba(220, 38, 38, 0.1) !important;
          border: 1px solid rgba(220, 38, 38, 0.3) !important;
          padding: 20px !important;
          border-radius: 12px !important;
          margin: 25px 0 !important;
          font-size: 14px !important;
          line-height: 1.6 !important;
          color: rgba(255, 255, 255, 0.9) !important;
        }
        
        .heliora-button-group {
          display: flex !important;
          gap: 12px !important;
          justify-content: center !important;
          margin-top: 30px !important;
        }
        
        .heliora-btn {
          flex: 1 !important;
          max-width: 200px !important;
          background: white !important;
          color: #0a0a0a !important;
          border: none !important;
          padding: 16px 32px !important;
          font-size: 16px !important;
          font-weight: 700 !important;
          border-radius: 12px !important;
          cursor: pointer !important;
          box-shadow: 0 4px 12px rgba(0, 0, 0, 0.3) !important;
          transition: all 0.3s ease !important;
          text-transform: uppercase !important;
          letter-spacing: 0.5px !important;
        }
        
        .heliora-btn:hover {
          transform: translateY(-2px) !important;
          box-shadow: 0 6px 20px rgba(255, 255, 255, 0.3) !important;
        }
        
        .heliora-footer {
          margin-top: 25px !important;
          padding-top: 20px !important;
          border-top: 1px solid rgba(255, 255, 255, 0.08) !important;
          font-size: 12px !important;
          color: rgba(255, 255, 255, 0.4) !important;
        }
      </style>
      <div class="heliora-warning-content">
        <div class="heliora-shield">
          <svg width="120" height="120" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
            <path d="M12 2L4 6V11C4 16.55 7.84 21.74 12 23C16.16 21.74 20 16.55 20 11V6L12 2Z" 
                  fill="url(#shield-gradient)" stroke="white" stroke-width="1" stroke-linecap="round" stroke-linejoin="round"/>
            <path d="M9 12L11 14L15 10" stroke="white" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
            <defs>
              <linearGradient id="shield-gradient" x1="4" y1="2" x2="20" y2="23" gradientUnits="userSpaceOnUse">
                <stop offset="0%" stop-color="#dc2626"/>
                <stop offset="100%" stop-color="#991b1b"/>
              </linearGradient>
            </defs>
          </svg>
        </div>
        
        <div class="heliora-threat-badge">${type} BLOCKED</div>
        
        <h1>Surveillance Attack<br>Prevented</h1>
        
        <div class="heliora-info-grid">
          <div class="heliora-info-item">
            <span class="heliora-info-label">Domain:</span>
            <span class="heliora-info-value">${domain}</span>
          </div>
          <div class="heliora-info-item">
            <span class="heliora-info-label">Threat Type:</span>
            <span class="heliora-info-value">${isTunnel ? 'Tunnel Hosting (CamPhish)' : 'Surveillance Attack'}</span>
          </div>
          <div class="heliora-info-item">
            <span class="heliora-info-label">Protection Level:</span>
            <span class="heliora-info-value">MAXIMUM</span>
          </div>
        </div>
        
        <div class="heliora-warning-text">
          <strong>⚠️ What was blocked:</strong><br>
          This website attempted unauthorized ${type.toLowerCase()} access. HelioRa detected and blocked this CamPhish-style surveillance attack pattern.
        </div>
        
        <div class="heliora-button-group">
          <button class="heliora-btn" onclick="window.close()">Close Tab</button>
          <button class="heliora-btn" onclick="window.history.back()">Go Back</button>
        </div>
        
        <div class="heliora-footer">
          <strong>HELIORA SECURITY</strong> • Real-time surveillance protection
        </div>
      </div>
    `;
    
    if (document.body) {
      document.body.appendChild(overlay);
    } else {
      document.addEventListener('DOMContentLoaded', () => {
        document.body.appendChild(overlay);
      });
    }
  }
  
  function showCriticalWarning() {
    // Prevent duplicate warnings
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
  
  // ==================== FINAL SETUP ====================
  
  // Show immediate warning if high-risk site
  if (SHOULD_BLOCK) {
    console.log('%c[HelioRa] 🚨 HIGH THREAT SITE - Protection maximized', 'color: #ff5252; font-weight: bold; font-size: 16px');
  }
  
  console.log('%c[HelioRa] ✅ All surveillance APIs protected', 'color: #4CAF50; font-weight: bold');
  console.log('[HelioRa] Protected APIs: getUserMedia, getDisplayMedia, RTCPeerConnection, Geolocation, Clipboard, Notifications, Form Exfiltration');
  
})();
