// This runs in MAIN world context (page's actual JavaScript context)
// It MUST run before any page scripts to override APIs

(function() {
  'use strict';
  
  console.log('%c[HelioRa] Surveillance protection loaded', 'color: #4CAF50; font-weight: bold');
  
  // Threat detection
  const domain = window.location.hostname;
  const url = window.location.href.toLowerCase();
  
  const TUNNEL_PATTERNS = [
    'ngrok.io', 'ngrok-free.app', 'loca.lt', 'trycloudflare.com',
    'serveo.net', 'localhost.run', 'tunnelto.dev', 'localtunnel.me'
  ];
  
  const SUSPICIOUS_PATTERNS = [
    'festival', 'wish', 'greeting', 'live', 'meeting',
    'video-call', 'webcam', 'camera-test', 'mic-test'
  ];
  
  const isTunnel = TUNNEL_PATTERNS.some(p => domain.includes(p));
  const isSuspicious = SUSPICIOUS_PATTERNS.some(p => url.includes(p) || document.title.toLowerCase().includes(p));
  
  const SHOULD_BLOCK = isTunnel || isSuspicious;
  
  if (SHOULD_BLOCK) {
    console.log('%c[HelioRa] ⚠️ THREAT DETECTED - Blocking surveillance APIs', 'color: #ff5252; font-weight: bold; font-size: 14px');
    console.log('[HelioRa] Domain:', domain);
    console.log('[HelioRa] Is Tunnel:', isTunnel);
    console.log('[HelioRa] Is Suspicious:', isSuspicious);
  }
  
  // BLOCK getUserMedia (Camera/Microphone)
  const originalGetUserMedia = navigator.mediaDevices?.getUserMedia;
  if (originalGetUserMedia) {
    navigator.mediaDevices.getUserMedia = function(constraints) {
      console.log('%c[HelioRa] 📹 Camera/Mic requested', 'color: #ff9800; font-weight: bold');
      
      if (SHOULD_BLOCK) {
        console.log('%c[HelioRa] ❌ BLOCKED Camera/Mic', 'color: #f44336; font-weight: bold; font-size: 16px');
        
        setTimeout(() => showWarning('CAMERA & MICROPHONE'), 100);
        
        return Promise.reject(new DOMException(
          'Permission denied by HelioRa Security',
          'NotAllowedError'
        ));
      }
      
      return originalGetUserMedia.apply(this, arguments);
    };
  }
  
  // BLOCK Geolocation
  const originalGetPosition = navigator.geolocation?.getCurrentPosition;
  const originalWatchPosition = navigator.geolocation?.watchPosition;
  
  if (originalGetPosition) {
    navigator.geolocation.getCurrentPosition = function(success, error, options) {
      console.log('%c[HelioRa] 📍 GPS requested', 'color: #ff9800; font-weight: bold');
      
      if (SHOULD_BLOCK) {
        console.log('%c[HelioRa] ❌ BLOCKED GPS', 'color: #f44336; font-weight: bold; font-size: 16px');
        
        if (error) {
          error({
            code: 1,
            message: 'Location access denied by HelioRa',
            PERMISSION_DENIED: 1
          });
        }
        return;
      }
      
      return originalGetPosition.apply(this, arguments);
    };
  }
  
  if (originalWatchPosition) {
    navigator.geolocation.watchPosition = function(success, error, options) {
      console.log('%c[HelioRa] 📍 GPS watch requested', 'color: #ff9800; font-weight: bold');
      
      if (SHOULD_BLOCK) {
        console.log('%c[HelioRa] ❌ BLOCKED GPS watch', 'color: #f44336; font-weight: bold');
        
        if (error) {
          error({
            code: 1,
            message: 'Location access denied by HelioRa',
            PERMISSION_DENIED: 1
          });
        }
        return -1;
      }
      
      return originalWatchPosition.apply(this, arguments);
    };
  }
  
  // BLOCK Notifications
  const originalNotification = window.Notification?.requestPermission;
  if (originalNotification) {
    Notification.requestPermission = function() {
      console.log('%c[HelioRa] 🔔 Notification requested', 'color: #ff9800; font-weight: bold');
      
      if (SHOULD_BLOCK) {
        console.log('%c[HelioRa] ❌ BLOCKED Notification', 'color: #f44336; font-weight: bold');
        return Promise.resolve('denied');
      }
      
      return originalNotification.apply(this, arguments);
    };
  }
  
  // Show warning overlay
  function showWarning(type) {
    const overlay = document.createElement('div');
    overlay.id = 'heliora-block-overlay';
    overlay.innerHTML = `
      <style>
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700;800&display=swap');
        
        #heliora-block-overlay {
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
        
        #heliora-block-overlay::before {
          content: '' !important;
          position: absolute !important;
          width: 200% !important;
          height: 200% !important;
          background: radial-gradient(circle at 50% 50%, rgba(220, 38, 38, 0.15) 0%, transparent 50%) !important;
          animation: heliora-pulse-bg 4s ease-in-out infinite !important;
        }
        
        @keyframes heliora-pulse-bg {
          0%, 100% { transform: scale(1); opacity: 0.5; }
          50% { transform: scale(1.1); opacity: 0.8; }
        }
        
        #heliora-block-content {
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
        
        .heliora-shield-icon {
          width: 120px !important;
          height: 120px !important;
          margin: 0 auto 30px !important;
          position: relative !important;
          animation: heliora-shield-pulse 2s ease-in-out infinite !important;
        }
        
        @keyframes heliora-shield-pulse {
          0%, 100% { 
            transform: scale(1) rotate(0deg); 
            filter: drop-shadow(0 0 20px rgba(220, 38, 38, 0.6));
          }
          50% { 
            transform: scale(1.05) rotate(3deg); 
            filter: drop-shadow(0 0 30px rgba(220, 38, 38, 0.9));
          }
        }
        
        #heliora-block-content h1 {
          font-size: 42px !important;
          font-weight: 800 !important;
          margin-bottom: 15px !important;
          color: #ffffff !important;
          letter-spacing: -0.5px !important;
          line-height: 1.2 !important;
        }
        
        .heliora-subtitle {
          font-size: 16px !important;
          color: rgba(255, 255, 255, 0.6) !important;
          margin-bottom: 35px !important;
          font-weight: 400 !important;
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
          display: grid !important;
          grid-template-columns: 1fr !important;
          gap: 15px !important;
          margin: 30px 0 !important;
        }
        
        .heliora-info-card {
          background: rgba(255, 255, 255, 0.03) !important;
          padding: 20px !important;
          border-radius: 12px !important;
          border: 1px solid rgba(255, 255, 255, 0.08) !important;
          text-align: left !important;
          transition: all 0.3s ease !important;
        }
        
        .heliora-info-card:hover {
          background: rgba(255, 255, 255, 0.05) !important;
          border-color: rgba(220, 38, 38, 0.3) !important;
        }
        
        .heliora-info-label {
          font-size: 12px !important;
          color: rgba(255, 255, 255, 0.5) !important;
          text-transform: uppercase !important;
          letter-spacing: 1px !important;
          margin-bottom: 8px !important;
          font-weight: 600 !important;
        }
        
        .heliora-info-value {
          font-size: 16px !important;
          color: #ffffff !important;
          font-weight: 600 !important;
          word-break: break-all !important;
        }
        
        .heliora-threat-list {
          background: rgba(220, 38, 38, 0.1) !important;
          border: 1px solid rgba(220, 38, 38, 0.3) !important;
          padding: 20px !important;
          border-radius: 12px !important;
          margin: 25px 0 !important;
          text-align: left !important;
        }
        
        .heliora-threat-list-title {
          font-size: 14px !important;
          color: #fca5a5 !important;
          margin-bottom: 12px !important;
          font-weight: 700 !important;
          text-transform: uppercase !important;
          letter-spacing: 0.5px !important;
        }
        
        .heliora-threat-item {
          font-size: 14px !important;
          color: rgba(255, 255, 255, 0.85) !important;
          margin: 8px 0 !important;
          padding-left: 20px !important;
          position: relative !important;
          line-height: 1.6 !important;
        }
        
        .heliora-threat-item::before {
          content: '▸' !important;
          position: absolute !important;
          left: 0 !important;
          color: #dc2626 !important;
          font-weight: bold !important;
        }
        
        .heliora-button-group {
          display: flex !important;
          gap: 12px !important;
          justify-content: center !important;
          margin-top: 35px !important;
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
        
        .heliora-btn:active {
          transform: translateY(0) !important;
        }
        
        .heliora-btn-secondary {
          background: transparent !important;
          color: white !important;
          border: 2px solid rgba(255, 255, 255, 0.2) !important;
        }
        
        .heliora-btn-secondary:hover {
          background: rgba(255, 255, 255, 0.1) !important;
          border-color: rgba(255, 255, 255, 0.4) !important;
        }
        
        .heliora-footer {
          margin-top: 30px !important;
          padding-top: 25px !important;
          border-top: 1px solid rgba(255, 255, 255, 0.08) !important;
        }
        
        .heliora-footer-logo {
          font-size: 13px !important;
          color: rgba(255, 255, 255, 0.4) !important;
          font-weight: 600 !important;
        }
        
        .heliora-footer-tagline {
          font-size: 11px !important;
          color: rgba(255, 255, 255, 0.3) !important;
          margin-top: 5px !important;
        }
      </style>
      <div id="heliora-block-content">
        <div class="heliora-shield-icon">
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
        
        <p class="heliora-subtitle">
          HelioRa detected and blocked a CamPhish-style surveillance attempt
        </p>
        
        <div class="heliora-info-grid">
          <div class="heliora-info-card">
            <div class="heliora-info-label">Blocked Domain</div>
            <div class="heliora-info-value">${domain}</div>
          </div>
        </div>
        
        <div class="heliora-threat-list">
          <div class="heliora-threat-list-title">Detected Threats</div>
          <div class="heliora-threat-item">Attempted unauthorized camera access</div>
          <div class="heliora-threat-item">Attempted unauthorized microphone access</div>
          <div class="heliora-threat-item">Attempted unauthorized GPS location access</div>
          <div class="heliora-threat-item">Suspicious phishing template detected</div>
          <div class="heliora-threat-item">Temporary tunnel hosting identified (high risk)</div>
        </div>
        
        <div class="heliora-button-group">
          <button class="heliora-btn" onclick="window.close()">Close Tab</button>
          <button class="heliora-btn heliora-btn-secondary" onclick="window.history.back()">Go Back</button>
        </div>
        
        <div class="heliora-footer">
          <div class="heliora-footer-logo">HELIORA SECURITY</div>
          <div class="heliora-footer-tagline">Real-time surveillance protection platform</div>
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
  
  // Show immediate warning for high-threat sites
  if (SHOULD_BLOCK) {
    console.log('%c[HelioRa] 🚨 HIGH THREAT - Showing warning', 'color: #ff5252; font-weight: bold; font-size: 16px');
    
    // Slight delay to let page render
    setTimeout(() => {
      if (!document.getElementById('heliora-block-overlay')) {
        showWarning('SURVEILLANCE PROTECTION ACTIVE');
      }
    }, 1500);
  }
  
  console.log('%c[HelioRa] ✅ Protection active', 'color: #4CAF50; font-weight: bold');
})();
