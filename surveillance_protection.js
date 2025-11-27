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
        #heliora-block-overlay {
          position: fixed !important;
          top: 0 !important;
          left: 0 !important;
          width: 100vw !important;
          height: 100vh !important;
          background: linear-gradient(135deg, #c62828 0%, #8b0000 100%) !important;
          color: white !important;
          z-index: 2147483647 !important;
          display: flex !important;
          align-items: center !important;
          justify-content: center !important;
          font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif !important;
        }
        #heliora-block-content {
          text-align: center !important;
          padding: 60px !important;
          max-width: 700px !important;
        }
        #heliora-block-content h1 {
          font-size: 48px !important;
          margin-bottom: 30px !important;
          color: white !important;
          text-shadow: 0 4px 8px rgba(0,0,0,0.3) !important;
        }
        .heliora-warning-icon {
          font-size: 100px !important;
          margin-bottom: 20px !important;
          animation: heliora-pulse 2s infinite !important;
        }
        @keyframes heliora-pulse {
          0%, 100% { transform: scale(1); opacity: 1; }
          50% { transform: scale(1.1); opacity: 0.8; }
        }
        .heliora-info-box {
          background: rgba(0,0,0,0.4) !important;
          padding: 25px !important;
          border-radius: 15px !important;
          margin: 30px 0 !important;
          border: 2px solid rgba(255,255,255,0.3) !important;
        }
        .heliora-btn {
          background: white !important;
          color: #c62828 !important;
          border: none !important;
          padding: 18px 50px !important;
          font-size: 20px !important;
          font-weight: bold !important;
          border-radius: 10px !important;
          cursor: pointer !important;
          margin: 10px !important;
          box-shadow: 0 4px 12px rgba(0,0,0,0.3) !important;
          transition: transform 0.2s !important;
        }
        .heliora-btn:hover {
          transform: scale(1.05) !important;
        }
      </style>
      <div id="heliora-block-content">
        <div class="heliora-warning-icon">🛡️</div>
        <h1>SURVEILLANCE ATTACK BLOCKED</h1>
        <div class="heliora-info-box">
          <div style="font-size: 24px; margin-bottom: 15px; color: #ffeb3b;">
            ${type} ACCESS DENIED
          </div>
          <div style="font-size: 18px; margin: 10px 0;">
            <strong>Domain:</strong> ${domain}
          </div>
          <div style="font-size: 16px; opacity: 0.9; margin-top: 15px; line-height: 1.6;">
            This site attempted to access your camera, microphone, or location.<br>
            <strong>CamPhish-style surveillance attack detected and blocked.</strong>
          </div>
        </div>
        <div style="margin-top: 30px;">
          <button class="heliora-btn" onclick="window.close()">CLOSE TAB</button>
          <button class="heliora-btn" onclick="window.history.back()">GO BACK</button>
        </div>
        <div style="margin-top: 30px; font-size: 14px; opacity: 0.8;">
          Protected by HelioRa Security Platform
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
