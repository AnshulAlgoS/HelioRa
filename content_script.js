'use strict';

console.log('[HelioRa Content] Loaded on:', window.location.hostname);

class HelioRaContentScript {
  constructor() {
    this.domain = window.location.hostname.replace('www.', '');
    this.eventsSent = 0;
    this.maxEvents = 5; // Limit events per page
    this.init();
  }

  init() {
    // Wait for page to load
    if (document.readyState === 'loading') {
      document.addEventListener('DOMContentLoaded', () => this.analyze());
    } else {
      this.analyze();
    }

    // Inject PDF preview handler
    this.injectPDFHandler();
    
    // Inject phishing link protection
    this.injectPhishingProtection();
  }

  analyze() {
    setTimeout(() => {
      this.checkScripts();
      this.checkIframes();
      this.checkForms();
      this.checkLinks();
      this.monitorBehavior();
    }, 1000);
  }

  sendEvent(type, description, severity = 'low') {
    if (this.eventsSent >= this.maxEvents) return;

    const event = {
      time: new Date().toLocaleTimeString(),
      type,
      description,
      severity
    };

    chrome.runtime.sendMessage({
      action: 'addEvent',
      domain: this.domain,
      event
    }).catch(() => {});

    this.eventsSent++;
    console.log('[HelioRa Content] Event:', type, description);
  }

  checkScripts() {
    const scripts = document.querySelectorAll('script');
    const scriptCount = scripts.length;

    if (scriptCount > 50) {
      this.sendEvent(
        'excessive-scripts',
        `${scriptCount} scripts detected (potential risk)`,
        'medium'
      );
    }

    // Check for suspicious script content
    scripts.forEach(script => {
      const src = script.src || '';
      const content = script.textContent || '';

      // Crypto mining detection
      const miningKeywords = ['coinhive', 'cryptoloot', 'coin-hive', 'jsecoin', 'minero'];
      if (miningKeywords.some(kw => src.toLowerCase().includes(kw) || content.toLowerCase().includes(kw))) {
        this.sendEvent(
          'crypto-mining',
          'Crypto mining script detected',
          'critical'
        );
      }

      // Obfuscated code detection
      if (content.includes('eval(') || content.includes('atob(') || 
          (content.includes('String.fromCharCode') && content.length > 1000)) {
        this.sendEvent(
          'obfuscated-code',
          'Obfuscated JavaScript detected',
          'medium'
        );
      }
    });
  }

  checkIframes() {
    const iframes = document.querySelectorAll('iframe');
    
    if (iframes.length > 0) {
      let hiddenCount = 0;

      iframes.forEach(iframe => {
        const style = window.getComputedStyle(iframe);
        const width = parseInt(style.width);
        const height = parseInt(style.height);

        // Hidden iframe detection
        if (width <= 1 || height <= 1 || 
            style.display === 'none' || 
            style.visibility === 'hidden' ||
            style.opacity === '0') {
          hiddenCount++;
        }
      });

      if (hiddenCount > 0) {
        this.sendEvent(
          'hidden-iframes',
          `${hiddenCount} hidden iframe(s) detected`,
          'medium'
        );
      } else if (iframes.length > 3) {
        this.sendEvent(
          'multiple-iframes',
          `${iframes.length} iframes found`,
          'low'
        );
      }
    }
  }

  checkForms() {
    const forms = document.querySelectorAll('form');
    
    forms.forEach(form => {
      const action = form.action || '';
      const method = form.method || 'get';

      // Check for forms submitting to external domains
      if (action && !action.includes(this.domain) && action.startsWith('http')) {
        this.sendEvent(
          'external-form',
          'Form submits to external domain',
          'medium'
        );
      }

      // Check for password fields over HTTP
      if (window.location.protocol === 'http:' && form.querySelector('input[type="password"]')) {
        this.sendEvent(
          'insecure-password',
          'Password field on HTTP connection',
          'critical'
        );
      }
    });
  }

  checkLinks() {
    // Check for suspicious download links
    const links = document.querySelectorAll('a[href$=".exe"], a[href$=".scr"], a[href$=".bat"]');
    
    if (links.length > 0) {
      this.sendEvent(
        'executable-download',
        `${links.length} executable download link(s) found`,
        'medium'
      );
    }
  }

  monitorBehavior() {
    let xhrCount = 0;
    let redirectAttempts = 0;

    // Monitor XHR/Fetch requests
    const originalFetch = window.fetch;
    window.fetch = (...args) => {
      xhrCount++;
      if (xhrCount === 50) {
        this.sendEvent(
          'excessive-requests',
          'High volume of network requests detected',
          'medium'
        );
      }
      return originalFetch.apply(window, args);
    };

    const originalOpen = XMLHttpRequest.prototype.open;
    XMLHttpRequest.prototype.open = function(...args) {
      xhrCount++;
      if (xhrCount === 50) {
        this.sendEvent(
          'excessive-xhr',
          'High volume of XHR requests detected',
          'medium'
        );
      }
      return originalOpen.apply(this, args);
    }.bind(this);

    // Monitor DOM manipulation
    const observer = new MutationObserver(mutations => {
      let scriptInjections = 0;
      let iframeInjections = 0;

      mutations.forEach(mutation => {
        mutation.addedNodes.forEach(node => {
          if (node.nodeName === 'SCRIPT') scriptInjections++;
          if (node.nodeName === 'IFRAME') iframeInjections++;
        });
      });

      if (scriptInjections > 5) {
        this.sendEvent(
          'script-injection',
          `${scriptInjections} scripts injected dynamically`,
          'medium'
        );
      }

      if (iframeInjections > 0) {
        this.sendEvent(
          'iframe-injection',
          `${iframeInjections} iframe(s) injected dynamically`,
          'medium'
        );
      }
    });

    observer.observe(document.body, {
      childList: true,
      subtree: true
    });
  }

  injectPhishingProtection() {
    // Monitor all link clicks for phishing
    document.addEventListener('click', async (e) => {
      const link = e.target.closest('a');
      if (!link) return;

      const href = link.href || '';
      if (!href || href.startsWith('javascript:') || href.startsWith('#') || href.startsWith('mailto:') || href.startsWith('tel:')) {
        return;
      }

      // Check if link leads to external domain
      try {
        const currentDomain = window.location.hostname;
        const linkDomain = new URL(href).hostname;

        // If it's an external link, check for phishing
        if (linkDomain !== currentDomain) {
          // Quick phishing indicators check
          const isSuspicious = this.checkSuspiciousLink(href);
          
          if (isSuspicious.suspicious) {
            e.preventDefault();
            e.stopPropagation();
            
            const proceed = confirm(
              `⚠️ HELIORА SECURITY WARNING\n\n` +
              `This link appears suspicious:\n${linkDomain}\n\n` +
              `Reason: ${isSuspicious.reason}\n\n` +
              `Are you sure you want to continue?`
            );
            
            if (!proceed) {
              console.log('[HelioRa Content] Blocked suspicious link:', href);
              this.sendEvent('phishing-link-blocked', `Blocked suspicious link: ${linkDomain}`, 'critical');
            } else {
              window.location.href = href;
            }
          }
        }
      } catch (err) {
        // Invalid URL, ignore
      }
    }, true);

    // Highlight suspicious links on the page
    this.highlightSuspiciousLinks();
  }

  checkSuspiciousLink(url) {
    try {
      const urlLower = url.toLowerCase();
      const urlObj = new URL(url);
      const domain = urlObj.hostname;

      // Check for IP addresses
      if (/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(domain)) {
        return { suspicious: true, reason: 'Link uses IP address instead of domain name' };
      }

      // Check for suspicious TLDs
      const suspiciousTlds = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.pw'];
      if (suspiciousTlds.some(tld => domain.endsWith(tld))) {
        return { suspicious: true, reason: 'Suspicious domain extension commonly used in phishing' };
      }

      // Check for typosquatting
      const popularBrands = ['google', 'facebook', 'paypal', 'amazon', 'apple', 'microsoft', 'netflix', 'instagram'];
      for (const brand of popularBrands) {
        if (domain.includes(brand) && !domain.endsWith(`${brand}.com`)) {
          return { suspicious: true, reason: `Possible typosquatting of ${brand}.com` };
        }
      }

      // Check for phishing keywords
      const phishingKeywords = ['verify', 'account', 'suspend', 'secure', 'update', 'confirm', 'login'];
      const keywordCount = phishingKeywords.filter(kw => urlLower.includes(kw)).length;
      if (keywordCount >= 2) {
        return { suspicious: true, reason: 'Multiple phishing keywords detected in URL' };
      }

      return { suspicious: false, reason: '' };
    } catch (err) {
      return { suspicious: false, reason: '' };
    }
  }

  highlightSuspiciousLinks() {
    const links = document.querySelectorAll('a[href]');
    links.forEach(link => {
      const href = link.href;
      if (!href || href.startsWith('javascript:') || href.startsWith('#')) return;

      try {
        const currentDomain = window.location.hostname;
        const linkDomain = new URL(href).hostname;

        if (linkDomain !== currentDomain) {
          const check = this.checkSuspiciousLink(href);
          if (check.suspicious) {
            // Add visual warning
            link.style.border = '2px solid #F44336';
            link.style.backgroundColor = 'rgba(244, 67, 54, 0.1)';
            link.style.borderRadius = '3px';
            link.title = `⚠️ HelioRa Warning: ${check.reason}`;
          }
        }
      } catch (err) {
        // Invalid URL
      }
    });
  }

  injectPDFHandler() {
    // Intercept PDF clicks for inline preview
    document.addEventListener('click', async (e) => {
      const link = e.target.closest('a');
      if (!link) return;

      const href = link.href || '';
      if (href.toLowerCase().endsWith('.pdf')) {
        e.preventDefault();
        e.stopPropagation();

        console.log('[HelioRa Content] PDF link clicked:', href);

        // Create PDF preview modal
        this.showPDFPreview(href);
      }
    }, true);
  }

  showPDFPreview(pdfUrl) {
    // Create modal overlay
    const overlay = document.createElement('div');
    overlay.id = 'heliora-pdf-preview';
    overlay.style.cssText = `
      position: fixed;
      top: 0;
      left: 0;
      right: 0;
      bottom: 0;
      background: rgba(0, 0, 0, 0.95);
      z-index: 999999;
      display: flex;
      flex-direction: column;
      padding: 20px;
    `;

    // Create header
    const header = document.createElement('div');
    header.style.cssText = `
      display: flex;
      justify-content: space-between;
      align-items: center;
      padding: 15px 20px;
      background: linear-gradient(135deg, #FDB813, #E6A500);
      border-radius: 8px 8px 0 0;
      color: #0A0A0A;
    `;

    const title = document.createElement('div');
    title.style.cssText = `
      font-size: 16px;
      font-weight: 700;
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    `;
    title.textContent = '📄 HelioRa PDF Preview';

    const closeBtn = document.createElement('button');
    closeBtn.textContent = '✕';
    closeBtn.style.cssText = `
      background: rgba(0, 0, 0, 0.2);
      border: none;
      color: #0A0A0A;
      font-size: 24px;
      cursor: pointer;
      width: 36px;
      height: 36px;
      border-radius: 6px;
      display: flex;
      align-items: center;
      justify-content: center;
    `;
    closeBtn.onclick = () => overlay.remove();

    header.appendChild(title);
    header.appendChild(closeBtn);

    // Create info bar
    const infoBar = document.createElement('div');
    infoBar.style.cssText = `
      background: #1A1A1A;
      padding: 12px 20px;
      color: #B8B8B8;
      font-size: 12px;
      font-family: 'Courier New', monospace;
      border-bottom: 1px solid #333;
    `;
    infoBar.textContent = `📎 ${pdfUrl}`;

    // Create iframe for PDF
    const iframe = document.createElement('iframe');
    iframe.src = pdfUrl;
    iframe.style.cssText = `
      flex: 1;
      border: none;
      background: white;
      border-radius: 0 0 8px 8px;
    `;

    // Create action bar
    const actionBar = document.createElement('div');
    actionBar.style.cssText = `
      display: flex;
      gap: 10px;
      padding: 15px 20px;
      background: #1A1A1A;
      border-radius: 0 0 8px 8px;
      border-top: 1px solid #333;
    `;

    const downloadBtn = document.createElement('button');
    downloadBtn.textContent = '⬇ Download';
    downloadBtn.style.cssText = `
      flex: 1;
      padding: 12px;
      background: #FDB813;
      color: #0A0A0A;
      border: none;
      border-radius: 6px;
      font-weight: 700;
      font-size: 13px;
      cursor: pointer;
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    `;
    downloadBtn.onclick = () => {
      window.open(pdfUrl, '_blank');
      overlay.remove();
    };

    const openTabBtn = document.createElement('button');
    openTabBtn.textContent = '↗ Open in New Tab';
    openTabBtn.style.cssText = `
      flex: 1;
      padding: 12px;
      background: #2A2A2A;
      color: #FDB813;
      border: 1px solid #FDB813;
      border-radius: 6px;
      font-weight: 700;
      font-size: 13px;
      cursor: pointer;
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    `;
    openTabBtn.onclick = () => {
      window.open(pdfUrl, '_blank');
      overlay.remove();
    };

    actionBar.appendChild(downloadBtn);
    actionBar.appendChild(openTabBtn);

    // Assemble modal
    const container = document.createElement('div');
    container.style.cssText = `
      display: flex;
      flex-direction: column;
      height: 100%;
      max-width: 1200px;
      margin: 0 auto;
      width: 100%;
    `;

    container.appendChild(header);
    container.appendChild(infoBar);
    container.appendChild(iframe);
    container.appendChild(actionBar);

    overlay.appendChild(container);
    document.body.appendChild(overlay);

    // Send event
    this.sendEvent(
      'pdf-preview',
      `PDF preview opened: ${pdfUrl.split('/').pop()}`,
      'low'
    );
  }
}

// Initialize
new HelioRaContentScript();

// Monitor and report blocked resources
const blockedResourceObserver = new PerformanceObserver((list) => {
  list.getEntries().forEach(entry => {
    // Check if resource failed to load (likely blocked)
    if (entry.transferSize === 0 && entry.decodedBodySize === 0) {
      const url = entry.name;
      
      // Check if it's an ad/tracker domain
      const knownAdTrackers = [
        'doubleclick.net', 'googlesyndication.com', 'googleadservices.com',
        'google-analytics.com', 'googletagmanager.com', 'facebook.com/tr',
        'scorecardresearch.com', 'adnxs.com', 'advertising.com',
        'quantserve.com', 'outbrain.com', 'taboola.com', 'criteo.com'
      ];
      
      if (knownAdTrackers.some(tracker => url.includes(tracker))) {
        chrome.runtime.sendMessage({
          action: 'resourceBlocked',
          url: url
        }).catch(() => {});
      }
    }
  });
});

try {
  blockedResourceObserver.observe({ entryTypes: ['resource'] });
  console.log('[HelioRa] Resource blocking monitor active');
} catch (e) {
  console.log('[HelioRa] Resource monitoring not available');
}

// ==================== macOS INTEGRATION ====================

// Listen for hidden surveillance warnings from service worker
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === 'showHiddenSurveillanceWarning') {
    showHiddenSurveillanceOverlay(request.domain, request.osStatus);
    sendResponse({ success: true });
    return true;
  }
});

function showHiddenSurveillanceOverlay(domain, osStatus) {
  // Remove any existing overlay
  const existing = document.getElementById('heliora-hidden-surveillance-warning');
  if (existing) existing.remove();
  
  const overlay = document.createElement('div');
  overlay.id = 'heliora-hidden-surveillance-warning';
  overlay.style.cssText = `
    position: fixed !important;
    top: 0 !important;
    left: 0 !important;
    width: 100vw !important;
    height: 100vh !important;
    background: radial-gradient(circle, #8B0000 0%, #4B0000 100%) !important;
    color: white !important;
    z-index: 2147483647 !important;
    display: flex !important;
    align-items: center !important;
    justify-content: center !important;
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif !important;
    animation: pulse-red 1.5s ease-in-out infinite !important;
  `;
  
  const activeDevices = [];
  if (osStatus.osCameraActive) activeDevices.push('CAMERA');
  if (osStatus.osMicActive) activeDevices.push('MICROPHONE');
  
  overlay.innerHTML = `
    <style>
      @keyframes pulse-red {
        0%, 100% { opacity: 0.95; }
        50% { opacity: 1; }
      }
      @keyframes shake {
        0%, 100% { transform: translateX(0); }
        25% { transform: translateX(-10px); }
        75% { transform: translateX(10px); }
      }
    </style>
    <div style="text-align: center; padding: 60px; max-width: 800px; animation: shake 0.5s ease-in-out infinite;">
      <div style="font-size: 120px; margin-bottom: 30px; animation: pulse-red 1s ease-in-out infinite;">
        🚨
      </div>
      
      <h1 style="font-size: 56px; margin-bottom: 20px; font-weight: 900; text-transform: uppercase; letter-spacing: 3px;">
        CRITICAL SECURITY BREACH
      </h1>
      
      <div style="background: rgba(255, 255, 255, 0.2); padding: 30px; border-radius: 20px; margin: 30px 0; border: 3px solid #FFD700;">
        <h2 style="font-size: 36px; color: #FFD700; margin-bottom: 20px; font-weight: 800;">
          HIDDEN SURVEILLANCE DETECTED
        </h2>
        <p style="font-size: 22px; line-height: 1.8; margin-bottom: 25px;">
          <strong>⚠️ YOUR ${activeDevices.join(' AND ')} ${activeDevices.length > 1 ? 'ARE' : 'IS'} ACTIVE</strong><br>
          <span style="color: #FFD700; font-size: 28px;">BUT NO WEBSITE HAS PERMISSION</span>
        </p>
        <p style="font-size: 18px; line-height: 1.6; color: rgba(255, 255, 255, 0.9);">
          This means <strong>${domain}</strong> is bypassing browser security<br>
          and accessing your ${activeDevices.join(' and ').toLowerCase()} through a hidden backdoor.
        </p>
      </div>
      
      <div style="background: rgba(0, 0, 0, 0.5); padding: 25px; border-radius: 15px; margin: 30px 0; border: 2px solid #FF0000;">
        <p style="font-size: 20px; line-height: 1.8; margin-bottom: 20px;">
          <strong>⚠️ THIS IS EXTREMELY DANGEROUS ⚠️</strong>
        </p>
        <p style="font-size: 16px; line-height: 1.6; color: rgba(255, 255, 255, 0.85);">
          • Your ${activeDevices.join(' and ').toLowerCase()} ${activeDevices.length > 1 ? 'are' : 'is'} being accessed without consent<br>
          • This could be spyware, malware, or a sophisticated attack<br>
          • Someone may be watching/listening right now<br>
          • This site bypassed all browser protections
        </p>
      </div>
      
      <div style="margin-top: 40px;">
        <button id="heliora-close-tab-now" style="
          background: #FFD700;
          color: #000;
          border: none;
          padding: 20px 50px;
          font-size: 24px;
          border-radius: 15px;
          cursor: pointer;
          font-weight: 900;
          text-transform: uppercase;
          box-shadow: 0 10px 30px rgba(255, 215, 0, 0.5);
          margin: 10px;
        ">
          🚨 CLOSE TAB IMMEDIATELY 🚨
        </button>
      </div>
      
      <div style="margin-top: 30px; font-size: 14px; color: rgba(255, 255, 255, 0.7);">
        <strong>Technical Details:</strong><br>
        Domain: ${domain}<br>
        OS Detection Time: ${osStatus.osTimestamp}<br>
        macOS AVFoundation: ${activeDevices.join(', ')} IN USE<br>
        Browser Permission Status: NONE GRANTED<br>
        <br>
        <strong>🛡️ Protected by HelioRa Security + macOS System Monitor</strong><br>
        <em>Cross-layer surveillance detection - Browser + OS verification</em>
      </div>
    </div>
  `;
  
  document.body.appendChild(overlay);
  
  // Add event listeners
  document.getElementById('heliora-close-tab-now').addEventListener('click', () => {
    window.close();
    
    // If window.close() doesn't work (some browsers prevent it), try to navigate away
    setTimeout(() => {
      window.location.href = 'about:blank';
    }, 100);
  });
  
  // Also send notification
  console.error('%c[HelioRa] 🚨 CRITICAL SECURITY BREACH - HIDDEN SURVEILLANCE', 'color: red; font-size: 20px; font-weight: bold');
  console.error('[HelioRa] Domain:', domain);
  console.error('[HelioRa] OS Status:', osStatus);
  console.error('[HelioRa] Action: CLOSE THIS TAB IMMEDIATELY');
}

console.log('[HelioRa] macOS Integration Active - Cross-layer surveillance detection enabled');
