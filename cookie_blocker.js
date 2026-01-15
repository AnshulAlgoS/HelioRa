(function() {
  'use strict';

  // Configuration constants
  const HELIORA_COOKIE_MAX_RUNTIME = 120000;
  const HELIORA_CHECK_INTERVAL = 500;
  let startTime = Date.now();
  const style = document.createElement('style');
  style.id = 'heliora-blocking-styles';
  style.textContent = `
    [class*="popup"], [id*="popup"],
    [class*="modal"], [id*="modal"],
    [class*="overlay"], [id*="overlay"],
    [class*="banner"], [id*="banner"],
    [class*="newsletter"], [id*="newsletter"],
    [class*="subscribe"], [id*="subscribe"],
    [class*="signup"], [id*="signup"],
    [class*="offer"], [id*="offer"],
    [class*="promotion"], [id*="promotion"],
    [aria-modal="true"],
    [role="dialog"] {}
    
    #onetrust-banner-sdk, #onetrust-consent-sdk,
    #CybotCookiebotDialog,
    #usercentrics-root,
    #termly-code-snippet-support,
    .fc-consent-root,
    .cc-banner, .cc-window,
    [id*="cookie"], [class*="cookie"],
    [id*="consent"], [class*="consent"],
    [id*="gdpr"], [class*="gdpr"] {
      display: none !important;
      visibility: hidden !important;
      opacity: 0 !important;
      pointer-events: none !important;
      z-index: -9999 !important;
    }
    
    html, body {
      overflow: auto !important;
      position: static !important;
    }
  `;
  
  if (document.head) {
    document.head.appendChild(style);
  } else {
    const observer = new MutationObserver(() => {
      if (document.head) {
        document.head.appendChild(style);
        observer.disconnect();
      }
    });
    observer.observe(document.documentElement, { childList: true });
  }

  function isAggressiveFixedPopup(el) {
    if (!el || !el.parentNode) return false;

    let style;
    try {
      style = window.getComputedStyle(el);
    } catch {
      return false;
    }

    const pos = style.position;
    const z = parseInt(style.zIndex || '0');
    const opacity = parseFloat(style.opacity || '1');
    const display = style.display;
    const visibility = style.visibility;

    if (display === 'none' || visibility === 'hidden' || opacity === 0) return false;

    if (!(pos === 'fixed' || pos === 'sticky' || pos === 'absolute')) return false;
    if (z < 10) return false;

    const text = (el.innerText || '').toLowerCase();
    const id = (el.id || '').toLowerCase();
    const cls = (el.className || '').toString().toLowerCase();
    const aria = (el.getAttribute('aria-label') || '').toLowerCase();

    // Ignore small UI elements like chat widgets
    const rect = el.getBoundingClientRect();
    if (rect.width < 50 && rect.height < 50) return false;

    if (id.startsWith('heliora-')) return false;

    const cookieSignals = [
      'cookie', 'cookies', 'consent', 'gdpr', 'privacy', 'term', 'policy'
    ];

    const popupSignals = [
      'subscribe', 'sign up', 'sign-up', 'login',
      'install app', 'use our app', 'turn on notifications',
      'enable notifications', 'newsletter', 'download our app',
      'accept notifications', 'allow notifications',
      'offer', 'discount', 'sale', 'promotion', 'exclusive',
      'wait', 'don\'t go', 'unlock', 'premium', 'register',
      'join now', 'get started', 'limited time'
    ];

    const vendorSignals = [
      'onetrust', 'cookiebot', 'quantcast', 'didomi',
      'trustarc', 'iubenda', 'osano', 'privacymanager',
      'optin', 'opt-in', 'popup', 'modal', 'overlay', 'dialog', 'banner'
    ];

    const signal =
      cookieSignals.some(k => text.includes(k) || id.includes(k) || cls.includes(k) || aria.includes(k)) ||
      popupSignals.some(k => text.includes(k)) || 
      vendorSignals.some(v => id.includes(v) || cls.includes(v));

    const isDialog =
      el.getAttribute('role') === 'dialog' ||
      el.getAttribute('aria-modal') === 'true';

    // Check for large overlays covering significant screen area
    const coversScreen = (rect.width > window.innerWidth * 0.8 && rect.height > window.innerHeight * 0.8);
    
    return (signal && (isDialog || z > 10)) || coversScreen;
  }

  function removePopups() {
    if (Date.now() - startTime > HELIORA_COOKIE_MAX_RUNTIME) return;

    const allElements = document.querySelectorAll('body *');
    
    for (let el of allElements) {
      if (isAggressiveFixedPopup(el)) {
        console.log('[HelioRa] Blocking popup:', el);
        
        el.style.setProperty('display', 'none', 'important');
        el.style.setProperty('visibility', 'hidden', 'important');
        el.style.setProperty('opacity', '0', 'important');
        el.style.setProperty('pointer-events', 'none', 'important');
        
        // Unlock body scroll if blocked by modal
        document.body.style.setProperty('overflow', 'auto', 'important');
        document.documentElement.style.setProperty('overflow', 'auto', 'important');
      }
    }
  }

  removePopups();

  // Monitor dynamic content changes
  const observer = new MutationObserver((mutations) => {
    let shouldScan = false;
    for (const m of mutations) {
      if (m.addedNodes.length > 0) shouldScan = true;
    }
    if (shouldScan) removePopups();
  });

  if (document.body) {
    observer.observe(document.body, { childList: true, subtree: true });
  } else {
    document.addEventListener('DOMContentLoaded', () => {
      observer.observe(document.body, { childList: true, subtree: true });
    });
  }

  // Periodic check for stubborn popups
  const interval = setInterval(() => {
    if (Date.now() - startTime > HELIORA_COOKIE_MAX_RUNTIME) {
      clearInterval(interval);
      observer.disconnect();
      return;
    }
    removePopups();
  }, HELIORA_CHECK_INTERVAL);
  
  // Re-check on scroll for lazy-loaded elements
  window.addEventListener('scroll', () => {
    startTime = Date.now(); 
    removePopups();
  }, { passive: true });

  console.log('[HelioRa] Cookie/Popup Blocker Active');

})();
