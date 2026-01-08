// HelioRa Enhanced Cookie & Popup Blocker
// Designed to remove visual annoyances, banners, and overlays.

(function() {
  'use strict';

  // Configuration
  const HELIORA_COOKIE_MAX_RUNTIME = 120000; // 120s limit (extended coverage)
  const HELIORA_CHECK_INTERVAL = 500; // Check every 500ms
  let startTime = Date.now();

  // Enhanced Blocking: Generic Overlay/Popup/Modal Blocking
  // We inject CSS to hide common annoyance patterns immediately.
  const style = document.createElement('style');
  style.id = 'heliora-blocking-styles';
  style.textContent = `
    /* Hiding generic popup/modal/banner classes */
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
    [role="dialog"] {
      /* Base styles for potential blocking */
    }
    
    /* Force hide known cookie/consent IDs */
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
    
    /* Restore scrolling if locked */
    html, body {
      overflow: auto !important;
      position: static !important;
    }
  `;
  
  if (document.head) {
    document.head.appendChild(style);
  } else {
    // If head doesn't exist yet (document_start), wait for it
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

    // Aggressive check: Any fixed/sticky element with z-index > 10 is suspect if it covers content
    if (!(pos === 'fixed' || pos === 'sticky' || pos === 'absolute')) return false;
    if (z < 10) return false;

    const text = (el.innerText || '').toLowerCase();
    const id = (el.id || '').toLowerCase();
    const cls = (el.className || '').toString().toLowerCase();
    const aria = (el.getAttribute('aria-label') || '').toLowerCase();

    // If it's a small icon or button (e.g. chat widget, back to top), ignore it unless it's an ad
    const rect = el.getBoundingClientRect();
    if (rect.width < 50 && rect.height < 50) return false;

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
      popupSignals.some(k => text.includes(k)) || // Text content check is powerful
      vendorSignals.some(v => id.includes(v) || cls.includes(v));

    const isDialog =
      el.getAttribute('role') === 'dialog' ||
      el.getAttribute('aria-modal') === 'true';

    // Aggressive check: If it's a dialog OR has a signal OR is just a big overlay covering the screen
    const coversScreen = (rect.width > window.innerWidth * 0.8 && rect.height > window.innerHeight * 0.8);
    
    return (signal && (isDialog || z > 10)) || coversScreen;
  }

  function removePopups() {
    if (Date.now() - startTime > HELIORA_COOKIE_MAX_RUNTIME) return;

    // 1. Scan all elements in body
    const allElements = document.querySelectorAll('body *');
    
    for (let el of allElements) {
      if (isAggressiveFixedPopup(el)) {
        console.log('[HelioRa] Blocking popup:', el);
        
        // Hide element
        el.style.setProperty('display', 'none', 'important');
        el.style.setProperty('visibility', 'hidden', 'important');
        el.style.setProperty('opacity', '0', 'important');
        el.style.setProperty('pointer-events', 'none', 'important');
        
        // If it was a modal, we often need to unlock the body scroll
        document.body.style.setProperty('overflow', 'auto', 'important');
        document.documentElement.style.setProperty('overflow', 'auto', 'important');
      }
    }

    // 2. Handle Shadow DOM (where many modern popups hide)
    // Skipped deep traversal for performance
  }

  // Run immediately
  removePopups();

  // Run on mutation (dynamic content)
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

  // Periodic cleanup for stubborn popups
  const interval = setInterval(() => {
    if (Date.now() - startTime > HELIORA_COOKIE_MAX_RUNTIME) {
      clearInterval(interval);
      observer.disconnect();
      return;
    }
    removePopups();
  }, HELIORA_CHECK_INTERVAL);
  
  // Re-trigger on scroll (lazy loaded popups)
  window.addEventListener('scroll', () => {
    startTime = Date.now(); // Reset timer on interaction
    removePopups();
  }, { passive: true });

  console.log('[HelioRa] Cookie/Popup Blocker Active');

})();
