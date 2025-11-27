'use strict';

console.log('[HelioRa Cookie Blocker] Loaded on:', window.location.hostname);

// Auto-decline cookie banners
class CookieBannerBlocker {
  constructor() {
    this.settings = {
      autoCookieDecline: true,
      blockCookies: false
    };
    this.init();
  }

  async init() {
    // Load settings first
    try {
      const result = await chrome.runtime.sendMessage({ action: 'getSettings' });
      if (result?.settings) {
        this.settings = {
          autoCookieDecline: result.settings.autoCookieDecline !== false,
          blockCookies: result.settings.blockCookies === true
        };
      }
    } catch (err) {
      console.log('[HelioRa Cookie] Using default settings');
      // Default: auto-decline enabled
      this.settings.autoCookieDecline = true;
    }
    
    console.log('[HelioRa Cookie] Settings loaded:', this.settings);
    
    // ALWAYS block cookie banners by default (unless explicitly disabled)
    const shouldBlock = this.settings.autoCookieDecline || this.settings.blockCookies;
    console.log('[HelioRa Cookie] Should block:', shouldBlock);
    
    if (shouldBlock) {
      // Inject CSS to hide cookie banners immediately
      this.injectHidingCSS();
      
      // Start blocking immediately, don't wait
      this.blockCookieBanners();
      
      // Also run after DOM loads
      if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', () => {
          this.blockCookieBanners();
          // Run again after a short delay for late-loading banners
          setTimeout(() => this.blockCookieBanners(), 1000);
          setTimeout(() => this.blockCookieBanners(), 3000);
        });
      } else {
        // Already loaded, run multiple times
        setTimeout(() => this.blockCookieBanners(), 500);
        setTimeout(() => this.blockCookieBanners(), 1500);
        setTimeout(() => this.blockCookieBanners(), 3000);
      }

      // Watch for dynamically added cookie banners
      this.observeDOMChanges();
    }
  }
  
  injectHidingCSS() {
    // Inject CSS to instantly hide common cookie banners
    const style = document.createElement('style');
    style.id = 'heliora-cookie-blocker';
    style.textContent = `
      /* Hide ALL common cookie banner patterns */
      #onetrust-banner-sdk,
      #onetrust-consent-sdk,
      .onetrust-pc-dark-filter,
      #onetrust-pc-sdk,
      #CybotCookiebotDialog,
      #CybotCookiebotDialogBodyUnderlay,
      .cky-consent-container,
      .cky-consent-bar,
      #usercentrics-root,
      .didomi-popup,
      .didomi-host,
      #truste-consent-track,
      .qc-cmp2-container,
      #qc-cmp2-ui,
      .fc-consent-root,
      .cc-window,
      .cc-banner,
      .cookie-banner,
      .cookie-consent,
      .cookie-notice,
      .cookie-bar,
      .cookie-popup,
      .gdpr-banner,
      .gdpr-consent,
      .consent-banner,
      .consent-bar,
      .privacy-banner,
      .privacy-notice,
      [class*="cookie-banner"],
      [class*="cookie-consent"],
      [class*="cookie-notice"],
      [class*="cookie-bar"],
      [class*="cookie-popup"],
      [class*="gdpr-banner"],
      [class*="gdpr-consent"],
      [class*="consent-banner"],
      [id*="cookie-banner"],
      [id*="cookie-consent"],
      [id*="cookie-notice"],
      [id*="gdpr"],
      [aria-label*="cookie" i],
      [aria-label*="consent" i],
      .osano-cm-window,
      #osano-cm-window,
      .termly-styles-root,
      #termly-code-snippet-support {
        display: none !important;
        visibility: hidden !important;
        opacity: 0 !important;
        pointer-events: none !important;
        height: 0 !important;
        width: 0 !important;
        position: absolute !important;
        z-index: -9999 !important;
      }
      
      /* Hide overlays and backdrops */
      .modal-backdrop,
      .cookie-overlay,
      [class*="cookie"][class*="overlay"],
      [class*="consent"][class*="overlay"] {
        display: none !important;
        visibility: hidden !important;
      }
      
      /* Re-enable scrolling */
      body.modal-open,
      body[style*="overflow: hidden"],
      html[style*="overflow: hidden"] {
        overflow: auto !important;
      }
      
      /* Hide any fixed/sticky elements at bottom with cookie text */
      div[style*="position: fixed"][style*="bottom"],
      div[style*="position: sticky"][style*="bottom"] {
        display: none !important;
      }
    `;
    
    (document.head || document.documentElement).appendChild(style);
    console.log('[HelioRa Cookie] Injected aggressive hiding CSS');
  }

  blockCookieBanners() {
    console.log('[HelioRa] Aggressively searching for cookie banners...');

    // EVERY possible cookie banner selector
    const cookieBannerSelectors = [
      // Generic pattern matching (most aggressive)
      '[class*="cookie"]',
      '[id*="cookie"]',
      '[class*="Cookie"]',
      '[id*="Cookie"]',
      '[class*="gdpr"]',
      '[id*="gdpr"]',
      '[class*="GDPR"]',
      '[id*="GDPR"]',
      '[class*="consent"]',
      '[id*="consent"]',
      '[class*="Consent"]',
      '[id*="Consent"]',
      '[class*="privacy"]',
      '[id*="privacy"]',
      '[class*="banner"]',
      '[class*="notice"]',
      '[class*="popup"]',
      '[aria-label*="cookie" i]',
      '[aria-label*="consent" i]',
      '[aria-label*="privacy" i]',
      '[role="dialog"]',
      '[role="alertdialog"]',
      
      // Major cookie consent platforms
      '#onetrust-banner-sdk',
      '#onetrust-consent-sdk',
      '#onetrust-pc-sdk',
      '.onetrust-pc-dark-filter',
      '#CybotCookiebotDialog',
      '#CybotCookiebotDialogBodyUnderlay',
      '.cky-consent-container',
      '.cky-consent-bar',
      '#usercentrics-root',
      '.didomi-popup',
      '.didomi-host',
      '#truste-consent-track',
      '.qc-cmp2-container',
      '#qc-cmp2-ui',
      '.fc-consent-root',
      '.cc-window',
      '.cc-banner',
      '#cookieConsent',
      '.osano-cm-window',
      '#osano-cm-window',
      '.termly-styles-root',
      '#termly-code-snippet-support',
      
      // Generic cookie classes
      '.cookie-banner',
      '.cookie-consent',
      '.cookie-notice',
      '.cookie-bar',
      '.cookie-popup',
      '.cookie-message',
      '.cookie-warning',
      '.cookie-notification',
      '.gdpr-banner',
      '.gdpr-consent',
      '.consent-banner',
      '.consent-bar',
      '.privacy-banner',
      '.privacy-notice'
    ];

    let bannersFound = 0;

    cookieBannerSelectors.forEach(selector => {
      try {
        const elements = document.querySelectorAll(selector);
        elements.forEach(element => {
          // Check if it's actually a cookie banner (visible and has cookie-related text)
          const text = element.textContent.toLowerCase();
          const isCookieBanner = text.includes('cookie') || text.includes('consent') || 
                                 text.includes('privacy') || text.includes('gdpr') ||
                                 text.includes('accept') || text.includes('reject');
          
          if (isCookieBanner) {
            // If "Block All Cookies" is enabled, just remove the banner immediately
            if (this.settings.blockCookies) {
              element.style.display = 'none';
              setTimeout(() => element.remove(), 100);
              bannersFound++;
              console.log('[HelioRa] Force removed cookie banner (Block All Cookies enabled)');
            } else {
              // Otherwise try to decline automatically
              const declined = this.findAndClickDeclineButton(element);
              
              if (!declined) {
                // If no decline button found, just hide the banner
                element.style.display = 'none';
                setTimeout(() => element.remove(), 100);
              }
              
              bannersFound++;
              console.log('[HelioRa] Blocked cookie banner:', selector);
            }
          }
        });
      } catch (err) {
        // Ignore selector errors
      }
    });
    
    // Also remove cookie consent overlays/backdrops
    this.removeOverlays();
    
    // Nuclear option: remove ANY fixed/sticky element with cookie text
    this.removeFixedCookieElements();

    if (bannersFound > 0) {
      console.log(`[HelioRa] Blocked ${bannersFound} cookie banner(s)`);
      
      // Notify the extension
      chrome.runtime.sendMessage({
        action: 'cookieBannerBlocked',
        count: bannersFound
      }).catch(() => {});
    }
  }
  
  removeFixedCookieElements() {
    // Find ALL fixed/sticky positioned elements
    const allElements = document.querySelectorAll('*');
    
    allElements.forEach(element => {
      try {
        const style = window.getComputedStyle(element);
        const position = style.position;
        
        // Check if it's fixed or sticky
        if (position === 'fixed' || position === 'sticky') {
          const text = element.textContent?.toLowerCase() || '';
          const classes = element.className?.toString().toLowerCase() || '';
          const id = element.id?.toLowerCase() || '';
          
          // Check if it contains cookie-related keywords
          const hasCookieText = text.includes('cookie') || text.includes('consent') || 
                                text.includes('privacy') || text.includes('gdpr') ||
                                text.includes('accept') || text.includes('reject');
          
          const hasCookieClass = classes.includes('cookie') || classes.includes('consent') ||
                                 classes.includes('gdpr') || classes.includes('privacy');
          
          const hasCookieId = id.includes('cookie') || id.includes('consent') ||
                              id.includes('gdpr') || id.includes('privacy');
          
          // If it's a cookie banner, nuke it
          if ((hasCookieText && text.length < 5000) || hasCookieClass || hasCookieId) {
            element.style.display = 'none';
            element.style.visibility = 'hidden';
            element.style.opacity = '0';
            element.style.zIndex = '-9999';
            element.remove();
            console.log('[HelioRa Cookie] Removed fixed cookie element:', element.className || element.id);
          }
        }
      } catch (err) {
        // Ignore errors
      }
    });
  }
  
  removeOverlays() {
    // Remove dark overlays that cookie popups create
    const overlays = document.querySelectorAll('[class*="overlay"], [class*="backdrop"], [class*="modal-backdrop"]');
    overlays.forEach(overlay => {
      const style = window.getComputedStyle(overlay);
      const zIndex = parseInt(style.zIndex);
      
      // If it's a high z-index overlay (likely from cookie banner)
      if (zIndex > 1000) {
        overlay.style.display = 'none';
        overlay.remove();
      }
    });
    
    // Re-enable scrolling if it was disabled by cookie banner
    document.body.style.overflow = '';
    document.documentElement.style.overflow = '';
  }

  findAndClickDeclineButton(banner) {
    // Common decline button selectors and text patterns
    const declinePatterns = [
      'reject', 'decline', 'deny', 'refuse', 'disagree', 'no', 'necessary',
      'essential', 'only necessary', 'reject all', 'decline all'
    ];

    const acceptPatterns = ['accept', 'agree', 'allow', 'ok', 'yes', 'consent'];

    // Find all buttons in the banner
    const buttons = banner.querySelectorAll('button, a, [role="button"], input[type="button"], input[type="submit"]');

    let declineButton = null;
    let acceptButton = null;

    buttons.forEach(button => {
      const text = button.textContent.toLowerCase();
      const ariaLabel = (button.getAttribute('aria-label') || '').toLowerCase();
      const id = (button.id || '').toLowerCase();
      const className = (button.className || '').toLowerCase();
      
      const fullText = `${text} ${ariaLabel} ${id} ${className}`;

      // Check if it's a decline button
      if (declinePatterns.some(pattern => fullText.includes(pattern))) {
        // Prioritize buttons with more explicit decline text
        if (!declineButton || text.includes('reject') || text.includes('decline')) {
          declineButton = button;
        }
      }
      
      // Track accept buttons to avoid clicking them
      if (acceptPatterns.some(pattern => fullText.includes(pattern))) {
        if (!text.includes('necessary') && !text.includes('essential')) {
          acceptButton = button;
        }
      }
    });

    // Click the decline button if found
    if (declineButton) {
      console.log('[HelioRa] Clicking decline button:', declineButton.textContent);
      declineButton.click();
      
      // Also hide the banner
      setTimeout(() => {
        banner.style.display = 'none';
        banner.remove();
      }, 500);
      
      return true;
    }

    return false;
  }

  observeDOMChanges() {
    // Watch for new cookie banners being added
    const observer = new MutationObserver((mutations) => {
      let shouldCheck = false;
      
      mutations.forEach(mutation => {
        mutation.addedNodes.forEach(node => {
          if (node.nodeType === 1) { // Element node
            const text = node.textContent?.toLowerCase() || '';
            const className = node.className?.toString().toLowerCase() || '';
            const id = node.id?.toLowerCase() || '';
            
            if (text.includes('cookie') || text.includes('consent') || text.includes('privacy') ||
                className.includes('cookie') || className.includes('consent') || 
                id.includes('cookie') || id.includes('consent')) {
              shouldCheck = true;
            }
          }
        });
      });

      if (shouldCheck) {
        setTimeout(() => this.blockCookieBanners(), 500);
      }
    });

    observer.observe(document.body, {
      childList: true,
      subtree: true
    });
  }
}

// Initialize the cookie banner blocker
const cookieBlocker = new CookieBannerBlocker();

// Re-check periodically for lazy-loaded banners
setInterval(() => {
  if (cookieBlocker.settings.autoCookieDecline || cookieBlocker.settings.blockCookies) {
    cookieBlocker.blockCookieBanners();
  }
}, 3000);
