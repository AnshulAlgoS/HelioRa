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
    }
    
    // If either auto-decline or block cookies is enabled, start blocking
    if (this.settings.autoCookieDecline || this.settings.blockCookies) {
      // Inject CSS to hide cookie banners immediately
      this.injectHidingCSS();
      
      // Wait for page to load
      if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', () => this.blockCookieBanners());
      } else {
        this.blockCookieBanners();
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
      /* Hide common cookie banner classes */
      #onetrust-banner-sdk,
      #onetrust-consent-sdk,
      .onetrust-pc-dark-filter,
      #CybotCookiebotDialog,
      .cky-consent-container,
      #usercentrics-root,
      .didomi-popup,
      #truste-consent-track,
      .qc-cmp2-container,
      #qc-cmp2-ui,
      .fc-consent-root,
      .cc-window,
      .cc-banner,
      [class*="cookie-banner"],
      [class*="cookie-consent"],
      [class*="gdpr-banner"],
      [id*="cookie-banner"],
      [id*="cookie-consent"] {
        display: none !important;
        visibility: hidden !important;
        opacity: 0 !important;
        pointer-events: none !important;
      }
      
      /* Re-enable scrolling if disabled by cookie banner */
      body.modal-open {
        overflow: auto !important;
      }
    `;
    
    (document.head || document.documentElement).appendChild(style);
    console.log('[HelioRa Cookie] Injected hiding CSS');
  }

  blockCookieBanners() {
    console.log('[HelioRa] Searching for cookie banners...');

    // Common cookie banner selectors
    const cookieBannerSelectors = [
      // Generic selectors
      '[class*="cookie"]',
      '[id*="cookie"]',
      '[class*="gdpr"]',
      '[id*="gdpr"]',
      '[class*="consent"]',
      '[id*="consent"]',
      '[class*="privacy-banner"]',
      '[id*="privacy-banner"]',
      '[class*="notice"]',
      '[aria-label*="cookie" i]',
      '[aria-label*="consent" i]',
      '[role="dialog"]',
      '[role="banner"]',
      
      // Specific cookie banner libraries
      '#onetrust-banner-sdk',
      '#onetrust-consent-sdk',
      '.onetrust-pc-dark-filter',
      '#cookieConsent',
      '.cookie-banner',
      '.cookie-consent',
      '.gdpr-banner',
      '.cc-window',
      '.cc-banner',
      '.cookie-notice',
      '#CybotCookiebotDialog',
      '.cky-consent-container',
      '#usercentrics-root',
      '.didomi-popup',
      '#truste-consent-track',
      '.qc-cmp2-container',
      '#qc-cmp2-ui',
      '.fc-consent-root',
      '#sp_message_container_'
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

    if (bannersFound > 0) {
      console.log(`[HelioRa] Blocked ${bannersFound} cookie banner(s)`);
      
      // Notify the extension
      chrome.runtime.sendMessage({
        action: 'cookieBannerBlocked',
        count: bannersFound
      }).catch(() => {});
    }
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
