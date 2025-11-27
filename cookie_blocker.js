'use strict';

console.log('[HelioRa Cookie Blocker] Loaded on:', window.location.hostname);

// Auto-decline cookie banners
class CookieBannerBlocker {
  constructor() {
    this.init();
  }

  init() {
    // Wait for page to load
    if (document.readyState === 'loading') {
      document.addEventListener('DOMContentLoaded', () => this.blockCookieBanners());
    } else {
      this.blockCookieBanners();
    }

    // Watch for dynamically added cookie banners
    this.observeDOMChanges();
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
      
      // Specific cookie banner libraries
      '#onetrust-banner-sdk',
      '#cookieConsent',
      '.cookie-banner',
      '.cookie-consent',
      '.gdpr-banner',
      '.cc-window',
      '.cookie-notice',
      '#CybotCookiebotDialog',
      '.cky-consent-container',
      '#usercentrics-root',
      '.didomi-popup',
      '#truste-consent-track'
    ];

    let bannersFound = 0;

    cookieBannerSelectors.forEach(selector => {
      try {
        const elements = document.querySelectorAll(selector);
        elements.forEach(element => {
          // Check if it's actually a cookie banner (visible and has cookie-related text)
          const text = element.textContent.toLowerCase();
          if (text.includes('cookie') || text.includes('consent') || text.includes('privacy') || text.includes('gdpr')) {
            // Try to find and click decline/reject button
            const declined = this.findAndClickDeclineButton(element);
            
            if (!declined) {
              // If no decline button found, just hide the banner
              element.style.display = 'none';
              element.remove();
            }
            
            bannersFound++;
            console.log('[HelioRa] Blocked cookie banner:', selector);
          }
        });
      } catch (err) {
        // Ignore selector errors
      }
    });

    if (bannersFound > 0) {
      console.log(`[HelioRa] Blocked ${bannersFound} cookie banner(s)`);
      
      // Notify the extension
      chrome.runtime.sendMessage({
        action: 'cookieBannerBlocked',
        count: bannersFound
      }).catch(() => {});
    }
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
            if (text.includes('cookie') || text.includes('consent') || text.includes('privacy')) {
              shouldCheck = true;
            }
          }
        });
      });

      if (shouldCheck) {
        setTimeout(() => this.blockCookieBanners(), 1000);
      }
    });

    observer.observe(document.body, {
      childList: true,
      subtree: true
    });
  }
}

// Initialize the cookie banner blocker
setTimeout(() => {
  new CookieBannerBlocker();
}, 1000);

// Re-check periodically for lazy-loaded banners
setInterval(() => {
  new CookieBannerBlocker();
}, 5000);
