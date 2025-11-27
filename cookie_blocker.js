'use strict';

console.log('[HelioRa Cookie Blocker] Starting...');

// STEP 1: Inject aggressive CSS immediately (runs even before DOM loads)
const hideCSS = `
/* Cookie banners - General */
#onetrust-banner-sdk,
#onetrust-consent-sdk,
#CybotCookiebotDialog,
#CybotCookiebotDialogBodyLevelButtonLevelOptinAllowAll,
.cookie-banner,
.cookie-consent,
.cookie-notice,
.cookie-popup,
.cookie-dialog,
.cookie-modal,
.cookie-bar,
.gdpr-banner,
.gdpr-consent,
.privacy-banner,
[id*="cookie"],
[id*="Cookie"],
[class*="cookie"],
[class*="Cookie"],
[class*="consent"],
[class*="Consent"],
[class*="gdpr"],
[class*="GDPR"],
.fc-consent-root,
#qc-cmp2-container,
.qc-cmp2-container,
[id*="didomi"],
[class*="didomi"],
.trustarc-banner,
#teconsent,
.iubenda-cs-container,
.cc-window,
.cc-banner,
.cookiealert,
.cookiesjsr,
.osano-cm-window {
  display: none !important;
  visibility: hidden !important;
  opacity: 0 !important;
  pointer-events: none !important;
  z-index: -9999 !important;
}

/* Amazon-specific */
span[data-action="sp-cc"],
form[action*="cookie"],
div[class*="sp-cc"],
#sp-cc-container,
[id*="sp-cc"],
[class*="sp-cc"],
[aria-label*="cookie" i],
[aria-labelledby*="cookie" i] {
  display: none !important;
  visibility: hidden !important;
  opacity: 0 !important;
  pointer-events: none !important;
}

/* Overlays and backdrops */
.modal-backdrop,
.cookie-overlay,
[class*="overlay"],
div[style*="position: fixed"][style*="background"],
div[style*="position: fixed"][style*="z-index"] {
  opacity: 0 !important;
  pointer-events: none !important;
  display: none !important;
}

/* Re-enable scrolling */
body.modal-open,
body[style*="overflow: hidden"],
html[style*="overflow: hidden"] {
  overflow: auto !important;
}
`;

// Inject CSS immediately
const style = document.createElement('style');
style.textContent = hideCSS;
(document.head || document.documentElement).appendChild(style);

console.log('[HelioRa Cookie] CSS injected');

// STEP 2: Aggressively remove cookie banners
function nukeCookieBanners() {
  let removed = 0;

  // List of selectors to remove
  const selectors = [
    // OneTrust
    '#onetrust-banner-sdk',
    '#onetrust-consent-sdk',
    '#onetrust-pc-sdk',
    
    // CookieBot
    '#CybotCookiebotDialog',
    
    // Quantcast
    '#qc-cmp2-container',
    '.qc-cmp2-container',
    
    // Didomi
    '[id*="didomi"]',
    '[class*="didomi"]',
    
    // TrustArc
    '#truste-consent-track',
    '#teconsent',
    
    // Amazon specific
    'span[data-action="sp-cc"]',
    'form[action*="cookie"]',
    'div[class*="sp-cc"]',
    '#sp-cc-container',
    '[id*="sp-cc"]',
    '[data-action*="cookie"]',
    
    // Generic patterns
    '.cookie-banner',
    '.cookie-consent',
    '.cookie-notice',
    '.cookie-popup',
    '.cookie-dialog',
    '.cookie-modal',
    '.cookie-bar',
    '.cookie-preferences',
    '.gdpr-banner',
    '.gdpr-consent',
    '.privacy-banner',
    '.cc-window',
    '.cc-banner',
    '.osano-cm-window',
    
    // Attribute selectors
    '[id*="cookie"]',
    '[id*="Cookie"]',
    '[class*="cookieConsent"]',
    '[class*="CookieConsent"]',
    '[class*="cookie-preferences"]',
    '[aria-label*="cookie" i]',
    '[aria-label*="consent" i]',
    '[aria-labelledby*="cookie" i]',
  ];

  // Remove by selectors
  selectors.forEach(selector => {
    try {
      const elements = document.querySelectorAll(selector);
      elements.forEach(el => {
        el.remove();
        removed++;
      });
    } catch (e) {
      // Selector might be invalid, skip
    }
  });

  // Nuclear option: Find ANY fixed/sticky element with cookie-related content
  const allElements = document.querySelectorAll('*');
  allElements.forEach(el => {
    try {
      const style = window.getComputedStyle(el);
      const position = style.position;
      const zIndex = parseInt(style.zIndex) || 0;
      
      if (position === 'fixed' || position === 'sticky' || zIndex > 999) {
        const text = el.innerText?.toLowerCase() || '';
        const id = el.id?.toLowerCase() || '';
        const className = el.className?.toString().toLowerCase() || '';
        const ariaLabel = el.getAttribute('aria-label')?.toLowerCase() || '';
        
        const cookieKeywords = [
          'cookie', 'consent', 'gdpr', 'privacy', 
          'we use cookies', 'we use similar tools',
          'accept', 'decline', 'reject', 
          'manage preferences', 'cookie preferences',
          'cookie notice', 'your choice applies',
          'third-party advertising', 'personalized ads'
        ];
        
        const hasCookieContent = cookieKeywords.some(keyword => 
          text.includes(keyword) || 
          id.includes(keyword) || 
          className.includes(keyword) ||
          ariaLabel.includes(keyword)
        );
        
        // Extra check for Amazon-style long cookie text
        const hasLongCookieText = text.length > 100 && (
          text.includes('we use cookies') || 
          text.includes('cookie preferences') ||
          text.includes('advertising cookies')
        );
        
        if (hasCookieContent || hasLongCookieText) {
          el.remove();
          removed++;
        }
      }
    } catch (e) {
      // Skip elements that can't be checked
    }
  });

  // Remove overlays
  document.querySelectorAll('.modal-backdrop, [class*="overlay"]').forEach(el => {
    el.remove();
    removed++;
  });

  // Re-enable scrolling
  document.body.style.overflow = '';
  document.documentElement.style.overflow = '';

  if (removed > 0) {
    console.log(`[HelioRa Cookie] Removed ${removed} cookie banners`);
  }

  return removed;
}

// STEP 3: Try to click "Reject/Decline" buttons
function clickDeclineButtons() {
  const declineSelectors = [
    // Text-based (most common)
    'button:not([class*="accept"]):not([id*="accept"])',
    'a:not([class*="accept"]):not([id*="accept"])',
    'input[type="button"]:not([class*="accept"])',
    
    // Specific platforms
    '#onetrust-reject-all-handler',
    '[id*="reject"]',
    '[class*="reject"]',
    '[id*="decline"]',
    '[class*="decline"]',
    '[data-action*="decline"]',
    '[data-action*="reject"]',
    '[aria-label*="reject" i]',
    '[aria-label*="decline" i]',
  ];

  const declineKeywords = ['reject', 'decline', 'deny', 'refuse', 'no thanks', 'necessary only', 'essential only', 'no, thanks'];
  const avoidKeywords = ['accept', 'agree', 'allow', 'ok', 'got it'];

  let clicked = false;

  declineSelectors.forEach(selector => {
    try {
      const buttons = document.querySelectorAll(selector);
      buttons.forEach(btn => {
        const text = btn.innerText?.toLowerCase() || '';
        const ariaLabel = btn.getAttribute('aria-label')?.toLowerCase() || '';
        const value = btn.value?.toLowerCase() || '';
        
        const isDecline = declineKeywords.some(kw => 
          text.includes(kw) || ariaLabel.includes(kw) || value.includes(kw)
        );
        const isAccept = avoidKeywords.some(kw => 
          text.includes(kw) || ariaLabel.includes(kw) || value.includes(kw)
        );
        
        if (isDecline && !isAccept && !clicked) {
          console.log('[HelioRa Cookie] Clicking decline button:', text || ariaLabel || value);
          btn.click();
          clicked = true;
          
          // After clicking, remove the entire parent container
          setTimeout(() => {
            let parent = btn.parentElement;
            while (parent && parent !== document.body) {
              const parentText = parent.innerText?.toLowerCase() || '';
              if (parentText.includes('cookie') || parentText.includes('consent')) {
                parent.remove();
                console.log('[HelioRa Cookie] Removed parent container after click');
                break;
              }
              parent = parent.parentElement;
            }
          }, 100);
        }
      });
    } catch (e) {
      // Skip invalid selectors
    }
  });

  return clicked;
}

// STEP 4: Main execution
let scanCount = 0;

function scanAndDestroy() {
  scanCount++;
  console.log(`[HelioRa Cookie] Scan #${scanCount}`);
  
  // Remove banners
  const removed = nukeCookieBanners();
  
  // Click decline if available
  const clicked = clickDeclineButtons();
  
  if (removed > 0 || clicked) {
    console.log('[HelioRa Cookie] Action taken - removed or clicked');
  }
}

// Run immediately
scanAndDestroy();

// Run multiple times during page load
setTimeout(() => scanAndDestroy(), 500);
setTimeout(() => scanAndDestroy(), 1000);
setTimeout(() => scanAndDestroy(), 2000);
setTimeout(() => scanAndDestroy(), 3000);

// Monitor for new banners
const observer = new MutationObserver(() => {
  scanAndDestroy();
});

if (document.body) {
  observer.observe(document.body, {
    childList: true,
    subtree: true
  });
} else {
  document.addEventListener('DOMContentLoaded', () => {
    observer.observe(document.body, {
      childList: true,
      subtree: true
    });
  });
}

// Scan every 3 seconds as backup
setInterval(() => scanAndDestroy(), 3000);

console.log('[HelioRa Cookie Blocker] Fully armed and operational');
