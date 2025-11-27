'use strict';

// This injector runs in content script context
// Its job is to inject surveillance_protection.js into the MAIN world (page context)

console.log('[HelioRa Injector] Starting surveillance protection injection...');

// Method 1: Inject via script tag (most reliable for overriding APIs)
try {
  const script = document.createElement('script');
  script.src = chrome.runtime.getURL('surveillance_protection.js');
  script.type = 'text/javascript';
  
  // Inject as early as possible
  (document.head || document.documentElement).prepend(script);
  
  // Remove after loading to avoid detection
  script.onload = () => {
    script.remove();
    console.log('[HelioRa Injector] Protection script injected and removed');
  };
  
  console.log('[HelioRa Injector] Injection successful');
} catch (error) {
  console.error('[HelioRa Injector] Failed to inject:', error);
}
