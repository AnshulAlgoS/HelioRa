'use strict';

console.log('[HelioRa Injector] Starting surveillance protection injection...');

chrome.storage.local.get(['settings'], (result) => {
  const settings = result.settings || {};
  const settingsScript = document.createElement('script');
  settingsScript.textContent = `window.__HELIORA_SETTINGS__ = ${JSON.stringify(settings)};`;
  (document.head || document.documentElement).prepend(settingsScript);
  settingsScript.remove();

  try {
    const script = document.createElement('script');
    script.src = chrome.runtime.getURL('surveillance_protection.js');
    script.type = 'text/javascript';
    (document.head || document.documentElement).prepend(script);
    
    script.onload = () => {
      script.remove();
      console.log('[HelioRa Injector] Protection script injected and removed');
    };
    
    console.log('[HelioRa Injector] Injection successful');
  } catch (error) {
    console.error('[HelioRa Injector] Failed to inject:', error);
  }
});
chrome.storage.onChanged.addListener((changes, namespace) => {
  if (namespace === 'local' && changes.settings) {
    window.postMessage({
      type: 'HELIORA_SETTINGS_UPDATE',
      settings: changes.settings.newValue
    }, '*');
  }
});
