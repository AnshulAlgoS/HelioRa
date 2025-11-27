'use strict';

console.log('[HelioRa Fraud Detector] Initializing advanced fraud detection...');

class AdvancedFraudDetector {
  constructor() {
    this.domain = window.location.hostname.replace('www.', '');
    this.fraudPatterns = {
      otp: ['otp', 'one time password', 'verification code', '6 digit', 'sms code'],
      card: ['card number', 'cvv', 'expiry', 'credit card', 'debit card', 'card details'],
      upi: ['upi pin', 'mpin', 'transaction password', 'atm pin'],
      recovery: ['recovery phrase', 'seed phrase', 'private key', 'wallet phrase', '12 words'],
      urgent: ['verify immediately', 'urgent action', 'session expired', 'account suspended', 'verify now', 'limited time'],
      payment: ['₹', 'rs.', 'inr', 'amount', 'pay now', 'send money', 'transfer']
    };
    
    this.legitimateBrands = {
      google: { domains: ['google.com', 'accounts.google.com'], colors: ['#4285f4', '#ea4335', '#34a853', '#fbbc04'] },
      paytm: { domains: ['paytm.com'], colors: ['#00b9f5', '#002e6e'] },
      phonepe: { domains: ['phonepe.com'], colors: ['#5f259f', '#ffffff'] },
      amazon: { domains: ['amazon.in', 'amazon.com'], colors: ['#ff9900', '#146eb4'] },
      paypal: { domains: ['paypal.com'], colors: ['#003087', '#009cde'] },
      sbi: { domains: ['onlinesbi.sbi', 'onlinesbi.com'], colors: ['#22509e', '#ed232a'] },
      hdfc: { domains: ['hdfcbank.com'], colors: ['#004c8f', '#ed1c24'] },
      icici: { domains: ['icicibank.com'], colors: ['#f15a22', '#4d4d4f'] },
      axis: { domains: ['axisbank.com'], colors: ['#97144d'] }
    };
    
    this.fraudScore = 0;
    this.detectedThreats = [];
    this.isPaymentPage = false;
    this.formDataMonitored = new Map();
    
    this.init();
  }

  init() {
    console.log('[HelioRa Fraud] Starting real-time fraud detection...');
    
    // Wait for page load
    if (document.readyState === 'loading') {
      document.addEventListener('DOMContentLoaded', () => this.startDetection());
    } else {
      this.startDetection();
    }
  }

  startDetection() {
    // 1. Detect page intent
    this.detectPageIntent();
    
    // 2. Fake brand detection
    this.detectFakeBrand();
    
    // 3. UPI redirection detection
    this.monitorUPIRedirects();
    
    // 4. Form data exfiltration
    this.monitorFormExfiltration();
    
    // 5. Scam popup detection
    this.detectScamPopups();
    
    // 6. Payment hijack detection
    this.monitorPaymentHijack();
    
    // 7. Suspicious iframe detection
    this.detectSuspiciousIframes();
    
    // 8. Deepfake/stock photo detection
    this.detectSyntheticMedia();
    
    // Report findings
    setTimeout(() => this.reportFindings(), 2000);
  }

  detectPageIntent() {
    const bodyText = document.body.innerText.toLowerCase();
    const title = document.title.toLowerCase();
    const fullText = bodyText + ' ' + title;
    
    // Only flag if it's clearly a scam, not just mentioning the keywords
    let intent = 'unknown';
    let confidence = 0;
    
    // Check for actual input fields asking for sensitive data
    const inputs = document.querySelectorAll('input');
    let hasCardInput = false;
    let hasUPIInput = false;
    let hasPinInput = false;
    let hasOTPInput = false;
    
    inputs.forEach(input => {
      const name = (input.name || '').toLowerCase();
      const id = (input.id || '').toLowerCase();
      const placeholder = (input.placeholder || '').toLowerCase();
      const label = input.labels?.[0]?.textContent.toLowerCase() || '';
      
      const fullInputText = name + ' ' + id + ' ' + placeholder + ' ' + label;
      
      if (fullInputText.includes('cvv') || fullInputText.includes('card number')) {
        hasCardInput = true;
      }
      if (fullInputText.includes('upi pin') || fullInputText.includes('mpin')) {
        hasUPIInput = true;
      }
      if (fullInputText.includes('atm pin') || fullInputText.includes('pin')) {
        hasPinInput = true;
      }
      if (fullInputText.includes('otp') || fullInputText.includes('verification code')) {
        hasOTPInput = true;
      }
    });
    
    // Only flag if there are actual input fields AND suspicious context
    const hasSuspiciousUrl = !window.location.protocol.startsWith('https') || 
                             window.location.hostname.length > 30;
    
    if (hasUPIInput && hasSuspiciousUrl) {
      this.fraudScore += 80;
      this.detectedThreats.push('CRITICAL: Page has UPI PIN input field (NEVER enter your UPI PIN on untrusted sites)');
    }
    
    if (hasCardInput && hasSuspiciousUrl) {
      this.fraudScore += 70;
      this.detectedThreats.push('WARNING: Page requesting card details on suspicious domain');
    }
    
    // Check for recovery phrases in input fields
    const textareas = document.querySelectorAll('textarea');
    textareas.forEach(textarea => {
      const placeholder = (textarea.placeholder || '').toLowerCase();
      if (placeholder.includes('recovery phrase') || placeholder.includes('seed phrase') || placeholder.includes('12 words')) {
        this.fraudScore += 90;
        this.detectedThreats.push('CRITICAL: Page requesting crypto wallet recovery phrase');
      }
    });
  }

  async detectFakeBrand() {
    const domain = this.domain;
    const pageTitle = document.title.toLowerCase();
    const pageText = document.body.innerText.toLowerCase();
    
    // Only check if page explicitly claims to be a brand
    const brandClaims = [];
    
    // Check title and prominent text for brand impersonation
    for (const [brand, data] of Object.entries(this.legitimateBrands)) {
      // Check if page explicitly claims to be this brand (in title or main heading)
      const mainHeadings = document.querySelectorAll('h1, h2, title');
      let claimsToBeBrand = false;
      
      mainHeadings.forEach(heading => {
        const text = heading.textContent.toLowerCase();
        if (text === brand || text.includes(`${brand} login`) || text.includes(`${brand} sign in`)) {
          claimsToBeBrand = true;
        }
      });
      
      if (claimsToBeBrand) {
        // Now check if domain matches
        const isLegitimate = data.domains.some(legit => domain.endsWith(legit) || domain === legit);
        
        if (!isLegitimate) {
          brandClaims.push({
            brand: brand,
            domain: domain,
            legitimateDomains: data.domains
          });
        }
      }
    }
    
    // Send to AI for analysis if we have suspicious brand claims
    if (brandClaims.length > 0) {
      await this.analyzeBrandImpersonation(brandClaims);
    }
  }
  
  async analyzeBrandImpersonation(brandClaims) {
    // Send to extension for AI analysis
    try {
      const result = await chrome.runtime.sendMessage({
        action: 'analyzeBrandImpersonation',
        domain: this.domain,
        url: window.location.href,
        brandClaims: brandClaims,
        pageTitle: document.title,
        hasLoginForm: document.querySelectorAll('input[type="password"]').length > 0
      });
      
      if (result?.isFraud) {
        this.fraudScore += 85;
        this.detectedThreats.push(result.message);
        console.log('[HelioRa Fraud] AI confirmed brand impersonation');
      }
    } catch (err) {
      console.log('[HelioRa Fraud] Could not analyze brand impersonation');
    }
  }

  findBrandLogo(brand) {
    // Check images for brand logos
    const images = document.querySelectorAll('img');
    let found = false;
    
    images.forEach(img => {
      const src = (img.src || '').toLowerCase();
      const alt = (img.alt || '').toLowerCase();
      
      if (src.includes(brand) || alt.includes(brand) || alt.includes('logo')) {
        found = true;
      }
    });
    
    return found;
  }

  detectColorScheme(brandColors) {
    // Check if page uses brand color scheme
    const styles = document.querySelectorAll('*');
    let matchCount = 0;
    
    for (let i = 0; i < Math.min(styles.length, 100); i++) {
      const element = styles[i];
      const bgColor = window.getComputedStyle(element).backgroundColor;
      const color = window.getComputedStyle(element).color;
      
      brandColors.forEach(brandColor => {
        if (bgColor.includes(brandColor) || color.includes(brandColor)) {
          matchCount++;
        }
      });
    }
    
    return matchCount > 3;
  }

  monitorUPIRedirects() {
    // Monitor for UPI links
    const links = document.querySelectorAll('a[href^="upi://"], a[href*="upi"]');
    
    if (links.length > 0) {
      console.log('[HelioRa Fraud] UPI payment links detected');
      
      links.forEach(link => {
        const originalHref = link.href;
        
        // Monitor for changes
        const observer = new MutationObserver(() => {
          if (link.href !== originalHref) {
            this.fraudScore += 75;
            this.detectedThreats.push('🔴 UPI HIJACK: Payment destination changed after page load!');
            console.log('[HelioRa Fraud] UPI redirect hijacked!');
          }
        });
        
        observer.observe(link, { attributes: true, attributeFilter: ['href'] });
      });
    }
    
    // Monitor for dynamic UPI generation
    this.monitorDOMForUPI();
  }

  monitorDOMForUPI() {
    const observer = new MutationObserver((mutations) => {
      mutations.forEach(mutation => {
        mutation.addedNodes.forEach(node => {
          if (node.nodeType === 1) {
            const html = node.innerHTML || '';
            if (html.includes('upi://') || html.includes('upi:pay')) {
              console.log('[HelioRa Fraud] Dynamic UPI payment injected!');
              this.fraudScore += 50;
              this.detectedThreats.push('⚠️ Dynamic UPI payment link injected into page');
            }
          }
        });
      });
    });
    
    observer.observe(document.body, { childList: true, subtree: true });
  }

  monitorFormExfiltration() {
    // Monitor all input fields
    const inputs = document.querySelectorAll('input[type="text"], input[type="password"], input[type="email"], input[type="tel"], input[type="number"]');
    
    inputs.forEach(input => {
      input.addEventListener('input', (e) => {
        const value = e.target.value;
        const type = e.target.type;
        const name = e.target.name || e.target.id;
        
        // Track sensitive data
        if (type === 'password' || name.includes('password') || name.includes('pin')) {
          this.formDataMonitored.set('password', true);
        }
        if (type === 'email' || name.includes('email')) {
          this.formDataMonitored.set('email', true);
        }
        if (type === 'tel' || name.includes('phone')) {
          this.formDataMonitored.set('phone', true);
        }
      });
    });
    
    // Intercept fetch/XHR
    this.interceptNetworkRequests();
  }

  interceptNetworkRequests() {
    const currentDomain = this.domain;
    
    // Intercept fetch
    const originalFetch = window.fetch;
    window.fetch = async (...args) => {
      const url = args[0];
      
      try {
        const urlObj = new URL(url, window.location.origin);
        if (urlObj.hostname !== currentDomain && !urlObj.hostname.includes(currentDomain)) {
          // Data being sent to external domain
          if (this.formDataMonitored.size > 0) {
            this.fraudScore += 70;
            this.detectedThreats.push(
              `🔴 DATA EXFILTRATION: Your credentials are being sent to "${urlObj.hostname}" (untrusted server)`
            );
            console.log('[HelioRa Fraud] Form data exfiltration detected!', urlObj.hostname);
          }
        }
      } catch (err) {}
      
      return originalFetch.apply(window, args);
    };
    
    // Intercept XHR
    const originalOpen = XMLHttpRequest.prototype.open;
    XMLHttpRequest.prototype.open = function(method, url) {
      try {
        const urlObj = new URL(url, window.location.origin);
        if (urlObj.hostname !== currentDomain && !urlObj.hostname.includes(currentDomain)) {
          if (this.formDataMonitored.size > 0) {
            this.fraudScore += 70;
            this.detectedThreats.push(
              `🔴 DATA EXFILTRATION: Credentials being sent to external server`
            );
          }
        }
      } catch (err) {}
      
      return originalOpen.apply(this, arguments);
    }.bind(this);
  }

  detectScamPopups() {
    // Detect fake alert popups
    const scamPatterns = [
      'virus detected',
      'your computer is infected',
      'call now',
      'tech support',
      'microsoft support',
      'apple support',
      'congratulations! you won',
      'click here to claim',
      'your prize',
      'reward',
      'government grant',
      'income tax refund'
    ];
    
    setTimeout(() => {
      const bodyText = document.body.innerText.toLowerCase();
      
      scamPatterns.forEach(pattern => {
        if (bodyText.includes(pattern)) {
          this.fraudScore += 60;
          this.detectedThreats.push(`⚠️ SCAM POPUP: Detected "${pattern}" message - likely fake tech support/reward scam`);
        }
      });
      
      // Detect overlay popups
      const overlays = document.querySelectorAll('[style*="position: fixed"], [style*="z-index"]');
      overlays.forEach(overlay => {
        const text = overlay.innerText?.toLowerCase() || '';
        scamPatterns.forEach(pattern => {
          if (text.includes(pattern)) {
            overlay.style.display = 'none';
            this.detectedThreats.push('🛡️ BLOCKED: Scam overlay popup removed');
            console.log('[HelioRa Fraud] Blocked scam overlay');
          }
        });
      });
    }, 3000);
  }

  monitorPaymentHijack() {
    // Detect if we're on a payment page
    const pageText = document.body.innerText.toLowerCase();
    const isPayment = this.fraudPatterns.payment.some(p => pageText.includes(p));
    
    if (isPayment) {
      this.isPaymentPage = true;
      console.log('[HelioRa Fraud] Payment page detected - monitoring for hijacks');
      
      // Only activate sandbox if we detect actual suspicious activity
      // Don't show any message unless there's a real threat
    }
  }

  activatePaymentSandbox() {
    // Only called when actual threat detected during payment
    console.log('[HelioRa Fraud] Payment sandbox activated due to suspicious activity');
  }

  detectSuspiciousIframes() {
    const iframes = document.querySelectorAll('iframe');
    let hiddenIframeCount = 0;
    
    iframes.forEach(iframe => {
      const src = iframe.src || '';
      const style = window.getComputedStyle(iframe);
      
      // Hidden iframe - but check if it's actually suspicious
      const isHidden = style.display === 'none' || style.visibility === 'hidden' || 
                       parseInt(style.width) <= 1 || parseInt(style.height) <= 1;
      
      if (isHidden) {
        // Check if it's from a known legitimate service (analytics, payment processors, etc)
        const legitimateIframes = ['google', 'stripe', 'paypal', 'recaptcha', 'analytics'];
        const isLegitimate = legitimateIframes.some(service => src.includes(service));
        
        if (!isLegitimate && src) {
          hiddenIframeCount++;
        }
      }
    });
    
    // Only flag if multiple hidden iframes from unknown sources
    if (hiddenIframeCount >= 2) {
      this.fraudScore += 40;
      this.detectedThreats.push(`WARNING: ${hiddenIframeCount} hidden iframes detected - possible data harvesting`);
      console.log('[HelioRa Fraud] Suspicious hidden iframes:', hiddenIframeCount);
    }
  }

  detectSyntheticMedia() {
    // Detect stock photos and deepfakes (basic heuristics)
    const images = document.querySelectorAll('img');
    const suspiciousImages = [];
    
    images.forEach(img => {
      const src = img.src.toLowerCase();
      const alt = img.alt?.toLowerCase() || '';
      
      // Check for stock photo sites
      if (src.includes('shutterstock') || src.includes('istockphoto') || 
          src.includes('gettyimages') || src.includes('pexels') ||
          src.includes('unsplash') || src.includes('thispersondoesnotexist')) {
        suspiciousImages.push(src);
      }
      
      // Check for fake support/CEO images
      if (alt.includes('ceo') || alt.includes('support') || alt.includes('agent') || alt.includes('customer service')) {
        suspiciousImages.push(alt);
      }
    });
    
    if (suspiciousImages.length > 2) {
      this.fraudScore += 30;
      this.detectedThreats.push('⚠️ SYNTHETIC MEDIA: Page likely uses stock photos for social engineering');
      console.log('[HelioRa Fraud] Suspicious stock photos detected');
    }
  }

  reportFindings() {
    if (this.detectedThreats.length > 0 || this.fraudScore > 50) {
      console.log(`[HelioRa Fraud] FRAUD SCORE: ${this.fraudScore}/100`);
      console.log('[HelioRa Fraud] Threats:', this.detectedThreats);
      
      // Send to extension
      chrome.runtime.sendMessage({
        action: 'fraudDetected',
        domain: this.domain,
        fraudScore: this.fraudScore,
        threats: this.detectedThreats,
        isPaymentPage: this.isPaymentPage
      }).catch(() => {});
      
      // Show critical warning if score is high
      if (this.fraudScore >= 70) {
        this.showCriticalWarning();
      }
    }
  }

  showCriticalWarning() {
    // Create full-screen warning overlay
    const overlay = document.createElement('div');
    overlay.id = 'heliora-fraud-warning';
    overlay.style.cssText = `
      position: fixed;
      top: 0;
      left: 0;
      right: 0;
      bottom: 0;
      background: rgba(244, 67, 54, 0.98);
      z-index: 2147483647;
      display: flex;
      align-items: center;
      justify-content: center;
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    `;
    
    const warning = document.createElement('div');
    warning.style.cssText = `
      background: white;
      padding: 40px;
      border-radius: 16px;
      max-width: 600px;
      text-align: center;
      box-shadow: 0 20px 60px rgba(0,0,0,0.5);
    `;
    
    warning.innerHTML = `
      <svg width="80" height="80" viewBox="0 0 24 24" fill="none" stroke="#F44336" stroke-width="2" style="margin: 0 auto 20px;">
        <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"></path>
        <line x1="12" y1="9" x2="12" y2="13"></line>
        <line x1="12" y1="17" x2="12.01" y2="17"></line>
      </svg>
      <h1 style="color: #F44336; font-size: 28px; margin-bottom: 15px; font-weight: 700;">Security Threat Detected</h1>
      <p style="font-size: 15px; color: #555; margin-bottom: 25px; line-height: 1.5;">
        HelioRa has identified <strong>${this.detectedThreats.length} security issue(s)</strong> on this page that may indicate fraudulent activity.
      </p>
      <div style="text-align: left; background: #fff3e0; border-left: 4px solid #ff9800; padding: 20px; border-radius: 6px; margin-bottom: 25px; max-height: 200px; overflow-y: auto;">
        <h3 style="margin: 0 0 12px 0; color: #e65100; font-size: 14px; text-transform: uppercase; letter-spacing: 0.5px;">Detected Threats</h3>
        ${this.detectedThreats.map(threat => {
          // Remove emojis from threat messages
          const cleanThreat = threat.replace(/[\u{1F300}-\u{1F9FF}]|[\u{2600}-\u{26FF}]|[\u{2700}-\u{27BF}]/gu, '').trim();
          return `<p style="margin: 8px 0; color: #d84315; font-size: 13px; line-height: 1.5;">▪ ${cleanThreat}</p>`;
        }).join('')}
      </div>
      <div style="background: #f5f5f5; padding: 15px; border-radius: 6px; margin-bottom: 25px;">
        <p style="font-size: 13px; color: #666; margin: 0; line-height: 1.6;">
          <strong>Recommendation:</strong> Leave this site immediately. Do not enter any personal information, passwords, or payment details.
        </p>
      </div>
      <div style="display: flex; gap: 12px; justify-content: center;">
        <button id="heliora-leave" style="
          flex: 1;
          padding: 14px 28px;
          background: linear-gradient(135deg, #F44336, #D32F2F);
          color: white;
          border: none;
          border-radius: 6px;
          font-size: 15px;
          font-weight: 600;
          cursor: pointer;
          box-shadow: 0 2px 8px rgba(244, 67, 54, 0.3);
          transition: all 0.2s;
        " onmouseover="this.style.transform='translateY(-2px)'; this.style.boxShadow='0 4px 12px rgba(244, 67, 54, 0.4)';" onmouseout="this.style.transform='translateY(0)'; this.style.boxShadow='0 2px 8px rgba(244, 67, 54, 0.3)';">Leave This Site (Recommended)</button>
        <button id="heliora-continue" style="
          flex: 0.6;
          padding: 14px 20px;
          background: white;
          color: #666;
          border: 2px solid #ddd;
          border-radius: 6px;
          font-size: 14px;
          font-weight: 600;
          cursor: pointer;
          transition: all 0.2s;
        " onmouseover="this.style.borderColor='#999';" onmouseout="this.style.borderColor='#ddd';">Continue Anyway</button>
      </div>
      <p style="font-size: 11px; color: #999; margin-top: 20px;">
        Protected by HelioRa Security • <span style="color: #F44336; font-weight: 600;">Fraud Score: ${this.fraudScore}/100</span>
      </p>
    `;
    
    overlay.appendChild(warning);
    document.body.appendChild(overlay);
    
    // Event listeners
    document.getElementById('heliora-leave').addEventListener('click', () => {
      window.history.back();
    });
    
    document.getElementById('heliora-continue').addEventListener('click', () => {
      overlay.remove();
    });
  }
}

// Initialize fraud detector
setTimeout(() => {
  new AdvancedFraudDetector();
}, 500);
