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
    
    let intent = 'unknown';
    let confidence = 0;
    
    // Check for credential harvesting
    let otpCount = 0;
    let cardCount = 0;
    let upiCount = 0;
    let recoveryCount = 0;
    let urgentCount = 0;
    
    this.fraudPatterns.otp.forEach(pattern => {
      if (fullText.includes(pattern)) otpCount++;
    });
    
    this.fraudPatterns.card.forEach(pattern => {
      if (fullText.includes(pattern)) cardCount++;
    });
    
    this.fraudPatterns.upi.forEach(pattern => {
      if (fullText.includes(pattern)) upiCount++;
    });
    
    this.fraudPatterns.recovery.forEach(pattern => {
      if (fullText.includes(pattern)) recoveryCount++;
    });
    
    this.fraudPatterns.urgent.forEach(pattern => {
      if (fullText.includes(pattern)) urgentCount++;
    });
    
    // Classify intent
    if (cardCount >= 2) {
      intent = 'Payment Credential Harvesting';
      confidence = Math.min(95, cardCount * 30);
      this.fraudScore += 70;
      this.detectedThreats.push('🚨 CRITICAL: Page is requesting credit/debit card details');
    }
    
    if (upiCount >= 1) {
      intent = 'UPI PIN Harvesting';
      confidence = Math.min(95, upiCount * 40);
      this.fraudScore += 80;
      this.detectedThreats.push('🚨 CRITICAL: Page is asking for UPI PIN (NEVER share this!)');
    }
    
    if (recoveryCount >= 1) {
      intent = 'Crypto Wallet Theft';
      confidence = 95;
      this.fraudScore += 90;
      this.detectedThreats.push('🚨 CRITICAL: Page is requesting wallet recovery phrase');
    }
    
    if (otpCount >= 2 && urgentCount >= 1) {
      intent = 'Account Takeover Scam';
      confidence = Math.min(90, (otpCount + urgentCount) * 20);
      this.fraudScore += 60;
      this.detectedThreats.push('⚠️ WARNING: Urgent OTP request detected - possible account takeover');
    }
    
    if (intent !== 'unknown') {
      console.log(`[HelioRa Fraud] INTENT DETECTED: ${intent} (${confidence}% confidence)`);
    }
    
    return { intent, confidence };
  }

  detectFakeBrand() {
    const domain = this.domain;
    const pageText = document.body.innerText.toLowerCase();
    
    // Check each legitimate brand
    for (const [brand, data] of Object.entries(this.legitimateBrands)) {
      // Check if page mentions the brand
      if (pageText.includes(brand)) {
        // Check if domain matches
        const isLegitimate = data.domains.some(legit => domain.endsWith(legit) || domain === legit);
        
        if (!isLegitimate) {
          // Check for logo/visual impersonation
          const hasLogo = this.findBrandLogo(brand);
          const hasColorScheme = this.detectColorScheme(data.colors);
          
          if (hasLogo || hasColorScheme) {
            this.fraudScore += 85;
            this.detectedThreats.push(
              `🎭 BRAND IMPERSONATION: This page imitates ${brand.toUpperCase()} but is hosted on "${domain}" (not official)`
            );
            console.log(`[HelioRa Fraud] Fake ${brand} detected!`);
          }
        }
      }
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
      console.log('[HelioRa Fraud] Payment page detected - activating safe tunnel');
      
      // Monitor for suspicious behavior
      this.activatePaymentSandbox();
    }
  }

  activatePaymentSandbox() {
    // Prevent new iframes during payment
    const originalCreateElement = document.createElement;
    document.createElement = function(tagName) {
      if (tagName.toLowerCase() === 'iframe') {
        console.log('[HelioRa Fraud] BLOCKED: Iframe creation during payment');
        throw new Error('HelioRa: Iframe blocked during payment for security');
      }
      return originalCreateElement.apply(document, arguments);
    };
    
    // Warn user
    this.detectedThreats.push('🔒 SAFE PAYMENT MODE: HelioRa has secured this payment page');
  }

  detectSuspiciousIframes() {
    const iframes = document.querySelectorAll('iframe');
    
    iframes.forEach(iframe => {
      const src = iframe.src || '';
      const style = window.getComputedStyle(iframe);
      
      // Hidden iframe
      if (style.display === 'none' || style.visibility === 'hidden' || 
          parseInt(style.width) <= 1 || parseInt(style.height) <= 1) {
        this.fraudScore += 40;
        this.detectedThreats.push('⚠️ Hidden iframe detected - possible data harvesting');
      }
      
      // Cross-origin iframe
      try {
        const iframeDomain = new URL(src).hostname;
        if (iframeDomain !== this.domain) {
          console.log('[HelioRa Fraud] Cross-origin iframe:', iframeDomain);
        }
      } catch (err) {}
    });
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
      <div style="font-size: 64px; margin-bottom: 20px;">🚨</div>
      <h1 style="color: #F44336; font-size: 28px; margin-bottom: 20px;">FRAUD DETECTED</h1>
      <p style="font-size: 16px; color: #333; margin-bottom: 20px; line-height: 1.6;">
        <strong>HelioRa has detected ${this.detectedThreats.length} fraud indicator(s) on this page.</strong>
      </p>
      <div style="text-align: left; background: #f5f5f5; padding: 20px; border-radius: 8px; margin-bottom: 20px;">
        ${this.detectedThreats.map(threat => `<p style="margin: 10px 0; color: #d32f2f;">• ${threat}</p>`).join('')}
      </div>
      <div style="display: flex; gap: 15px; justify-content: center;">
        <button id="heliora-leave" style="
          flex: 1;
          padding: 15px 30px;
          background: #F44336;
          color: white;
          border: none;
          border-radius: 8px;
          font-size: 16px;
          font-weight: bold;
          cursor: pointer;
        ">🛡️ Leave This Site</button>
        <button id="heliora-continue" style="
          flex: 1;
          padding: 15px 30px;
          background: #ccc;
          color: #666;
          border: none;
          border-radius: 8px;
          font-size: 16px;
          font-weight: bold;
          cursor: pointer;
        ">Continue (Risky)</button>
      </div>
      <p style="font-size: 12px; color: #999; margin-top: 20px;">Protected by HelioRa Security</p>
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
