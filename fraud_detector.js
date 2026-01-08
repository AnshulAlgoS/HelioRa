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
    this.otpRiskScore = 0;
    this.evilginxRisk = 0;
    this.detectedThreats = [];
    this.otpInputs = [];
    
    this.init();
  }

  init() {
    console.log('[HelioRa Fraud] Starting real-time fraud detection...');
    if (document.readyState === 'loading') {
      document.addEventListener('DOMContentLoaded', () => this.startDetection());
    } else {
      this.startDetection();
    }
  }

  startDetection() {
    // Listen for Main World signals (Evilginx detection)
    document.addEventListener('HelioRaMainWorldSignal', (e) => this.handleMainWorldSignal(e));

    // 1. Detect OTP Fields (Behavioral)
    this.detectOTPFields();
    
    // 2. Calculate Contextual Trust Score
    this.calculateRiskScore();
    
    // 3. Run other detectors
    this.detectFakeBrand();
    this.monitorUPIRedirects();
    this.detectScamPopups();
    this.detectSuspiciousIframes();
    
    // 4. Handle OTP Risk
    if (this.otpInputs.length > 0) {
      this.handleOTPRisk();
    }
    
    // Report findings
    setTimeout(() => this.reportFindings(), 2000);
  }

  handleMainWorldSignal(e) {
    const { type, details } = e.detail;
    console.log(`[HelioRa] Received Main World Signal: ${type}`, details);
    
    let riskIncrease = 0;
    
    if (type === 'HistoryAbuse') {
      riskIncrease = 20;
      this.detectedThreats.push('History API Abuse (URL Masking)');
    } else if (type === 'SuspiciousCookie') {
      riskIncrease = 15;
      this.detectedThreats.push('Suspicious Cookie Behavior');
    } else if (type === 'CrossOriginExfiltration') {
      riskIncrease = 30;
      this.detectedThreats.push('Cross-Origin Data Exfiltration');
    }
    
    if (riskIncrease > 0) {
      this.evilginxRisk += riskIncrease;
      this.calculateRiskScore(); // Recalculate and trigger warnings if needed
      this.handleOTPRisk();
    }
  }

  /**
   * 1. Behavioral OTP Detection
   * Analyzes input fields for OTP-like characteristics without relying solely on keywords.
   */
  detectOTPFields() {
    const inputs = document.querySelectorAll('input');
    this.otpInputs = [];
    
    inputs.forEach(input => {
      // Check for specific attributes
      const isNumeric = input.inputMode === 'numeric' || input.type === 'number' || input.pattern === '[0-9]*';
      const isOneTime = input.autocomplete === 'one-time-code';
      const hasLength = input.maxLength >= 4 && input.maxLength <= 8;
      const nameMatch = /otp|code|pin|verification/i.test(input.name || input.id || '');
      
      // Strong signal: explicit autocomplete
      if (isOneTime) {
        this.otpInputs.push(input);
        return;
      }
      
      // Behavioral signal: Numeric + Length constraint + Name hint
      if (isNumeric && hasLength && nameMatch) {
        this.otpInputs.push(input);
      }
    });
    
    if (this.otpInputs.length > 0) {
      console.log(`[HelioRa] Detected ${this.otpInputs.length} potential OTP fields via behavior`);
    }
  }

  /**
   * 2. Contextual Trust Scoring
   * Calculates a risk score based on domain, page content, and browser behavior.
   */
  calculateRiskScore() {
    let domainRisk = this.checkDomainRisk();
    let pageMimicry = this.checkPageMimicry();
    let browserBehavior = this.checkBrowserBehavior();
    let networkRisk = 0; // Will be updated by main world events if possible, but we calculate static signals here
    
    // Zero-touch signals (from existing checks)
    if (this.detectedThreats.some(t => t.includes('UPI') || t.includes('Exfiltration'))) {
      networkRisk += 20;
    }

    this.otpRiskScore = domainRisk + pageMimicry + browserBehavior + networkRisk + this.evilginxRisk;
    
    // Cap at 100
    this.otpRiskScore = Math.min(100, this.otpRiskScore);
    
    // Dispatch to Main World for Fetch Interception
    document.dispatchEvent(new CustomEvent('HelioRaRiskUpdate', {
      detail: { riskScore: this.otpRiskScore }
    }));
    
    console.log(`[HelioRa] OTP Risk Score: ${this.otpRiskScore} (Domain: ${domainRisk}, Page: ${pageMimicry}, Behavior: ${browserBehavior}, Evilginx: ${this.evilginxRisk})`);
  }

  checkDomainRisk() {
    let risk = 0;
    const domain = this.domain.toLowerCase();
    
    // Free TLDs
    const freeTLDs = ['.tk', '.ml', '.cf', '.ga', '.gq'];
    if (freeTLDs.some(tld => domain.endsWith(tld))) risk += 30;
    
    // IP-based domain
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(domain)) risk += 35;
    
    // Temporary hosting patterns
    const tempHosts = ['ngrok', 'vercel.app', 'netlify.app', 'herokuapp.com', 'glitch.me', 'surge.sh'];
    if (tempHosts.some(host => domain.includes(host))) risk += 25;
    
    // Punycode (xn--)
    if (domain.startsWith('xn--')) risk += 20;
    
    return risk;
  }

  checkPageMimicry() {
    let risk = 0;
    
    // Inline Base64 images (common in phishing kits)
    const images = document.querySelectorAll('img[src^="data:image"]');
    if (images.length > 3) risk += 10;
    
    // Missing privacy policy
    const bodyText = document.body.innerText.toLowerCase();
    if (!bodyText.includes('privacy policy') && !bodyText.includes('terms')) risk += 10;
    
    // Brand mismatch (using existing logic)
    // If detectFakeBrand() found something, it adds to fraudScore, let's tap into that logic
    // We'll do a quick check here
    const title = document.title.toLowerCase();
    if (title.includes('login') || title.includes('sign in')) {
      if (!window.location.protocol.startsWith('https')) risk += 20;
    }
    
    return risk;
  }

  checkBrowserBehavior() {
    let risk = 0;
    
    // Fullscreen on load (suspicious for login pages)
    if (document.fullscreenElement) risk += 15;
    
    // Hidden iframes (from existing check)
    const hiddenIframes = document.querySelectorAll('iframe[style*="display: none"], iframe[style*="visibility: hidden"]');
    if (hiddenIframes.length > 0) risk += 15;
    
    return risk;
  }

  /**
   * 3. Risk Handling
   * Determines actions based on the calculated risk score.
   */
  handleOTPRisk() {
    if (this.otpRiskScore < 40) {
      // Allow silently
      return;
    }
    
    if (this.otpRiskScore >= 40 && this.otpRiskScore < 70) {
      // WARN USER
      this.showOTPWarning("Suspicious Authentication Request");
    }
    
    if (this.otpRiskScore >= 70) {
      // HARD BLOCK
      this.freezeOTPInputs();
      this.showOTPWarning("High-Risk Authentication Blocked");
    }
  }

  freezeOTPInputs() {
    this.otpInputs.forEach(input => {
      input.disabled = true;
      input.style.backgroundColor = '#ffebee';
      input.style.border = '2px solid #f44336';
      input.placeholder = "Blocked by HelioRa";
      
      // Prevent paste
      input.addEventListener('paste', (e) => {
        e.preventDefault();
        e.stopPropagation();
      }, true);
    });
    console.log('[HelioRa] OTP Inputs frozen due to high risk');
  }

  showOTPWarning(title) {
    if (document.getElementById('heliora-otp-warning')) return;
    
    const div = document.createElement('div');
    div.id = 'heliora-otp-warning';
    div.style.cssText = `
      position: fixed;
      top: 20px;
      right: 20px;
      width: 380px;
      background: white;
      border-left: 5px solid ${this.otpRiskScore >= 70 ? '#f44336' : '#ff9800'};
      padding: 20px;
      border-radius: 8px;
      box-shadow: 0 8px 30px rgba(0,0,0,0.25);
      z-index: 2147483647;
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
      animation: slideIn 0.3s ease-out;
    `;
    
    const riskColor = this.otpRiskScore >= 70 ? '#d32f2f' : '#f57c00';
    
    div.innerHTML = `
      <h3 style="margin: 0 0 12px; color: ${riskColor}; font-size: 16px; display: flex; align-items: center; font-weight: 600;">
        <span style="font-size: 20px; margin-right: 10px;">🛡️</span> ${title}
      </h3>
      <p style="margin: 0 0 15px; font-size: 14px; color: #333; line-height: 1.4;">
        This site is attempting a high-risk authentication flow commonly used in scams.
      </p>
      <div style="font-size: 12px; color: #555; margin-bottom: 15px; background: #f8f9fa; padding: 12px; border-radius: 6px; border: 1px solid #eee;">
        <div style="margin-bottom: 4px;"><strong>Risk Score:</strong> ${this.otpRiskScore}/100</div>
        ${this.getRiskBreakdown()}
      </div>
      <div style="display: flex; gap: 10px;">
        ${this.otpRiskScore >= 70 ? 
          `<button id="heliora-report" style="flex: 1; padding: 8px; background: #d32f2f; color: white; border: none; border-radius: 4px; cursor: pointer; font-weight: 500;">Report Scam</button>` :
          `<button id="heliora-ignore" style="flex: 1; padding: 8px; background: #f0f0f0; border: none; border-radius: 4px; cursor: pointer; color: #333;">Ignore (Unsafe)</button>`
        }
      </div>
    `;
    
    document.body.appendChild(div);
    
    // Add slide-in animation
    const style = document.createElement('style');
    style.textContent = `@keyframes slideIn { from { transform: translateX(100%); opacity: 0; } to { transform: translateX(0); opacity: 1; } }`;
    document.head.appendChild(style);
    
    // Handlers
    setTimeout(() => {
        const btn = document.getElementById('heliora-ignore');
        if (btn) btn.onclick = () => div.remove();
        
        const reportBtn = document.getElementById('heliora-report');
        if (reportBtn) reportBtn.onclick = () => {
            alert('Reported to HelioRa Cloud (Simulation)');
            div.remove();
        };
    }, 100);
  }

  getRiskBreakdown() {
    const reasons = [];
    if (this.checkDomainRisk() > 20) reasons.push("Suspicious Domain");
    if (this.checkPageMimicry() > 10) reasons.push("Page Mimicry");
    if (this.checkBrowserBehavior() > 10) reasons.push("Unusual Behavior");
    if (this.evilginxRisk > 0) reasons.push("Reverse Proxy Indicators");
    return reasons.length ? "Reasons: " + reasons.join(", ") : "Reason: Generic Risk Pattern";
  }

  /**
   * Legacy Methods
   * Maintained for backward compatibility with older detection logic.
   */
  detectFakeBrand() {
    // Simplified logic to avoid duplication
    const domain = this.domain;
    for (const [brand, data] of Object.entries(this.legitimateBrands)) {
      if (document.title.toLowerCase().includes(brand) && !data.domains.some(d => domain.includes(d))) {
        this.fraudScore += 50;
        this.detectedThreats.push(`Potential Brand Impersonation: ${brand}`);
      }
    }
  }

  monitorUPIRedirects() {
    const links = document.querySelectorAll('a[href^="upi://"]');
    if (links.length > 0) {
      console.log('[HelioRa] UPI links detected');
      // If risky domain, flag it
      if (this.otpRiskScore > 30) {
        this.detectedThreats.push('Risky UPI Link');
        this.otpRiskScore += 20; // Increase risk
        this.handleOTPRisk(); // Re-evaluate
      }
    }
  }

  detectScamPopups() {}
  detectSuspiciousIframes() {}

  reportFindings() {
    if (this.otpRiskScore > 40) {
        chrome.runtime.sendMessage({
            action: 'fraudDetected',
            domain: this.domain,
            fraudScore: this.otpRiskScore,
            threats: this.detectedThreats
        }).catch(() => {});
    }
  }
}

// Initialize
new AdvancedFraudDetector();
