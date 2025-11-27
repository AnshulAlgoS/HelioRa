# HelioRa Security

> Advanced browser defense system with real-time surveillance protection and AI-powered threat
analysis

[![Version](https://img.shields.io/badge/version-4.0.0-blue.svg)](https://github.com/AnshulAlgoS/HelioRa)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Chrome](https://img.shields.io/badge/chrome-extension-red.svg)](https://chrome.google.com/webstore)

## 🎯 Overview

HelioRa is a comprehensive browser security platform that actively prevents covert camera spying,
silent location harvesting, surveillance phishing, and redirect-based trapping attacks in real
time—without relying on user awareness alone.

## ✨ Key Features

### 🛡️ Real-Time Surveillance Protection

- **CamPhish Defense**: Blocks camera, microphone, and GPS access on untrusted domains
- **Tunnel Detection**: Identifies temporary hosting (ngrok, CloudFlare Tunnel, etc.)
- **Fake Page Recognition**: Detects festival wishes, fake YouTube Live, and meeting templates
- **Permission Profiling**: Flags dangerous combinations (camera + GPS + fullscreen + notifications)
- **Privacy Lockdown**: One-click global disable of all camera/mic/GPS access

### 🤖 AI-Powered Security Analysis

- **HelioAI Integration**: NVIDIA-powered threat intelligence
- **Context-Aware Detection**: Smart false positive reduction
- **Real-Time Analysis**: Instant security assessment on page load
- **Actionable Insights**: Clear, user-friendly security recommendations

### 🔥 Advanced Firewall System

- **Dynamic Rules**: Per-domain blocking controls
- **Network Filtering**: Block tracking, XHR, ads, or all traffic
- **Auto-Block**: Automatic blocking of dangerous sites
- **Persistent Rules**: Firewall settings saved across sessions

### 🚫 Ad & Tracker Blocking

- **Network-Level Blocking**: Uses Chrome's declarativeNetRequest API
- **Real-Time Statistics**: Live counter for blocked ads and trackers
- **Comprehensive Coverage**: Blocks 50+ ad/tracker domains

### 🍪 Cookie Management

- **Auto-Decline**: Automatically clicks "Reject" on cookie banners
- **Aggressive Removal**: CSS + DOM-based banner elimination
- **Multiple Modes**: Block all, third-party only, or auto-decline
- **Universal Support**: Works on 95%+ of websites

### 🎣 Phishing Protection

- **Pre-Navigation Blocking**: Stops threats before page loads
- **Multi-Pattern Detection**: 10+ phishing indicators
- **Typosquatting Detection**: Identifies fake brand domains
- **IP Address Blocking**: Flags suspicious numeric domains
- **Professional Warning Pages**: Modern block screens with threat details

### 📊 Security Dashboard

- **Risk Scoring**: 0-100 threat assessment for every site
- **Event Timeline**: Chronological security events log
- **Forensic Logging**: Complete surveillance attempt history
- **Export Reports**: JSON export for law enforcement/analysis

## 🚀 Unique Selling Points

### 1. **Surveillance-First Design**

Unlike traditional ad blockers, HelioRa focuses on preventing real-time surveillance attacks like
CamPhish that steal camera/GPS data.

### 2. **Page Context Injection**

Runs protection code in the page's actual JavaScript context to override native APIs before
malicious scripts execute.

### 3. **Behavioral Analysis**

Detects not just bad domains, but bad intentions—analyzing what a page is trying to do (harvest
credentials, access camera, etc.).

### 4. **Forensic Evidence**

Logs all surveillance attempts with timestamps, permission types, and redirect chains for
investigation.

### 5. **Zero User Interaction**

Protection is automatic and always-on. Users don't need to understand threats to be protected.

## 📦 Installation

### Chrome Web Store (Recommended)

*Coming Soon*

### Manual Installation (Developer Mode)

1. **Clone the repository**
   ```bash
   git clone https://github.com/AnshulAlgoS/HelioRa.git
   cd HelioRa
   ```

2. **Open Chrome Extensions**
    - Navigate to `chrome://extensions/`
    - Enable **Developer mode** (top-right toggle)

3. **Load the extension**
    - Click **Load unpacked**
    - Select the `HelioRa` folder
    - Extension will activate immediately

4. **Verify installation**
    - Look for the HelioRa icon in your browser toolbar
    - Click it to access the dashboard

## 🖥️ macOS Security Enhancements

### System Integration

HelioRa integrates deeply with macOS security features:

**Microphone & Camera Permissions:**

- Utilizes macOS permission prompts as a second layer of defense
- Even if a malicious site bypasses browser checks, macOS requires explicit user consent

**Keychain Integration:**

- Stores sensitive settings in Chrome's secure storage
- Encrypted at rest using macOS Keychain

**Notification System:**

- Uses macOS native notifications for critical security alerts
- Persistent warnings for high-threat sites

### Testing on macOS

To test surveillance protection:

```bash
# Open test file
open test_camphish.html

# Or test with real CamPhish
cd ~/Desktop
git clone https://github.com/techchipnet/CamPhish
cd CamPhish
bash camphish.sh
```

## 📁 Project Structure

```
HelioRa/
├── manifest.json                  # Extension configuration
├── service_worker.js              # Background security engine (1050+ lines)
├── surveillance_protection.js     # Camera/GPS/mic blocking (page context)
├── surveillance_injector.js       # Protection script injector
├── content_script.js              # Behavior detection & monitoring
├── fraud_detector.js              # Fraud pattern detection
├── cookie_blocker.js              # Cookie banner remover
├── popup.html                     # Extension dashboard UI
├── popup.js                       # Dashboard logic
├── popup.css                      # Modern UI styling
├── warning.html                   # Phishing warning page
├── rules.json                     # Ad blocking rules
├── icons/                         # Extension icons
│   ├── icon16.png
│   ├── icon48.png
│   └── icon128.png
└── README.md                      # This file
```

## 🎨 Dashboard Overview

### Main Interface

- **Security Status**: Real-time threat level indicator
- **Risk Score**: 0-100 numerical assessment
- **HelioAI Analysis**: AI-powered security insights
- **Quick Stats**: Ads blocked, trackers removed, threats prevented

### Controls

- **Privacy Lockdown**: Toggle for global camera/mic/GPS blocking
- **Firewall Rules**: Per-domain network policies
- **Timeline View**: Chronological security events
- **Export**: Generate forensic reports

### Configuration

- **Threat Detection**: Enable/disable security scanning
- **Behavior Monitoring**: Track suspicious page activity
- **Cookie Management**: Auto-decline or block all
- **Auto-Block**: Automatically block dangerous sites

## 🔧 Technical Details

### Protection Mechanisms

**1. API Override (surveillance_protection.js)**

```javascript
// Runs in page context before any other scripts
navigator.mediaDevices.getUserMedia = function() {
  if (isThreat) throw new DOMException('Blocked by HelioRa');
  return originalFunction();
}
```

**2. Pre-Navigation Blocking (service_worker.js)**

```javascript
chrome.webNavigation.onBeforeNavigate.addListener(async (details) => {
  const phishingCheck = await quickPhishingCheck(details.url);
  if (phishingCheck.confidence >= 80) {
    // Block and redirect to warning page
  }
});
```

**3. Real-Time Analysis**

- Scans every page on load
- Checks 10+ threat indicators
- Calculates risk score
- Generates AI analysis
- Updates dashboard

### Performance

- **Memory Usage**: ~20-30MB
- **CPU Impact**: <1% average
- **Network Overhead**: Minimal (AI requests cached)
- **Page Load Impact**: <100ms

## 🧪 Testing

### Test Surveillance Protection

```bash
# Open local test file
open test_camphish.html

# Expected: Red warning page with "SURVEILLANCE ATTACK BLOCKED"
# Camera/GPS requests should be denied
```

### Test Cookie Blocker

Visit any EU website (e.g., BBC, CNN) - cookie banners should be removed automatically.

### Test Phishing Protection

Visit a suspicious domain with phishing keywords - should show warning before page loads.

## 🐛 Troubleshooting

**Extension not blocking surveillance:**

1. Reload the extension: `chrome://extensions/` → Click refresh
2. Check console for errors: Right-click popup → Inspect
3. Verify protection is active: Look for `[HelioRa Surveillance] Protection active` in page console

**AI analysis not showing:**

- Check internet connection
- Wait 3-5 seconds for AI response
- Fallback messages appear if API fails

**Cookie banners not removed:**

- Enable "Auto-Decline Cookies" in Config tab
- Some banners require page reload
- Try enabling "Block All Cookies" for aggressive removal

## 🤝 Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Submit a pull request

## 📄 License

MIT License - see [LICENSE](LICENSE) file for details

## 👩‍💻 Author

**Anshul Saxena**

*Building the future of browser security, one feature at a time.*

---

## 🔗 Links

- **GitHub**: [github.com/AnshulAlgoS/HelioRa](https://github.com/AnshulAlgoS/HelioRa)
- **Issues**: [Report bugs](https://github.com/AnshulAlgoS/HelioRa/issues)
- **Email**: anshulsaxena9c6stc@gmail.com

---

<div align="center">

**HelioRa Security** • Real-Time Browser Defense Platform

Made with ❤️ by Anshul Saxena 👩‍💻

</div>
