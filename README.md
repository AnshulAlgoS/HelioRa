# HelioRa Security - Advanced Web Security Firewall

**HelioRa Security** is a powerful Chrome extension that provides comprehensive web security
protection through real-time threat intelligence, PDF security validation, behavior-based malware
detection, and user-controlled network firewall rules. Optimized for macOS (Apple) security
standards.

![Version](https://img.shields.io/badge/version-4.0.0-blue)
![Manifest](https://img.shields.io/badge/manifest-v3-green)
![License](https://img.shields.io/badge/license-MIT-orange)

---

## 🛡️ Core Features

### 1. Live Threat Intelligence

- **Real-time website reputation checking** using threat database
- **Classification system:**
    - ✅ **Safe:** No threats detected
    - ⚠️ **Suspicious:** Potential security concerns
    - 🛑 **Dangerous:** Confirmed threats (phishing, malware, scams)
- **Live risk indicator** in popup UI with visual status
- **Automatic warning banners** on dangerous sites
- **Typosquatting detection** for popular domains (Google, Facebook, PayPal, etc.)
- **Threat caching** for improved performance (1-hour cache)

### 2. Download & PDF Security

- **PDF download validation:**
    - Source domain reputation checking
    - MIME type vs file extension mismatch detection
    - File size anomaly detection (exploit prevention)
- **Blocks disguised executables** pretending to be PDFs
- **Automatic blocking** of risky downloads with notifications
- **Domain blacklist** integration for download sources

### 3. Behavior-Based Detection (Heuristic Security)

Advanced content script that detects and flags suspicious browser behaviors:

- **🔍 Crypto-mining detection:**
    - Keyword-based script detection (Coinhive, CryptoLoot, etc.)
    - CPU usage monitoring for mining activity
- **🔐 Obfuscated JavaScript detection:**
    - Pattern matching for eval(), atob(), String.fromCharCode()
    - Suspicion scoring system
- **🖼️ Hidden iframe detection:**
    - Monitors for invisible or 1x1 pixel iframes
    - Tracks dynamically added iframes
- **↪️ Forced redirect detection:**
    - Intercepts location.assign() and location.replace()
    - Meta refresh tag monitoring
- **📡 Excessive network activity:**
    - XHR/Fetch request monitoring
    - Rate-limiting alerts (>50 requests/10 seconds)
- **🔧 DOM manipulation detection:**
    - MutationObserver for suspicious changes
    - Tracks rapid script/iframe injections

### 4. User-Controlled Network Firewall (Manual Rules)

Granular per-domain control with 5 firewall modes:

- **✅ Allow All:** No restrictions (default)
- **🎯 Block Tracking:** Blocks analytics and tracking scripts
- **🚫 Block XHR/Fetch:** Blocks all AJAX requests and pings
- **📵 Block Ads Only:** Blocks ad-related scripts and images
- **⛔ Block All:** Complete domain block (all resource types)

**Features:**

- Domain-specific rules stored in `chrome.storage.sync`
- Dynamic rule application using `declarativeNetRequest`
- Complete blacklist support for dangerous domains
- Real-time rule updates without extension reload

---

## 📊 Security Dashboard

The popup provides comprehensive security status:

### Real-Time Status Display

- **Security Status:** Color-coded threat level (Safe/Suspicious/Dangerous)
- **Current Domain:** Domain name with live threat classification
- **Threat Description:** Detailed explanation of detected threats

### Behavior Alerts Panel

- **Live alerts** from content script detections
- **Alert types:** Crypto-mining, obfuscated scripts, hidden iframes, redirects, etc.
- **Timestamp tracking** with human-readable time formatting
- **One-click alert clearing** per domain

### Statistics Dashboard

- **Threats Blocked:** Total dangerous sites blocked
- **Risky Downloads:** Suspicious PDF/file downloads prevented
- **Behavior Alerts:** Total heuristic detections triggered

### Firewall Controls

- **Per-domain rule selector** (5 firewall modes)
- **Quick blacklist button** for current domain
- **Visual rule status** display

---

## 🎨 UI Design

**Design Philosophy:** "HelioRa" = Sun + Light + Protection + Visibility

- **Modern gradient header** (purple theme: #667eea → #764ba2)
- **Color-coded security status:**
    - Green gradient for safe sites
    - Amber gradient for suspicious sites
    - Red gradient for dangerous sites
- **macOS-optimized typography:** SF Pro Display, SF Mono
- **Smooth animations** and transitions
- **Accessible design** with clear visual hierarchy
- **Compact 420px width** for optimal sidebar usage

---

## 🚀 Installation

### Method 1: Chrome Web Store (Coming Soon)

*Extension will be available on the Chrome Web Store*

### Method 2: Manual Installation (Developer Mode)

1. **Clone or download this repository:**
   ```bash
   git clone https://github.com/yourusername/heliora-security.git
   cd heliora-security
   ```

2. **Open Chrome Extensions page:**
   ```
   chrome://extensions/
   ```

3. **Enable Developer Mode:**
    - Toggle the switch in the top-right corner

4. **Load the extension:**
    - Click "Load unpacked"
    - Select the `HelioRa` folder

5. **Pin the extension:**
    - Click the puzzle icon in Chrome toolbar
    - Pin HelioRa Security for quick access

---

## 🔧 Usage Guide

### Basic Protection

1. **Enable Security Features:**
    - Open HelioRa popup
    - Navigate to "Security" tab
    - Toggle features on/off:
        - Threat Detection
        - PDF Security
        - Behavior Detection
        - Network Firewall

2. **View Current Site Status:**
    - Popup shows real-time security status
    - Badge icon indicates threat level
    - Click for detailed information

### Setting Firewall Rules

1. **Per-Domain Rules:**
    - Visit a website
    - Open HelioRa popup
    - Select firewall mode from dropdown
    - Rule applies immediately

2. **Blacklist a Domain:**
    - Click "🚫 Add to Blacklist" button
    - Confirm action
    - Domain is completely blocked

3. **Manage Rules:**
    - Navigate to "Firewall" tab
    - View all blacklisted domains
    - View custom firewall rules
    - Remove domains with ×button

### Responding to Threats

**Dangerous Site Detected:**

- Auto-block redirects to warning page (if enabled)
- Or displays warning banner on page
- Shows threat type and description
- Option to go back or close tab

**Behavior Alert Triggered:**

- Alert appears in popup panel
- Shows alert type and description
- Review and clear as needed
- Consider blacklisting the domain

**Risky PDF Download:**

- Download automatically canceled
- Notification shown (if supported)
- Alert logged in statistics
- Check download source reputation

---

## 🍎 macOS Security Enhancements

HelioRa is optimized for Apple's security standards:

### System Integration

- **Safari-style security warnings** with Apple design language
- **Gatekeeper-inspired threat blocking** mechanism
- **XProtect-style behavior detection** patterns
- **Optimized for macOS Chrome** and Chromium-based browsers

### Privacy-First Approach

- **All processing happens locally** (no external API calls in current version)
- **No data collection or analytics**
- **Settings synced via Chrome's secure sync** (optional)
- **Threat database stored locally** for offline protection

### Performance

- **Lightweight content script** with minimal memory footprint
- **Efficient observer patterns** (MutationObserver, event listeners)
- **Smart caching** to reduce redundant checks
- **Optimized for Apple Silicon** (M1/M2/M3 chips)

---

## 📁 Project Structure

```
HelioRa/
├── manifest.json                 # Extension manifest (Manifest V3)
├── service_worker.js            # Background service worker
│                                # - Threat intelligence engine
│                                # - PDF security validation
│                                # - Firewall rule management
│                                # - Statistics tracking
├── content_script.js            # Behavior detection script
│                                # - Crypto-mining detection
│                                # - Script obfuscation detection
│                                # - DOM manipulation monitoring
├── popup.html                   # Popup UI structure
├── popup.css                    # Modern styling (macOS-optimized)
├── popup.js                     # Popup logic and interactions
├── warning.html                 # Threat warning page
├── firewall_rules.json          # Dynamic firewall rules (empty by default)
├── icons/
│   ├── icon16.png              # 16×16 toolbar icon
│   ├── icon48.png              # 48×48 extension icon
│   └── icon128.png             # 128×128 store icon
├── LICENSE                      # MIT License
└── README.md                    # This file
```

---

## 🔒 Permissions Explained

HelioRa requires specific permissions for security functionality:

| Permission | Purpose | Usage |
|------------|---------|-------|
| `declarativeNetRequest` | Firewall rules | Apply network-level blocking rules |
| `declarativeNetRequestWithHostAccess` | Per-domain rules | Domain-specific firewall configuration |
| `declarativeNetRequestFeedback` | Rule debugging | Monitor rule matches in debug mode |
| `storage` | Settings & cache | Store settings, threat cache, statistics |
| `tabs` | Current tab info | Detect active domain for security check |
| `webRequest` | Request monitoring | Monitor downloads and network activity |
| `downloads` | PDF security | Intercept and validate downloads |
| `scripting` | Warning injection | Inject warning banners on dangerous sites |
| `alarms` | Periodic tasks | Refresh threat database cache |
| `<all_urls>` | Universal access | Check any website for threats |

**Privacy Note:** All data is processed locally. No information is sent to external servers.

---

## 🧪 Development

### Debug Mode

The extension automatically enables debug mode when running unpacked:

1. **View service worker console:**
    - Go to `chrome://extensions/`
    - Find HelioRa Security
    - Click "service worker" link
    - View detailed logs

2. **Test behavior detection:**
    - Open DevTools console on any page
    - Watch for `[HelioRa]` prefixed messages
    - Alerts logged with detection details

3. **Test firewall rules:**
    - Set domain rules via popup
    - Check Network tab in DevTools
    - Blocked requests show as "blocked:other"

### Extending Threat Database

Currently uses a static threat database. To add external API:

1. **Update `checkThreatDatabase()` in service_worker.js:**
   ```javascript
   async function checkThreatDatabase(domain) {
     // Call external API (e.g., Google Safe Browsing)
     const response = await fetch(`https://api.example.com/check?domain=${domain}`);
     const data = await response.json();
     return data;
   }
   ```

2. **Add API key to settings:**
    - Store in `chrome.storage.sync`
    - Add UI field in Settings tab

### Adding Custom Behavior Detections

Edit `content_script.js` to add new detection patterns:

```javascript
detectCustomBehavior() {
  // Your detection logic here
  if (suspiciousCondition) {
    this.sendAlert({
      type: 'custom-threat',
      description: 'Your threat description'
    });
  }
}
```

---

## 📈 Statistics & Analytics

HelioRa tracks local security metrics:

- **Threats Blocked:** Count of dangerous sites blocked
- **Risky Downloads:** Suspicious downloads prevented
- **Behavior Alerts:** Heuristic detections triggered
- **Firewall Rules Applied:** Total rule applications

**Reset Statistics:** Settings → Data Management → Reset Statistics

---

## 🐛 Troubleshooting

### Sites Not Being Checked

- Ensure "Threat Detection" is enabled in Security tab
- Check if domain is whitelisted
- Try clearing threat cache (reset statistics)

### Firewall Rules Not Working

- Verify "Network Firewall" is enabled
- Check rule is set correctly for domain
- Reload the target website
- Check for conflicting browser extensions

### Behavior Alerts Not Showing

- Enable "Behavior Detection" in Security tab
- Content script must be allowed on page
- Check for conflicts with other security extensions

### Extension Not Loading

- Verify Manifest V3 support (Chrome 88+)
- Check all files are present in directory
- Look for errors in `chrome://extensions/`
- Reload extension after code changes

---

## 🔄 Version History

### Version 4.0.0 (2024)

- 🆕 Complete rebuild as security-focused extension
- ✅ Live threat intelligence system
- ✅ PDF security validation
- ✅ Behavior-based malware detection
- ✅ User-controlled network firewall
- ✅ macOS-optimized design
- ✅ Real-time security dashboard
- ✅ Typosquatting detection
- ✅ Warning page for dangerous sites
- ✅ Comprehensive statistics tracking

---

## 🤝 Contributing

Contributions welcome! Please follow these guidelines:

1. **Fork the repository**
2. **Create feature branch:** `git checkout -b feature/new-detection`
3. **Commit changes:** `git commit -am 'Add new threat detection'`
4. **Push to branch:** `git push origin feature/new-detection`
5. **Submit Pull Request** with detailed description

### Code Style

- Use strict mode (`'use strict'`)
- Follow existing code formatting
- Add comments for complex logic
- Test all security features thoroughly

---

## 📄 License

MIT License

Copyright (c) 2024 Anshul Saxena

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

---

## 👨‍💻 Author

**Anshul Saxena**

---

## 🙏 Acknowledgments

- Chrome Extensions team for Manifest V3 documentation
- macOS security team for design inspiration
- Open source security community for threat intelligence patterns

---

## 📞 Support

For issues, feature requests, or questions:

- **GitHub Issues:** [Open an issue](https://github.com/yourusername/heliora-security/issues)
- **Provide details:** Chrome version, extension version, steps to reproduce
- **Include logs:** Service worker console output for debugging

---

## ⚡ Future Roadmap

- [ ] Integration with external threat intelligence APIs (Google Safe Browsing, VirusTotal)
- [ ] Machine learning-based behavior detection
- [ ] Export threat logs and statistics
- [ ] Custom threat database import/export
- [ ] WebAssembly-based performance optimization
- [ ] Safari extension port
- [ ] Enterprise policy support
- [ ] Cloud sync for threat intelligence
- [ ] Advanced DNS filtering
- [ ] Certificate validation and pinning

---

**Stay Protected with HelioRa Security** 🛡️

*"Like the sun brings light and visibility, HelioRa brings security and clarity to your web
browsing."*
