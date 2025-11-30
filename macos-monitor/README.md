# HelioRa macOS System Monitor

> Cross-verifies browser surveillance with OS-level camera/mic usage

## 🎯 What This Does

This is the **killer feature** that makes HelioRa unique:

**The Problem:** Browser extensions can only see what websites *try* to access. They can't see what
the OS *actually* grants.

**The Solution:** This macOS menu bar app monitors system-level camera/microphone usage and exposes
it via HTTP. The browser extension talks to this local server to cross-verify:

```
Browser says: "No website is using camera"
macOS says: "Camera is ACTIVE" 
HelioRa: "🚨 NUCLEAR ALERT - Hidden surveillance detected!"
```

## 🚀 Features

- **Real-Time OS Monitoring**: Checks camera/mic status every 500ms
- **Menu Bar Integration**: Shows live status in macOS menu bar
- **HTTP API**: Exposes surveillance status on `localhost:9876`
- **Zero Network**: Everything runs locally, no internet required
- **Lightweight**: <10MB memory, <1% CPU
- **Native Notifications**: macOS notifications when camera/mic activate

## 📦 Installation

### Option 1: Pre-built App (Easiest)

1. **Download** `HelioRaMonitor.app` from releases
2. **Move** to `/Applications/`
3. **Open** - Right-click → Open (to bypass Gatekeeper)
4. **Grant permissions** when prompted:
    - Camera access
    - Microphone access
    - Screen recording (optional)

### Option 2: Build from Source

#### Prerequisites:

- macOS 12.0 or later
- Xcode 14+ or Swift 5.9+

#### Steps:

```bash
cd macos-monitor/HelioRaMonitor

# Build using Swift Package Manager
swift build -c release

# Or open in Xcode
open HelioRaMonitor.xcodeproj

# Build and run
# Product → Run (⌘R)
```

#### Using Xcode:

1. Open `HelioRaMonitor.xcodeproj` in Xcode
2. Select your Mac as the target
3. Product → Build (⌘B)
4. Product → Run (⌘R)
5. App will appear in menu bar (shield icon)

## 🔌 API Endpoints

The app runs an HTTP server on `http://localhost:9876`:

### `GET /status` - Complete surveillance status

```bash
curl http://localhost:9876/status
```

Response:

```json
{
  "camera": false,
  "microphone": false,
  "location": false,
  "screenRecording": false,
  "timestamp": "2024-12-01T15:30:45Z",
  "serverVersion": "1.0.0"
}
```

### `GET /camera` - Camera status only

```bash
curl http://localhost:9876/camera
```

Response:

```json
{
  "active": false,
  "timestamp": "2024-12-01T15:30:45Z"
}
```

### `GET /microphone` - Microphone status only

```bash
curl http://localhost:9876/microphone
```

Response:

```json
{
  "active": false,
  "timestamp": "2024-12-01T15:30:45Z"
}
```

### `GET /health` - Server health check

```bash
curl http://localhost:9876/health
```

Response:

```json
{
  "status": "ok",
  "version": "1.0.0",
  "uptime": 3600.5
}
```

## 🔗 Browser Extension Integration

The browser extension automatically talks to this app:

```javascript
// In service_worker.js
async function checkOSCameraStatus() {
  try {
    const response = await fetch('http://localhost:9876/camera');
    const data = await response.json();
    
    if (data.active) {
      // OS says camera is ON
      // Cross-check with browser's knowledge
      
      if (!browserSaysCameraIsUsed()) {
        // CRITICAL: Hidden surveillance!
        showNuclearWarning();
      }
    }
  } catch (error) {
    // App not running - gracefully degrade
  }
}
```

## 🧪 Testing

### 1. Test HTTP Server

```bash
# Start the app first, then:
curl http://localhost:9876/status

# Expected: JSON response with all statuses false
```

### 2. Test Camera Detection

```bash
# Open Photo Booth or FaceTime
# Camera LED should turn on

curl http://localhost:9876/camera

# Expected: "active": true
```

### 3. Test with Extension

1. Start HelioRa Monitor
2. Load HelioRa extension in Chrome
3. Visit a site with camera access
4. Extension will query `localhost:9876` automatically
5. Check console for cross-verification logs

## 🔐 Privacy & Security

### What it monitors:

- ✅ System-wide camera usage (any app)
- ✅ System-wide microphone usage (any app)
- ✅ Screen recording permissions
- ✅ Location services status

### What it does NOT do:

- ❌ Record video/audio
- ❌ Access actual camera feed
- ❌ Send data to internet
- ❌ Track which apps use camera
- ❌ Store any usage history

### How it works:

- Uses Apple's `AVCaptureDevice.isInUseByAnotherApplication` API
- Only checks **if** devices are in use (boolean)
- Doesn't access actual device data
- 100% local processing

## 🎨 Menu Bar Interface

When running, you'll see a shield icon in your menu bar:

**Inactive (blue shield):**

```
📹 Camera: Inactive
🎤 Microphone: Inactive
📍 Location: Inactive
🖥️ Screen Recording: Inactive
```

**Active (red shield):**

```
📹 Camera: ACTIVE ⚠️
🎤 Microphone: ACTIVE ⚠️
📍 Location: Inactive
🖥️ Screen Recording: Inactive
```

## 🐛 Troubleshooting

**App won't open:**

- Right-click → Open (first time only)
- Check System Settings → Privacy & Security

**Server not responding:**

```bash
# Check if port is in use
lsof -i :9876

# Kill existing process
kill -9 <PID>

# Restart app
```

**Permission denied:**

- Go to System Settings → Privacy & Security
- Grant Camera and Microphone access to HelioRa Monitor

**Extension can't connect:**

```bash
# Test manually first
curl http://localhost:9876/health

# If that works, check extension console for errors
```

## 📊 Performance

- **Memory:** ~8-12 MB
- **CPU:** <0.5% idle, <1% when polling
- **Network:** 0 (local only)
- **Battery:** Negligible impact

## 🔄 Auto-Start (Optional)

To run on macOS login:

1. Open **System Settings**
2. Go to **General → Login Items**
3. Click **+** button
4. Select **HelioRaMonitor.app**

## 📄 Architecture

```
┌─────────────────────────────────────┐
│   Browser (Chrome Extension)        │
│                                      │
│   service_worker.js detects:        │
│   "No site is using camera"         │
└──────────────┬───────────────────────┘
               │
               │ HTTP GET /camera
               ▼
┌─────────────────────────────────────┐
│   macOS App (Menu Bar)              │
│                                      │
│   AVFoundation reports:             │
│   "Camera IS in use"                │
└──────────────┬───────────────────────┘
               │
               │ Response: { "active": true }
               ▼
┌─────────────────────────────────────┐
│   Extension Logic                   │
│                                      │
│   Browser: false                    │
│   macOS: true                       │
│   = HIDDEN SURVEILLANCE!            │
│                                      │
│   🚨 NUCLEAR WARNING 🚨             │
└─────────────────────────────────────┘
```

## 🤝 Contributing

Improvements welcome:

- [ ] WebSocket support (lower latency)
- [ ] Screen capture detection
- [ ] Bluetooth device monitoring
- [ ] Network activity tracking
- [ ] Per-app usage tracking

## 📝 License

MIT License - same as main HelioRa project

---

<div align="center">

**HelioRa macOS Monitor** • OS-Level Surveillance Detection

The missing piece of browser security.

Made with ❤️ by Anshul Saxena

</div>
