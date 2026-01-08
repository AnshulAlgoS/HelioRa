# HelioRa

HelioRa is a Chrome extension designed to stabilize web page behavior and add a decision layer to sensitive browser actions.

## Context & Motivation

This project began as a personal utility to clean up  websites. While testing and scanning pages, I found that ads, trackers, and cookie overlays created significant noise and instability. Although I often run headless scripts for automation, I needed a reliable way to reproduce and stabilize these pages directly in Chrome for manual debugging.

The project's scope evolved after I encountered "CamPhish" style attacks—techniques that trick users into inadvertently granting camera or microphone access. I realized that while browsers ask for permission, they rarely explain the *context* or *risk* of that request to non-technical users.

I extended HelioRa to act as a **decision and visibility layer**. Instead of just silently blocking or blindly allowing requests, it attempts to "pause and explain" high-risk actions—like submitting credentials, entering OTPs, or granting hardware access—giving the user a chance to understand the risk before proceeding.

## What This Project Is

*   **A Visibility Tool**: It exposes what a page is trying to do (e.g., "This site is asking for camera access immediately after loading" or "You are entering an OTP on a site hosted via a tunneling service").
*   **A Stability Utility**: It suppresses noise (ads, consent banners) to keep the DOM clean for testing or browsing.
*   **An Educational Layer**: It provides context for security decisions, helping users recognize patterns associated with phishing or surveillance.

## ✨ Key Features

###  1. Interaction Interception (The "Pause")
HelioRa injects scripts into the main world context to wrap sensitive browser APIs. When a site attempts a risky action, the extension interrupts the flow and presents a summary of the risk.

*   **Credential/OTP Submission**: Detects input fields resembling OTPs or passwords. If the origin is unknown or suspicious (e.g., an IP address, a tunneling service, or a punycode domain), it interrupts the submit action.
*   **Hardware Access**: Intercepts `getUserMedia` to prevent drive-by camera/microphone access, especially on sites that haven't established trust.
*   **Data Exfiltration Monitoring**: Monitors `fetch`, `XHR`, and `Beacon` requests for patterns resembling data theft.

###  2. Heuristic Analysis & NVIDIA AI
Instead of generic blacklists, the extension combines deterministic heuristics with lightweight AI analysis:
*   **NVIDIA AI Integration**: Leverages local AI acceleration to analyze page structure and script behavior patterns in real-time without sending data to the cloud.
*   **Transport Security**: Checks for HTTPS usage and certificate validity.
*   **Domain Structure**: Flags high-entropy subdomains or known tunneling patterns (often used in phishing campaigns).
*   **Context Awareness**: Differentiates between a trusted domain (e.g., a known bank) and a generic hosting provider or local file system.

###  3. Forensic Analysis & UI Visualization
The extension provides a detailed breakdown of *why* a site was flagged, rather than a generic warning.
*   **Forensic Reports**: Displays a terminal-style analysis log (e.g., "Insecure Transport Protocol," "IDN Homograph Pattern Detected," "High Entropy Subdomain").
*   **Visual Risk Indicators**: Uses a dynamic "jelly" animation in the popup to visually represent the current threat level (Safe, Suspicious, Dangerous).
*   **Plain-English Explanations**: Translates technical heuristics into actionable advice (e.g., "Recommendation: Terminate Connection Immediately").

###  4. DOM Stabilization
Uses `declarativeNetRequest` and content scripts to reduce page noise:
*   **Ad & Tracker Blocking**: Uses static rules to block common ad networks and tracking pixels.
*   **Cookie Consent Handling**: Automatically attempts to decline or hide cookie consent popups to prevent them from obstructing content.
*   **Granular Control**: Users can toggle blocking features (Ads, Trackers, Cookies) independently via the popup.

## Technical Implementation

*   **Manifest V3**: Built on the current Chrome Extension architecture.
*   **Main World Injection**: Scripts run in the page's execution context to reliably wrap browser APIs before other page scripts load.
*   **Dynamic Rulesets**: Blocking rules are split into separate JSON files and managed via the `declarativeNetRequest` API, allowing for independent toggling without reloading the extension.

## Installation (Developer Mode)

1.  Clone this repository.
2.  Open Chrome and navigate to `chrome://extensions/`.
3.  Enable **Developer mode** (top right).
4.  Click **Load unpacked** and select the project directory.

## License

MIT License - see [LICENSE](LICENSE) file for details

## 👩‍💻 Author

**Anshul Saxena**

*Building practical tools for transparency and control.*

---

<div align="center">

**HelioRa**

Developed by Anshul Saxena

</div>
