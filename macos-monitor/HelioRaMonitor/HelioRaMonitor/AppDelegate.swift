//
//  AppDelegate.swift
//  HelioRa System Monitor
//
//  macOS menu bar app for cross-verifying browser surveillance with OS-level camera/mic usage
//  Created by Anshul Saxena
//

import Cocoa
import AVFoundation
import CoreLocation
import Swifter

@main
class AppDelegate: NSObject, NSApplicationDelegate, CLLocationManagerDelegate {
    
    // MARK: - Properties
    
    var statusItem: NSStatusItem!
    var menu: NSMenu!
    var server: HttpServer!
    
    // Monitoring state
    var isCameraActive = false
    var isMicrophoneActive = false
    var isLocationActive = false
    var isScreenRecording = false
    
    // HTTP server
    let serverPort: UInt16 = 9876
    
    // Location manager
    var locationManager: CLLocationManager!
    
    // Timers for polling
    var cameraTimer: Timer?
    var micTimer: Timer?
    var screenTimer: Timer?
    
    // MARK: - App Lifecycle
    
    func applicationDidFinishLaunching(_ aNotification: Notification) {
        // Create status bar item
        setupMenuBar()
        
        // Start monitoring
        startMonitoring()
        
        // Start HTTP server
        startHTTPServer()
        
        // Request permissions
        requestPermissions()
        
        print("HelioRa Monitor started on port \(serverPort)")
    }
    
    func applicationWillTerminate(_ aNotification: Notification) {
        stopMonitoring()
        server?.stop()
    }
    
    // MARK: - Menu Bar Setup
    
    func setupMenuBar() {
        // Create status item
        statusItem = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
        
        if let button = statusItem.button {
            button.image = NSImage(systemSymbolName: "shield.fill", accessibilityDescription: "HelioRa Monitor")
            button.image?.isTemplate = true
        }
        
        // Create menu
        menu = NSMenu()
        
        menu.addItem(NSMenuItem(title: "HelioRa System Monitor", action: nil, keyEquivalent: ""))
        menu.addItem(NSMenuItem.separator())
        
        menu.addItem(NSMenuItem(title: "📹 Camera: Inactive", action: nil, keyEquivalent: ""))
        menu.addItem(NSMenuItem(title: "🎤 Microphone: Inactive", action: nil, keyEquivalent: ""))
        menu.addItem(NSMenuItem(title: "📍 Location: Inactive", action: nil, keyEquivalent: ""))
        menu.addItem(NSMenuItem(title: "🖥️ Screen Recording: Inactive", action: nil, keyEquivalent: ""))
        
        menu.addItem(NSMenuItem.separator())
        menu.addItem(NSMenuItem(title: "Server: Running on :\(serverPort)", action: nil, keyEquivalent: ""))
        menu.addItem(NSMenuItem.separator())
        
        let quitItem = NSMenuItem(title: "Quit HelioRa Monitor", action: #selector(quitApp), keyEquivalent: "q")
        menu.addItem(quitItem)
        
        statusItem.menu = menu
    }
    
    func updateMenuBar() {
        guard let menu = menu else { return }
        
        menu.item(at: 2)?.title = isCameraActive ? "📹 Camera: ACTIVE ⚠️" : "📹 Camera: Inactive"
        menu.item(at: 3)?.title = isMicrophoneActive ? "🎤 Microphone: ACTIVE ⚠️" : "🎤 Microphone: Inactive"
        menu.item(at: 4)?.title = isLocationActive ? "📍 Location: ACTIVE ⚠️" : "📍 Location: Inactive"
        menu.item(at: 5)?.title = isScreenRecording ? "🖥️ Screen Recording: ACTIVE ⚠️" : "🖥️ Screen Recording: Inactive"
        
        // Update status icon color
        if let button = statusItem.button {
            if isCameraActive || isMicrophoneActive || isScreenRecording {
                button.image = NSImage(systemSymbolName: "shield.fill", accessibilityDescription: "HelioRa Monitor")
                button.contentTintColor = .systemRed
            } else {
                button.image = NSImage(systemSymbolName: "shield.fill", accessibilityDescription: "HelioRa Monitor")
                button.contentTintColor = .controlAccentColor
            }
        }
    }
    
    @objc func quitApp() {
        NSApplication.shared.terminate(nil)
    }
    
    // MARK: - Permission Requests
    
    func requestPermissions() {
        // Request camera permission
        AVCaptureDevice.requestAccess(for: .video) { granted in
            if granted {
                print("Camera permission granted")
            }
        }
        
        // Request microphone permission
        AVCaptureDevice.requestAccess(for: .audio) { granted in
            if granted {
                print("Microphone permission granted")
            }
        }
        
        // Request location permission
        locationManager = CLLocationManager()
        locationManager.delegate = self
        locationManager.requestAlwaysAuthorization()
    }
    
    // MARK: - Monitoring
    
    func startMonitoring() {
        // Camera monitoring (check every 0.5 seconds)
        cameraTimer = Timer.scheduledTimer(withTimeInterval: 0.5, repeats: true) { [weak self] _ in
            self?.checkCameraStatus()
        }
        
        // Microphone monitoring
        micTimer = Timer.scheduledTimer(withTimeInterval: 0.5, repeats: true) { [weak self] _ in
            self?.checkMicrophoneStatus()
        }
        
        // Screen recording monitoring
        screenTimer = Timer.scheduledTimer(withTimeInterval: 1.0, repeats: true) { [weak self] _ in
            self?.checkScreenRecordingStatus()
        }
    }
    
    func stopMonitoring() {
        cameraTimer?.invalidate()
        micTimer?.invalidate()
        screenTimer?.invalidate()
    }
    
    func checkCameraStatus() {
        let wasActive = isCameraActive
        
        // Check if any camera is in use
        let devices = AVCaptureDevice.devices(for: .video)
        isCameraActive = devices.contains { device in
            return device.isInUseByAnotherApplication
        }
        
        if isCameraActive != wasActive {
            DispatchQueue.main.async {
                self.updateMenuBar()
                
                if self.isCameraActive {
                    self.showNotification(title: "Camera Activated", body: "A camera is now in use on your system")
                }
            }
        }
    }
    
    func checkMicrophoneStatus() {
        let wasActive = isMicrophoneActive
        
        // Check if any microphone is in use
        let devices = AVCaptureDevice.devices(for: .audio)
        isMicrophoneActive = devices.contains { device in
            return device.isInUseByAnotherApplication
        }
        
        if isMicrophoneActive != wasActive {
            DispatchQueue.main.async {
                self.updateMenuBar()
                
                if self.isMicrophoneActive {
                    self.showNotification(title: "Microphone Activated", body: "A microphone is now in use on your system")
                }
            }
        }
    }
    
    func checkScreenRecordingStatus() {
        let wasActive = isScreenRecording
        
        // Check screen recording permission (macOS 10.15+)
        if #available(macOS 10.15, *) {
            isScreenRecording = CGPreflightScreenCaptureAccess()
        }
        
        if isScreenRecording != wasActive {
            DispatchQueue.main.async {
                self.updateMenuBar()
            }
        }
    }
    
    // MARK: - Location Manager Delegate
    
    func locationManager(_ manager: CLLocationManager, didChangeAuthorization status: CLAuthorizationStatus) {
        isLocationActive = (status == .authorizedAlways || status == .authorizedWhenInUse)
        updateMenuBar()
    }
    
    // MARK: - HTTP Server
    
    func startHTTPServer() {
        server = HttpServer()
        
        // CORS headers for browser extension
        let corsHeaders: [String: String] = [
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
            "Access-Control-Allow-Headers": "Content-Type",
            "Content-Type": "application/json"
        ]
        
        // GET /status - Current surveillance status
        server["/status"] = { request in
            let response: [String: Any] = [
                "camera": self.isCameraActive,
                "microphone": self.isMicrophoneActive,
                "location": self.isLocationActive,
                "screenRecording": self.isScreenRecording,
                "timestamp": ISO8601DateFormatter().string(from: Date()),
                "serverVersion": "1.0.0"
            ]
            
            let jsonData = try! JSONSerialization.data(withJSONObject: response, options: .prettyPrinted)
            let jsonString = String(data: jsonData, encoding: .utf8)!
            
            return HttpResponse.ok(.text(jsonString)).withHeaders(corsHeaders)
        }
        
        // GET /camera - Camera status only
        server["/camera"] = { request in
            let response: [String: Any] = [
                "active": self.isCameraActive,
                "timestamp": ISO8601DateFormatter().string(from: Date())
            ]
            
            let jsonData = try! JSONSerialization.data(withJSONObject: response, options: .prettyPrinted)
            let jsonString = String(data: jsonData, encoding: .utf8)!
            
            return HttpResponse.ok(.text(jsonString)).withHeaders(corsHeaders)
        }
        
        // GET /microphone - Microphone status only
        server["/microphone"] = { request in
            let response: [String: Any] = [
                "active": self.isMicrophoneActive,
                "timestamp": ISO8601DateFormatter().string(from: Date())
            ]
            
            let jsonData = try! JSONSerialization.data(withJSONObject: response, options: .prettyPrinted)
            let jsonString = String(data: jsonData, encoding: .utf8)!
            
            return HttpResponse.ok(.text(jsonString)).withHeaders(corsHeaders)
        }
        
        // GET /health - Server health check
        server["/health"] = { request in
            let response: [String: Any] = [
                "status": "ok",
                "version": "1.0.0",
                "uptime": ProcessInfo.processInfo.systemUptime
            ]
            
            let jsonData = try! JSONSerialization.data(withJSONObject: response, options: .prettyPrinted)
            let jsonString = String(data: jsonData, encoding: .utf8)!
            
            return HttpResponse.ok(.text(jsonString)).withHeaders(corsHeaders)
        }
        
        // OPTIONS - CORS preflight
        server["/status"] = { request in
            return HttpResponse.ok(.text("")).withHeaders(corsHeaders)
        }
        
        // Start server
        do {
            try server.start(serverPort)
            print("HTTP Server started on http://localhost:\(serverPort)")
            print("Test with: curl http://localhost:\(serverPort)/status")
        } catch {
            print("Server start error: \(error)")
            showNotification(title: "Server Error", body: "Failed to start HTTP server on port \(serverPort)")
        }
    }
    
    // MARK: - Notifications
    
    func showNotification(title: String, body: String) {
        let notification = NSUserNotification()
        notification.title = title
        notification.informativeText = body
        notification.soundName = NSUserNotificationDefaultSoundName
        
        NSUserNotificationCenter.default.deliver(notification)
    }
}
