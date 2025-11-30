#!/bin/bash

# HelioRa macOS Monitor - Build Script
# Builds the Swift app for distribution

set -e

echo "🛡️  Building HelioRa macOS Monitor..."
echo ""

# Check if Swift is installed
if ! command -v swift &> /dev/null; then
    echo "❌ Error: Swift is not installed"
    echo "Please install Xcode from the Mac App Store"
    exit 1
fi

echo "✓ Swift detected: $(swift --version | head -n 1)"
echo ""

# Navigate to project directory
cd "$(dirname "$0")/HelioRaMonitor"

# Clean previous builds
echo "🧹 Cleaning previous builds..."
rm -rf .build
echo "✓ Clean complete"
echo ""

# Resolve dependencies
echo "📦 Resolving dependencies..."
swift package resolve
echo "✓ Dependencies resolved"
echo ""

# Build in release mode
echo "🔨 Building in release mode..."
swift build -c release
echo "✓ Build complete"
echo ""

# Create app bundle structure
echo "📦 Creating app bundle..."
APP_NAME="HelioRaMonitor"
APP_BUNDLE="${APP_NAME}.app"
BUILD_DIR=".build/release"

rm -rf "$APP_BUNDLE"
mkdir -p "$APP_BUNDLE/Contents/MacOS"
mkdir -p "$APP_BUNDLE/Contents/Resources"

# Copy executable
cp "$BUILD_DIR/$APP_NAME" "$APP_BUNDLE/Contents/MacOS/"
chmod +x "$APP_BUNDLE/Contents/MacOS/$APP_NAME"

# Copy Info.plist
cp "${APP_NAME}/Info.plist" "$APP_BUNDLE/Contents/"

# Copy icon (if exists)
if [ -f "${APP_NAME}/AppIcon.icns" ]; then
    cp "${APP_NAME}/AppIcon.icns" "$APP_BUNDLE/Contents/Resources/"
fi

echo "✓ App bundle created"
echo ""

# Code signing (optional, for distribution)
echo "🔐 Code signing..."
if command -v codesign &> /dev/null; then
    codesign --force --deep --sign - "$APP_BUNDLE" 2>/dev/null || true
    echo "✓ Code signed (ad-hoc)"
else
    echo "⚠️  codesign not found, skipping (app will still work)"
fi
echo ""

# Create DMG for distribution (optional)
echo "📦 Creating distributable package..."
OUTPUT_DIR="../dist"
mkdir -p "$OUTPUT_DIR"

# Copy to dist folder
cp -R "$APP_BUNDLE" "$OUTPUT_DIR/"

# Create a simple tarball
cd "$OUTPUT_DIR"
tar -czf "${APP_NAME}.tar.gz" "$APP_BUNDLE"
rm -rf "$APP_BUNDLE"
cd -

echo "✓ Package created: dist/${APP_NAME}.tar.gz"
echo ""

echo "✅ Build complete!"
echo ""
echo "📍 Installation Instructions:"
echo "  1. Extract: tar -xzf ../dist/${APP_NAME}.tar.gz"
echo "  2. Move to Applications: mv ${APP_BUNDLE} /Applications/"
echo "  3. Launch: open /Applications/${APP_BUNDLE}"
echo ""
echo "🧪 Testing:"
echo "  1. Run: .build/release/${APP_NAME}"
echo "  2. Test API: curl http://localhost:9876/status"
echo ""
echo "🎉 Ready for demo!"
