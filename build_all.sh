#!/bin/bash

# Stop het script direct als er ergens een fout optreedt
set -e

# ==========================================
# 1. CONFIGURATIE & MAPPENSTRUCTUUR
# ==========================================
SRC_DIR="fendit-agent"
OUT_DIR="release"
MAC_OUT="$OUT_DIR/osx"
WIN_OUT="$OUT_DIR/windows"
TMP_PKG_DIR="tmp_pkg_build"

echo "🚀 Start Fendit Agent Build Pipeline..."

echo "📁 Mappenstructuur voorbereiden..."
rm -rf "$OUT_DIR" "$TMP_PKG_DIR"
mkdir -p "$MAC_OUT"
mkdir -p "$WIN_OUT"
mkdir -p "$TMP_PKG_DIR/payload"
mkdir -p "$TMP_PKG_DIR/scripts"

# ==========================================
# 2. WINDOWS BUILD
# ==========================================
echo "🪟 Windows Agent bouwen (fendit_base.exe)..."
cd "$SRC_DIR"
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -ldflags "-s -w -H=windowsgui" -o "../$WIN_OUT/fendit_base.exe" .
cd ..
echo "Windows build succesvol!"

# ==========================================
# 3. MACOS BUILD & PACKAGING
# ==========================================
echo "macOS Agent compileren (fendit-agent)..."
cd "$SRC_DIR"
GOOS=darwin GOARCH=arm64 go build -ldflags "-s -w" -o "../$TMP_PKG_DIR/payload/fendit-agent" .
cd ..
chmod +x "$TMP_PKG_DIR/payload/fendit-agent"

echo "📦 macOS PKG inpakken (fendit_base.pkg)..."
cp pkg_scripts/postinstall "$TMP_PKG_DIR/scripts/postinstall"
chmod +x "$TMP_PKG_DIR/scripts/postinstall"

pkgbuild --root "$TMP_PKG_DIR/payload" \
         --scripts "$TMP_PKG_DIR/scripts" \
         --identifier eu.fendit.agent \
         --version "${VERSION:-1.0}" \
         --install-location /usr/local/bin \
         "$MAC_OUT/fendit_base.pkg"
echo "macOS inpakken succesvol!"

# ==========================================
# 4. SCHOONMAKEN
# ==========================================
echo "🧹 Tijdelijke bestanden opruimen..."
rm -rf "$TMP_PKG_DIR"

echo ""
echo "Build Pipeline helemaal klaar!"
echo "Je kant-en-klare bestanden staan in:"
echo "   - Windows: ./$WIN_OUT/fendit_base.exe"
echo "   - macOS:   ./$MAC_OUT/fendit_base.pkg"
