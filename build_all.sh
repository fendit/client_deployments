#!/bin/bash
# Fendit Build Pipeline
#
# Outputs:
#   release/windows/fendit_base.exe  — Wails GUI installer (Windows amd64)
#   release/osx/fendit_base.pkg      — Wails GUI installer (macOS arm64, pkg-wrapped)
#
# Prerequisites: go, wails, node, npm, pkgbuild, mingw-w64

set -euo pipefail

INSTALLER_SRC="fendit-installer"
AGENT_SRC="fendit-agent"
OUT_DIR="release"
MAC_OUT="$OUT_DIR/osx"
WIN_OUT="$OUT_DIR/windows"
TMP_PKG_DIR="tmp_pkg_build"
VERSION="${VERSION:-1.0.0}"

echo "Fendit Build Pipeline — v${VERSION}"

# ── Sanity checks ─────────────────────────────────────────────────────────────
for cmd in go wails node npm pkgbuild lipo x86_64-w64-mingw32-gcc; do
  if ! command -v "$cmd" &>/dev/null; then
    echo "ERROR: '$cmd' not found. Install missing tools before running this script."
    exit 1
  fi
done

# ── Clean slate ───────────────────────────────────────────────────────────────
rm -rf "$OUT_DIR" "$TMP_PKG_DIR"
mkdir -p "$MAC_OUT" "$WIN_OUT" "$TMP_PKG_DIR/payload" "$TMP_PKG_DIR/scripts"

# Embedded binaries live in fendit-installer/embedded/ so the go:embed paths
# are never confused with the fendit-agent source directory.
mkdir -p "${INSTALLER_SRC}/embedded"

# ── Step 0: Generate macOS template tray icon ─────────────────────────────────
# sips converts the existing appicon.png to a 22x22 grayscale PNG template
# that NSImage renders correctly in light and dark menu bars.
echo "[0/6] Generating macOS tray icon..."
sips -s format png \
     --resampleWidth 22 \
     "${INSTALLER_SRC}/build/appicon.png" \
     --out "${AGENT_SRC}/icon_template.png" \
     2>/dev/null \
  || echo "  WARNING: sips conversion failed — place a 22x22 icon_template.png in ${AGENT_SRC}/ manually."

# ── Step 1: Cross-compile agent daemon for Windows ────────────────────────────
echo "[1/6] Compiling Windows agent daemon..."
( cd "$AGENT_SRC" && \
  CGO_ENABLED=0 GOOS=windows GOARCH=amd64 \
  go build -ldflags "-s -w" -o "../${INSTALLER_SRC}/embedded/fendit-agent-win.exe" . )

# ── Step 2: Build Windows installer via Wails ─────────────────────────────────
# Uses mingw-w64 toolchain for proper CGO cross-compilation.
# wails build handles npm install + build, icon embedding, and bundling.
echo "[2/6] Building Windows installer via Wails..."
( cd "$INSTALLER_SRC" && \
  CC=x86_64-w64-mingw32-gcc CGO_ENABLED=1 \
  wails build -platform windows/amd64 -clean )

cp "${INSTALLER_SRC}/build/bin/fendit-installer.exe" "$WIN_OUT/fendit_base.exe"
rm -f "${INSTALLER_SRC}/embedded/fendit-agent-win.exe"

# ── Step 3: Compile agent daemon for macOS (universal binary) ─────────────────
# Build each arch slice then merge with lipo so the embedded agent works on
# both Apple Silicon (arm64) and Intel (amd64) Macs.
echo "[3/6] Compiling macOS agent daemon (arm64 + amd64 → universal)..."
( cd "$AGENT_SRC" && \
  CGO_ENABLED=1 GOOS=darwin GOARCH=arm64 \
  go build -ldflags "-s -w" -o "../${INSTALLER_SRC}/embedded/fendit-agent-arm64" . )

( cd "$AGENT_SRC" && \
  CGO_ENABLED=1 GOOS=darwin GOARCH=amd64 \
  go build -ldflags "-s -w" -o "../${INSTALLER_SRC}/embedded/fendit-agent-amd64" . )

lipo -create \
    "${INSTALLER_SRC}/embedded/fendit-agent-arm64" \
    "${INSTALLER_SRC}/embedded/fendit-agent-amd64" \
    -output "${INSTALLER_SRC}/embedded/fendit-agent-mac"
chmod +x "${INSTALLER_SRC}/embedded/fendit-agent-mac"
rm -f "${INSTALLER_SRC}/embedded/fendit-agent-arm64" "${INSTALLER_SRC}/embedded/fendit-agent-amd64"

# ── Step 4: Build macOS installer via Wails (universal) ───────────────────────
# darwin/universal produces a fat .app that runs natively on both Intel and
# Apple Silicon without Rosetta 2 emulation.
echo "[4/6] Building macOS installer via Wails (universal)..."
( cd "$INSTALLER_SRC" && wails build -platform darwin/universal -clean )

rm -f "${INSTALLER_SRC}/embedded/fendit-agent-mac"

APP_BUNDLE=$(find "${INSTALLER_SRC}/build/bin" -maxdepth 1 -name "*.app" | head -1)
if [ -z "$APP_BUNDLE" ]; then
  echo "ERROR: No .app bundle found in ${INSTALLER_SRC}/build/bin/ after wails build."
  exit 1
fi
echo "  Found: $APP_BUNDLE"

# ── Step 5: Package macOS .app into a distributable .pkg ─────────────────────
echo "[5/6] Packaging macOS .pkg..."
cp -r "$APP_BUNDLE" "$TMP_PKG_DIR/payload/"
cp pkg_scripts/postinstall "$TMP_PKG_DIR/scripts/postinstall"
chmod +x "$TMP_PKG_DIR/scripts/postinstall"

pkgbuild \
  --root             "$TMP_PKG_DIR/payload" \
  --scripts          "$TMP_PKG_DIR/scripts" \
  --identifier       "eu.fendit.installer" \
  --version          "${VERSION}" \
  --install-location "/Applications" \
  "$MAC_OUT/fendit_base.pkg"

# ── Step 6: Clean up ─────────────────────────────────────────────────────────
echo "[6/6] Cleaning up..."
rm -rf "$TMP_PKG_DIR"

echo ""
echo "Build complete!"
echo "  Windows: ./$WIN_OUT/fendit_base.exe"
echo "  macOS:   ./$MAC_OUT/fendit_base.pkg"
