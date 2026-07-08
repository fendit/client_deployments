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
for cmd in go wails node npm pkgbuild x86_64-w64-mingw32-gcc; do
  if ! command -v "$cmd" &>/dev/null; then
    echo "ERROR: '$cmd' not found. Install missing tools before running this script."
    exit 1
  fi
done

# ── Clean slate ───────────────────────────────────────────────────────────────
rm -rf "$OUT_DIR" "$TMP_PKG_DIR"
mkdir -p "$MAC_OUT" "$WIN_OUT" "$TMP_PKG_DIR/payload" "$TMP_PKG_DIR/scripts"

# ── Step 1: Cross-compile agent daemon for Windows ────────────────────────────
echo "[1/6] Compiling Windows agent daemon..."
( cd "$AGENT_SRC" && \
  CGO_ENABLED=0 GOOS=windows GOARCH=amd64 \
  go build -ldflags "-s -w" -o "../${INSTALLER_SRC}/fendit-agent.exe" . )

# ── Step 2: Build Windows installer via Wails ─────────────────────────────────
# Uses mingw-w64 toolchain for proper CGO cross-compilation.
# wails build handles npm install + build, icon embedding, and bundling.
echo "[2/6] Building Windows installer via Wails..."
( cd "$INSTALLER_SRC" && \
  CC=x86_64-w64-mingw32-gcc CGO_ENABLED=1 \
  wails build -platform windows/amd64 -clean )

cp "${INSTALLER_SRC}/build/bin/fendit-installer.exe" "$WIN_OUT/fendit_base.exe"
rm -f "${INSTALLER_SRC}/fendit-agent.exe"

# ── Step 3: Compile agent daemon for macOS ────────────────────────────────────
echo "[3/6] Compiling macOS agent daemon..."
( cd "$AGENT_SRC" && \
  GOOS=darwin GOARCH=arm64 \
  go build -ldflags "-s -w" -o "../${INSTALLER_SRC}/fendit-agent" . )
chmod +x "${INSTALLER_SRC}/fendit-agent"

# ── Step 4: Build macOS installer via Wails ───────────────────────────────────
# Native arm64 build — no cross-compilation toolchain needed.
echo "[4/6] Building macOS installer via Wails..."
( cd "$INSTALLER_SRC" && wails build -platform darwin/arm64 -clean )

rm -f "${INSTALLER_SRC}/fendit-agent"

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
