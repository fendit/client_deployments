#!/bin/bash
# Fendit Build Pipeline
#
# Outputs:
#   release/windows/fendit_base.exe  — Wails GUI installer (Windows amd64)
#   release/osx/fendit_base.pkg      — Wails GUI installer (macOS arm64, pkg-wrapped)
#
# Prerequisites on the build host: go, wails, node, npm, pkgbuild

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
for cmd in go wails node npm pkgbuild; do
  if ! command -v "$cmd" &>/dev/null; then
    echo "ERROR: '$cmd' not found in PATH — install it before running this script."
    exit 1
  fi
done

# ── Clean slate ───────────────────────────────────────────────────────────────
rm -rf "$OUT_DIR" "$TMP_PKG_DIR"
mkdir -p "$MAC_OUT" "$WIN_OUT" "$TMP_PKG_DIR/payload" "$TMP_PKG_DIR/scripts"

# ── Step 1: Cross-compile agent daemon for Windows (CGO_ENABLED=0) ────────────
echo "[1/6] Compiling Windows agent daemon..."
( cd "$AGENT_SRC" && \
  CGO_ENABLED=0 GOOS=windows GOARCH=amd64 \
  go build -ldflags "-s -w" -o "../${INSTALLER_SRC}/fendit-agent.exe" . )

# ── Step 2: Build Windows installer ──────────────────────────────────────────
# The React frontend must exist before go build so //go:embed can pick it up.
echo "[2/6] Building React frontend..."
( cd "${INSTALLER_SRC}/frontend" && npm ci && npm run build )

echo "[2/6] Cross-compiling Windows installer (fendit_base.exe)..."
( cd "$INSTALLER_SRC" && \
  CGO_ENABLED=0 GOOS=windows GOARCH=amd64 \
  go build -ldflags "-s -w -H=windowsgui" \
    -o "../$WIN_OUT/fendit_base.exe" . )

rm -f "${INSTALLER_SRC}/fendit-agent.exe"

# ── Step 3: Compile agent daemon for macOS ────────────────────────────────────
echo "[3/6] Compiling macOS agent daemon..."
( cd "$AGENT_SRC" && \
  GOOS=darwin GOARCH=arm64 \
  go build -ldflags "-s -w" -o "../${INSTALLER_SRC}/fendit-agent" . )
chmod +x "${INSTALLER_SRC}/fendit-agent"

# ── Step 4: Build macOS installer via Wails ───────────────────────────────────
# wails build produces a proper .app bundle with Info.plist, icon, and the
# embedded fendit-agent binary (via //go:embed in main_darwin.go).
echo "[4/6] Building macOS installer via Wails..."
( cd "$INSTALLER_SRC" && wails build -platform darwin/arm64 -clean )

rm -f "${INSTALLER_SRC}/fendit-agent"

APP_BUNDLE=$(find "${INSTALLER_SRC}/build/bin" -maxdepth 1 -name "*.app" | head -1)
if [ -z "$APP_BUNDLE" ]; then
  echo "ERROR: No .app bundle found in ${INSTALLER_SRC}/build/bin/ after wails build."
  exit 1
fi
echo "  Found: $APP_BUNDLE"

# ── Step 5: Package .app into a distributable .pkg ────────────────────────────
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
