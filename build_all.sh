#!/bin/bash
# Fendit Build Pipeline
#
# Outputs:
#   release/windows/fendit_base.exe  — Wails GUI installer (Windows amd64)
#   release/osx/fendit_base.pkg      — Wails GUI installer (macOS universal, pkg-wrapped)
#
# Prerequisites: go, wails, node, npm, pkgbuild, lipo, mingw-w64

set -euo pipefail

INSTALLER_SRC="fendit-installer"
AGENT_SRC="fendit-agent"
OUT_DIR="release"
MAC_OUT="$OUT_DIR/osx"
WIN_OUT="$OUT_DIR/windows"
TMP_PKG_DIR="tmp_pkg_build"

# Strip leading 'v' from git tag so pkgbuild gets a clean semver string.
VERSION="${VERSION:-1.0.0}"
VERSION="${VERSION#v}"

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
mkdir -p "${INSTALLER_SRC}/embedded"

# ── Step 0: Generate macOS template tray icon ─────────────────────────────────
# sips is macOS-built-in. It converts the 512×512 appicon.png to a 22×22 PNG
# that NSImage renders as a template (auto light/dark menu-bar colour).
echo "[0/6] Generating macOS tray icon..."
sips -s format png \
     --resampleWidth 22 \
     "${INSTALLER_SRC}/build/appicon.png" \
     --out "${AGENT_SRC}/icon_template.png" \
     2>/dev/null \
  || echo "  WARNING: sips failed — using existing icon_template.png if present."

# ── CRITICAL: compile ALL agent binaries before any wails build ───────────────
#
# Wails' "Generating bindings" step compiles the installer package for the HOST
# (darwin/arm64) even when the TARGET is windows/amd64. That host compilation
# processes main_darwin.go which contains:
#
#   //go:embed embedded/fendit-agent-mac
#   var daemonExe []byte
#
# If embedded/fendit-agent-mac does not already exist as a regular FILE at that
# point, Wails / Go creates an EMPTY DIRECTORY at that path as a placeholder.
# The subsequent lipo call then fails with "Is a directory".
#
# Compiling all agent slices first guarantees both embedded paths are real
# binary files before any wails build command executes.

# ── Step 1: Compile macOS agent (arm64 + amd64) and merge ────────────────────
echo "[1/6] Compiling macOS agent daemon (arm64 + amd64 → universal)..."

( cd "$AGENT_SRC" && \
  CGO_ENABLED=1 GOOS=darwin GOARCH=arm64 \
  go build -ldflags "-s -w" -o "../${INSTALLER_SRC}/embedded/fendit-agent-arm64" . )

( cd "$AGENT_SRC" && \
  CGO_ENABLED=1 GOOS=darwin GOARCH=amd64 \
  go build -ldflags "-s -w" -o "../${INSTALLER_SRC}/embedded/fendit-agent-amd64" . )

# Remove any stale file or directory before lipo writes the output.
rm -rf "${INSTALLER_SRC}/embedded/fendit-agent-mac"
lipo -create \
    "${INSTALLER_SRC}/embedded/fendit-agent-arm64" \
    "${INSTALLER_SRC}/embedded/fendit-agent-amd64" \
    -output "${INSTALLER_SRC}/embedded/fendit-agent-mac"
chmod +x "${INSTALLER_SRC}/embedded/fendit-agent-mac"
rm -f "${INSTALLER_SRC}/embedded/fendit-agent-arm64" \
      "${INSTALLER_SRC}/embedded/fendit-agent-amd64"

# ── Step 2: Cross-compile agent daemon for Windows ────────────────────────────
echo "[2/6] Compiling Windows agent daemon..."
( cd "$AGENT_SRC" && \
  CGO_ENABLED=0 GOOS=windows GOARCH=amd64 \
  go build -ldflags "-s -w" -o "../${INSTALLER_SRC}/embedded/fendit-agent-win.exe" . )

# ── Step 3: Build Windows installer via Wails ─────────────────────────────────
# Both embedded binaries now exist as regular files.
# Wails' binding-generation step will find them and not create directories.
echo "[3/6] Building Windows installer via Wails..."
( cd "$INSTALLER_SRC" && \
  CC=x86_64-w64-mingw32-gcc CGO_ENABLED=1 \
  wails build -platform windows/amd64 -clean )

cp "${INSTALLER_SRC}/build/bin/fendit-installer.exe" "$WIN_OUT/fendit_base.exe"
rm -f "${INSTALLER_SRC}/embedded/fendit-agent-win.exe"

# ── Step 4: Build macOS installer via Wails (universal) ───────────────────────
# darwin/universal produces a fat .app that runs natively on Apple Silicon and
# Intel without Rosetta 2 emulation.
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
