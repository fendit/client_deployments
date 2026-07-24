#!/bin/bash
# Fendit Build Pipeline
#
# Outputs:
#   release/windows/fendit_installer.exe  — WebView2 GUI installer (Windows amd64)
#   release/osx/fendit_installer.pkg  — Fyne GUI installer (macOS universal, pkg-wrapped)
#
# Prerequisites (macOS arm64 runner):
#   go, pkgbuild, lipo, sips, iconutil, x86_64-w64-mingw32-gcc
#   goversioninfo  — go install github.com/josephspurrier/goversioninfo/cmd/goversioninfo@latest

set -euo pipefail

INSTALLER_SRC="fendit-installer"
AGENT_SRC="fendit-agent"
OUT_DIR="release"
MAC_OUT="$OUT_DIR/osx"
WIN_OUT="$OUT_DIR/windows"
TMP_DIR="tmp_build"

# Strip leading 'v' from git tag so pkgbuild gets a clean semver string.
VERSION="${VERSION:-1.0.0}"
VERSION="${VERSION#v}"

echo "Fendit Build Pipeline — v${VERSION}"

# ── Sanity checks ─────────────────────────────────────────────────────────────
for cmd in go pkgbuild lipo sips iconutil x86_64-w64-mingw32-gcc; do
  if ! command -v "$cmd" &>/dev/null; then
    echo "ERROR: '$cmd' not found. Install missing tools before running this script."
    exit 1
  fi
done

# goversioninfo is a Go tool — install it automatically if missing.
if ! command -v goversioninfo &>/dev/null; then
  echo "[*] Installing goversioninfo..."
  go install github.com/josephspurrier/goversioninfo/cmd/goversioninfo@latest
fi

# ── Clean slate ───────────────────────────────────────────────────────────────
rm -rf "$OUT_DIR" "$TMP_DIR" tmp_pkg_build  # tmp_pkg_build = legacy name
mkdir -p "$MAC_OUT" "$WIN_OUT"
mkdir -p "$TMP_DIR/payload" "$TMP_DIR/scripts" "$TMP_DIR/fendit.iconset" "$TMP_DIR/ico_sizes"
mkdir -p "${INSTALLER_SRC}/embedded"

# ── Step 0a: Generate valid icon.ico from the Fendit logo PNG ────────────────
# Produces 16/32/48/256 px PNGs via sips, then combines them into a valid
# multi-size ICO using Python's built-in struct module (no ImageMagick needed).
echo "[0a/6] Generating Windows icon.ico from logo PNG..."
SRC_PNG="${INSTALLER_SRC}/assets/fendit.png"
for size in 16 32 48 256; do
  sips -z "$size" "$size" "$SRC_PNG" --out "$TMP_DIR/ico_sizes/icon_${size}.png" 2>/dev/null
done
python3 - "$TMP_DIR/ico_sizes" "${AGENT_SRC}/icon.ico" << 'PYEOF'
import struct, sys, glob, os
ico_dir, out_path = sys.argv[1], sys.argv[2]
pngs   = sorted(glob.glob(os.path.join(ico_dir, 'icon_*.png')))
images = [open(p, 'rb').read() for p in pngs]
count  = len(images)
offset = 6 + count * 16
header = struct.pack('<HHH', 0, 1, count)
entries = b''
for data in images:
    w = struct.unpack('>I', data[16:20])[0]
    h = struct.unpack('>I', data[20:24])[0]
    entries += struct.pack('<BBBBHHII', min(w, 255), min(h, 255), 0, 0, 1, 32, len(data), offset)
    offset += len(data)
with open(out_path, 'wb') as f:
    f.write(header + entries + b''.join(images))
sizes = [struct.unpack('>I', open(p,'rb').read()[16:20])[0] for p in pngs]
print(f"  icon.ico: {count} sizes — {', '.join(str(s)+'px' for s in sizes)}")
PYEOF

# ── Step 0b: Generate Windows PE version resources ────────────────────────────
# goversioninfo reads versioninfo.json and emits resource_windows_amd64.syso
# which go build automatically links into the Windows PE binary.
# CompanyName, ProductName etc. are used by Defender as a publisher trust signal.
echo "[0b/6] Generating Windows PE version resources..."
# Copy the freshly generated ICO to the installer source so goversioninfo can
# embed it there too (gives the installer EXE a file icon in Downloads/Explorer
# AND lets setWindowIcon() load it at runtime for the title bar).
cp "${AGENT_SRC}/icon.ico" "${INSTALLER_SRC}/icon.ico"
( cd "$AGENT_SRC"    && GOOS=windows GOARCH=amd64 goversioninfo -icon=icon.ico -o resource_windows_amd64.syso )
( cd "$INSTALLER_SRC" && GOOS=windows GOARCH=amd64 goversioninfo -icon=icon.ico -o resource_windows_amd64.syso )

# ── Step 0: Generate macOS template tray icon ─────────────────────────────────
# sips converts the Fendit logo to the 22×22 PNG that the macOS
# menu bar renders as a template image (auto light/dark adaptation).
echo "[0/6] Generating macOS tray icon..."
sips -s format png \
     --resampleWidth 22 \
     "${INSTALLER_SRC}/assets/fendit.png" \
     --out "${AGENT_SRC}/icon_template.png" \
     2>/dev/null \
  || echo "  WARNING: sips failed — using existing icon_template.png if present."

# ── Step 1: Compile macOS agent (arm64 + amd64 → universal) ──────────────────
# Both slices must be real files before the installer embedding step runs —
# otherwise go:embed sees a missing file and aborts.
echo "[1/6] Compiling macOS agent daemon (arm64 + amd64 → universal)..."

( cd "$AGENT_SRC" && \
  CGO_ENABLED=1 GOOS=darwin GOARCH=arm64 \
  go build -ldflags "-s -w" -o "../${INSTALLER_SRC}/embedded/fendit-agent-arm64" . )

( cd "$AGENT_SRC" && \
  CGO_ENABLED=1 GOOS=darwin GOARCH=amd64 \
  CC="clang -arch x86_64" \
  go build -ldflags "-s -w" -o "../${INSTALLER_SRC}/embedded/fendit-agent-amd64" . )

rm -rf "${INSTALLER_SRC}/embedded/fendit-agent-mac"
lipo -create \
    "${INSTALLER_SRC}/embedded/fendit-agent-arm64" \
    "${INSTALLER_SRC}/embedded/fendit-agent-amd64" \
    -output "${INSTALLER_SRC}/embedded/fendit-agent-mac"
chmod +x "${INSTALLER_SRC}/embedded/fendit-agent-mac"
rm -f "${INSTALLER_SRC}/embedded/fendit-agent-arm64" \
      "${INSTALLER_SRC}/embedded/fendit-agent-amd64"

# ── Step 2: Cross-compile Windows agent ──────────────────────────────────────
echo "[2/6] Compiling Windows agent daemon..."
( cd "$AGENT_SRC" && \
  CGO_ENABLED=0 GOOS=windows GOARCH=amd64 \
  go build -ldflags "-s -w" -o "../${INSTALLER_SRC}/embedded/fendit-agent-win.exe" . )

# ── Step 3: Build Windows installer (Fyne) ───────────────────────────────────
# CGO required for Fyne (OpenGL). -H windowsgui suppresses the console window.
# Both embedded/* files must exist before this step (done above).
echo "[3/6] Building Windows installer (Fyne/Go → amd64)..."
( cd "$INSTALLER_SRC" && \
  CC=x86_64-w64-mingw32-gcc CGO_ENABLED=1 GOOS=windows GOARCH=amd64 \
  go build \
    -ldflags "-H windowsgui -s -w" \
    -o "../$WIN_OUT/fendit_installer.exe" \
    . )

rm -f "${INSTALLER_SRC}/embedded/fendit-agent-win.exe"

# ── Step 4: Build macOS installer (Fyne, arm64 + amd64 → universal) ──────────
# Fyne requires CGO on macOS (OpenGL + Cocoa). Cross-compiling amd64 from an
# arm64 host requires explicitly targeting x86_64 in the C toolchain.
echo "[4/6] Building macOS installer (Fyne/Go → universal)..."
( cd "$INSTALLER_SRC" && \
  CGO_ENABLED=1 GOOS=darwin GOARCH=arm64 \
  go build -ldflags "-s -w" -o "../$TMP_DIR/installer-arm64" . )

( cd "$INSTALLER_SRC" && \
  CGO_ENABLED=1 GOOS=darwin GOARCH=amd64 \
  CC="clang -arch x86_64" \
  go build -ldflags "-s -w" -o "../$TMP_DIR/installer-amd64" . )

lipo -create \
    "$TMP_DIR/installer-arm64" \
    "$TMP_DIR/installer-amd64" \
    -output "$TMP_DIR/fendit-installer"
chmod +x "$TMP_DIR/fendit-installer"
rm -f "${INSTALLER_SRC}/embedded/fendit-agent-mac" \
      "$TMP_DIR/installer-arm64" \
      "$TMP_DIR/installer-amd64"

# ── Step 5: Package macOS .app bundle → .pkg ─────────────────────────────────
echo "[5/6] Packaging macOS .app..."

# Build icon.icns from the Fendit logo (single source of truth).
SRC_ICON="${INSTALLER_SRC}/assets/fendit.png"
ICONSET="$TMP_DIR/fendit.iconset"
for size in 16 32 128 256 512; do
  sips -z $size $size "$SRC_ICON" \
    --out "${ICONSET}/icon_${size}x${size}.png" 2>/dev/null
  double=$((size * 2))
  [ $double -le 1024 ] && \
    sips -z $double $double "$SRC_ICON" \
      --out "${ICONSET}/icon_${size}x${size}@2x.png" 2>/dev/null
done
iconutil -c icns "$ICONSET" -o "$TMP_DIR/icon.icns"

# Assemble the .app bundle directory tree.
APP_BUNDLE="$TMP_DIR/payload/Fendit Security.app"
mkdir -p "$APP_BUNDLE/Contents/MacOS"
mkdir -p "$APP_BUNDLE/Contents/Resources"

cp "$TMP_DIR/fendit-installer"  "$APP_BUNDLE/Contents/MacOS/fendit-installer"
cp "$TMP_DIR/icon.icns"         "$APP_BUNDLE/Contents/Resources/icon.icns"

cat > "$APP_BUNDLE/Contents/Info.plist" << PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>CFBundleExecutable</key><string>fendit-installer</string>
  <key>CFBundleIconFile</key><string>icon</string>
  <key>CFBundleIdentifier</key><string>eu.fendit.installer</string>
  <key>CFBundleName</key><string>Fendit Security</string>
  <key>CFBundleDisplayName</key><string>Fendit Security</string>
  <key>CFBundleVersion</key><string>${VERSION}</string>
  <key>CFBundleShortVersionString</key><string>${VERSION}</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>NSHighResolutionCapable</key><true/>
  <key>NSPrincipalClass</key><string>NSApplication</string>
  <key>LSMinimumSystemVersion</key><string>11.0</string>
  <key>NSRequiresAquaSystemAppearance</key><false/>
</dict></plist>
PLIST

# Postinstall script opens the app in the console user's session.
cp pkg_scripts/postinstall "$TMP_DIR/scripts/postinstall"
chmod +x "$TMP_DIR/scripts/postinstall"

pkgbuild \
  --root             "$TMP_DIR/payload" \
  --scripts          "$TMP_DIR/scripts" \
  --identifier       "eu.fendit.installer" \
  --version          "${VERSION}" \
  --install-location "/Applications" \
  "$MAC_OUT/fendit_installer.pkg"

# ── Step 6: Clean up ──────────────────────────────────────────────────────────
echo "[6/6] Cleaning up..."
rm -rf "$TMP_DIR"

echo ""
echo "Build complete!"
echo "  Windows: ./$WIN_OUT/fendit_installer.exe"
echo "  macOS:   ./$MAC_OUT/fendit_installer.pkg"
