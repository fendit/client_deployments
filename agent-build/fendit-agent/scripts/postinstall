#!/bin/bash
set -e

# --- 1. IDENTIFICATIE ---
USER_NAME=$(stat -f "%Su" /dev/console)
INSTALLER_PATH=$(ls -t /Users/"$USER_NAME"/Downloads/fendit-agent*.pkg 2>/dev/null | head -n 1)

if [ -z "$INSTALLER_PATH" ]; then
    echo "[-] Fout: Geen fendit-agent installer gevonden in Downloads."
    exit 1
fi

FILENAME=$(basename "$INSTALLER_PATH")
WAZUH_GROUP=$(echo "$FILENAME" | cut -d'_' -f2)
INSTALL_TOKEN=$(echo "$FILENAME" | cut -d'_' -f3 | sed 's/\.pkg//')

WAZUH_PATH="/Library/Ossec"
YARA_SCAN_SCRIPT="$WAZUH_PATH/active-response/bin/yara_scan.sh"
YARA_DEST="/usr/local/bin/yara"

echo "[*] Fendit Onboarding gestart voor Groep: $WAZUH_GROUP"

# --- 2. DYNAMISCHE CONFIGURATIE OPHALEN ---
API_URL="https://api.fendit.eu/v1/agent-config"

echo "[*] Contact maken met Fendit Control Plane..."
CONFIG_JSON=$(curl -sf \
  -H "Authorization: Bearer $INSTALL_TOKEN" \
  -H "X-Install-Group: $WAZUH_GROUP" \
  "$API_URL")

if [ -z "$CONFIG_JSON" ]; then
    echo "[-] Fout: Kon configuratie niet ophalen."
    exit 1
fi

parse_json() {
    osascript -l JavaScript -e "function run(argv) { return JSON.parse(argv[0])['$1']; }" "$CONFIG_JSON"
}

ARCH=$(uname -m)
WAZUH_MANAGER=$(parse_json "agent_wazuh_manager")

if [[ "$ARCH" == "arm64" ]]; then
    WAZUH_URL=$(parse_json "agent_wazuh_apple_url")
    YARA_URL=$(parse_json "agent_yara_apple_url")
else
    WAZUH_URL=$(parse_json "agent_wazuh_intel_url")
    YARA_URL=$(parse_json "agent_yara_intel_url")
fi

# --- 3. YARA STANDALONE INSTALLATIE ---
echo "[*] Installeren YARA engine ($ARCH)..."
mkdir -p /tmp/yara_install
curl -L "$YARA_URL" -o /tmp/yara_install/yara.zip
unzip -q /tmp/yara_install/yara.zip -d /tmp/yara_install/

mkdir -p /usr/local/bin
mv /tmp/yara_install/yara "$YARA_DEST"
chown root:wheel "$YARA_DEST"
chmod 755 "$YARA_DEST"

# Verwijder macOS 'quarantine' flag
xattr -d com.apple.quarantine "$YARA_DEST" 2>/dev/null || true

# --- 4. WAZUH AGENT INSTALLATIE ---
echo "[*] Installeren Fendit Agent..."
curl -L "$WAZUH_URL" -o /tmp/wazuh_actual.pkg

echo "WAZUH_MANAGER='$WAZUH_MANAGER'" > /tmp/wazuh_envs
echo "WAZUH_AGENT_GROUP='$WAZUH_GROUP'" >> /tmp/wazuh_envs

/usr/sbin/installer -pkg /tmp/wazuh_actual.pkg -target /

# --- 5. DEPLOY YARA SCAN SCRIPT & PREPARE ENVIRONMENT ---
echo "[*] Omgeving voorbereiden voor YARA scans..."

# Belangrijk: Maak de shared map aan met de juiste groep (wazuh)
mkdir -p "$WAZUH_PATH/etc/shared"
chown root:wazuh "$WAZUH_PATH/etc/shared"
chmod 770 "$WAZUH_PATH/etc/shared"

cat <<EOF > "$YARA_SCAN_SCRIPT"
#!/bin/bash
# Fendit Real-time YARA Scanner
YARA_BIN="$YARA_DEST"
YARA_RULES="$WAZUH_PATH/etc/shared/mcp_rules.yarc"
LOG_FILE="$WAZUH_PATH/logs/active-responses.log"

# Wazuh stuurt JSON via stdin
read INPUT
FILE_PATH=\$(echo "\$INPUT" | grep -oP '(?<="file":")[^"]+')

if [ -z "\$FILE_PATH" ] || [ ! -f "\$FILE_PATH" ]; then exit 0; fi

# Scan uitvoeren
SCAN_RESULT="\$(\$YARA_BIN -w "\$YARA_RULES" "\$FILE_PATH" 2>/dev/null)"

if [ ! -z "\$SCAN_RESULT" ]; then
    ESCAPED_RESULT=\$(echo "\$SCAN_RESULT" | sed 's/"/\\"/g')
    echo "{\"yara_scan\": \"hit\", \"match\": \"\$ESCAPED_RESULT\", \"file\": \"\$FILE_PATH\"}" >> "\$LOG_FILE"
fi
exit 0
EOF

# Zet permissies op het scanscript
chown root:wazuh "$YARA_SCAN_SCRIPT"
chmod 750 "$YARA_SCAN_SCRIPT"

# --- 6. OPSCHONEN & STARTEN ---
"$WAZUH_PATH/bin/wazuh-control" start 2>/dev/null || true
rm -rf /tmp/yara_install /tmp/wazuh_actual.pkg /tmp/wazuh_envs

echo "-------------------------------------------------------"
echo "[SUCCESS] Fendit Agent is nu actief (Groep: wazuh)."
echo "-------------------------------------------------------"
