#!/bin/bash
set -e

# --- 1. IDENTIFICATIE ---
if [ "$EUID" -ne 0 ]; then echo "[-] Fout: Draai dit script als root."; exit 1; fi

INSTALLER_PATH=$(ls -t fendit-agent*.deb fendit-agent*.rpm 2>/dev/null | head -n 1)

if [ -z "$INSTALLER_PATH" ]; then
    echo "[-] Fout: Geen fendit-agent installer (.deb/.rpm) gevonden in huidige map."
    exit 1
fi

FILENAME=$(basename "$INSTALLER_PATH")
WAZUH_GROUP=$(echo "$FILENAME" | cut -d'_' -f2)
INSTALL_TOKEN=$(echo "$FILENAME" | cut -d'_' -f3 | sed 's/\.deb//;s/\.rpm//')

WAZUH_PATH="/var/ossec"
YARA_SCAN_SCRIPT="$WAZUH_PATH/active-response/bin/yara_scan.sh"
YARA_DEST="/usr/local/bin/yara"

echo "[*] Fendit Linux Onboarding gestart voor Groep: $WAZUH_GROUP"

# --- 2. CONFIGURATIE OPHALEN ---
API_URL="https://api.fendit.eu/v1/agent-config"

CONFIG_JSON=$(curl -sf \
  -H "Authorization: Bearer $INSTALL_TOKEN" \
  -H "X-Install-Group: $WAZUH_GROUP" \
  "$API_URL")

if [ -z "$CONFIG_JSON" ]; then echo "[-] Fout: Kon config niet ophalen."; exit 1; fi

parse_json() {
    echo "$CONFIG_JSON" | grep -oP "(?<=\"$1\":\")[^\"]+"
}

ARCH=$(uname -m)
WAZUH_MANAGER=$(parse_json "agent_wazuh_manager")

# Architectuur-specifieke URL's
if [[ "$ARCH" == "x86_64" ]]; then
    WAZUH_URL=$(parse_json "agent_wazuh_linux_x64_url")
    YARA_URL=$(parse_json "agent_yara_linux_x64_url")
else
    WAZUH_URL=$(parse_json "agent_wazuh_linux_arm_url")
    YARA_URL=$(parse_json "agent_yara_linux_arm_url")
fi

# --- 3. YARA STANDALONE INSTALLATIE ---
echo "[*] Installeren YARA standalone ($ARCH)..."
curl -L "$YARA_URL" -o /tmp/yara.tar.gz
mkdir -p /tmp/yara_unpack
tar -xzf /tmp/yara.tar.gz -C /tmp/yara_unpack/
mv /tmp/yara_unpack/yara "$YARA_DEST"
chown root:root "$YARA_DEST"
chmod 755 "$YARA_DEST"

# --- 4. WAZUH AGENT INSTALLATIE ---
echo "[*] Installeren Wazuh Agent..."
curl -L "$WAZUH_URL" -o /tmp/wazuh_agent.pkg

if command -v dpkg &> /dev/null; then
    WAZUH_MANAGER="$WAZUH_MANAGER" WAZUH_AGENT_GROUP="$WAZUH_GROUP" dpkg -i /tmp/wazuh_agent.pkg
else
    WAZUH_MANAGER="$WAZUH_MANAGER" WAZUH_AGENT_GROUP="$WAZUH_GROUP" rpm -i /tmp/wazuh_agent.pkg
fi

# --- 5. DEPLOY YARA SCAN SCRIPT & SHARED DIR ---
echo "[*] Voorbereiden YARA omgeving..."
mkdir -p "$WAZUH_PATH/etc/shared"
chown root:wazuh "$WAZUH_PATH/etc/shared"
chmod 770 "$WAZUH_PATH/etc/shared"

cat <<EOF > "$YARA_SCAN_SCRIPT"
#!/bin/bash
YARA_BIN="$YARA_DEST"
YARA_RULES="$WAZUH_PATH/etc/shared/mcp_rules.yarc"
LOG_FILE="$WAZUH_PATH/logs/active-responses.log"

read INPUT
FILE_PATH=\$(echo "\$INPUT" | grep -oP '(?<="file":")[^"]+')

if [ -z "\$FILE_PATH" ] || [ ! -f "\$FILE_PATH" ]; then exit 0; fi

SCAN_RESULT="\$(\$YARA_BIN -w "\$YARA_RULES" "\$FILE_PATH" 2>/dev/null)"

if [ ! -z "\$SCAN_RESULT" ]; then
    ESCAPED_RESULT=\$(echo "\$SCAN_RESULT" | sed 's/"/\\"/g')
    echo "{\"yara_scan\": \"hit\", \"match\": \"\$ESCAPED_RESULT\", \"file\": \"\$FILE_PATH\"}" >> "\$LOG_FILE"
fi
exit 0
EOF

chown root:wazuh "$YARA_SCAN_SCRIPT"
chmod 750 "$YARA_SCAN_SCRIPT"

# --- 6. STARTEN ---
systemctl restart wazuh-agent
rm -rf /tmp/yara.tar.gz /tmp/wazuh_agent.pkg /tmp/yara_unpack
echo "[SUCCESS] Linux Agent is volledig operationeel."
