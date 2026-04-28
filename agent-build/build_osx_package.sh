#!/bin/bash

# --- BUILD SCRIP TO BUILD .PKG PACKAGE ---

# --- 1. GO TO DEV FOLDER ---

cd ./fendit-agent

# --- 2. MAKE postinstall executable ---

chmod +x ./scripts/postinstall

# --- 3. MAKE postinstall executable ---

pkgbuild --nopayload --scripts ./fendit-agent/scripts --identifier com.fendit.agent --version 1.0 fendit-unsigned.pkg
productbuild --distribution ./fendit-agent/distribution.xml --resources ./fendit-agent/Resources --package-path ./fendit-agent_TEST-DEPLOY.pkg


# --- 4. Sign PKG package ---

