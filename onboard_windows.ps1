# --- 1. IDENTIFICATIE ---
$Installer = Get-ChildItem -Filter "fendit-agent*.msi" | Sort-Object LastWriteTime -Descending | Select-Object -First 1

if (-not $Installer) {
    Write-Error "[-] Fout: Geen fendit-agent.msi gevonden."
    exit 1
}

$Filename = $Installer.Name
$Parts = $Filename.Split('_')
$WazuhGroup = $Parts[1]
$InstallToken = $Parts[2].Replace(".msi", "")

$WazuhPath = "C:\Program Files (x86)\ossec-agent"
$YaraDir = "C:\Program Files\yara"
$YaraDest = "$YaraDir\yara64.exe"

Write-Host "[*] Fendit Windows Onboarding gestart voor Groep: $WazuhGroup"

# --- 2. CONFIGURATIE OPHALEN ---
$ApiUrl = "https://api.fendit.eu/v1/agent-config"
$Headers = @{
    "Authorization" = "Bearer $InstallToken"
    "X-Install-Group" = $WazuhGroup
}

$Config = Invoke-RestMethod -Uri $ApiUrl -Method Get -Headers $Headers
$WazuhManager = $Config.agent_wazuh_manager
$WazuhUrl = $Config.agent_wazuh_windows_url
$YaraUrl = $Config.agent_yara_windows_url

# --- 3. YARA STANDALONE INSTALLATIE ---
Write-Host "[*] Installeren YARA standalone..."
if (!(Test-Path $YaraDir)) { New-Item -ItemType Directory -Path $YaraDir -Force }

Invoke-WebRequest -Uri $YaraUrl -OutFile "C:\Windows\Temp\yara.zip"
Expand-Archive -Path "C:\Windows\Temp\yara.zip" -DestinationPath "C:\Windows\Temp\yara_unpack" -Force
Move-Item -Path "C:\Windows\Temp\yara_unpack\yara64.exe" -Destination $YaraDest -Force

# --- 4. WAZUH AGENT INSTALLATIE ---
Write-Host "[*] Installeren Wazuh Agent..."
Invoke-WebRequest -Uri $WazuhUrl -OutFile "C:\Windows\Temp\wazuh_agent.msi"

$MsiArgs = "/i C:\Windows\Temp\wazuh_agent.msi /qn WAZUH_MANAGER='$WazuhManager' WAZUH_AGENT_GROUP='$WazuhGroup'"
Start-Process msiexec.exe -ArgumentList $MsiArgs -Wait

# --- 5. DEPLOY YARA SCAN SCRIPT & SHARED DIR ---
Write-Host "[*] Voorbereiden YARA omgeving..."
if (!(Test-Path "$WazuhPath\etc\shared")) { New-Item -ItemType Directory -Path "$WazuhPath\etc\shared" -Force }

$YaraScript = @"
`$InputData = Read-Host
`$Json = `$InputData | ConvertFrom-Json
`$FilePath = `$Json.parameters.extra_args[0]

if (-not (Test-Path `$FilePath)) { exit 0 }

`$ScanResult = & "$YaraDest" -w "$WazuhPath\etc\shared\mcp_rules.yarc" "`$FilePath" 2>`$null

if (`$ScanResult) {
    `$Hit = @{
        yara_scan = "hit"
        match = `$ScanResult -join ", "
        file = `$FilePath
    }
    `$Hit | ConvertTo-Json -Compress | Add-Content "$WazuhPath\logs\active-responses.log"
}
"@

$YaraScript | Out-File -FilePath "$WazuhPath\active-response\bin\yara_scan.ps1" -Encoding ascii

# --- 6. STARTEN & OPSCHONEN ---
Restart-Service -Name "Wazuh"
Remove-Item -Path "C:\Windows\Temp\yara*" -Recurse -Force
Remove-Item -Path "C:\Windows\Temp\wazuh_agent.msi" -Force

Write-Host "[SUCCESS] Windows Agent is volledig operationeel."
