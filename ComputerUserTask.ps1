function RunWebScript {
    param (
        [string]$url
    )

    Try {
        $script = Invoke-WebRequest -Uri $url -UseBasicParsing | Select-Object -ExpandProperty Content
    
        Invoke-Expression $script -ErrorAction Continue
    } Catch {
        return 5
    }

    return $LASTEXITCODE
}

$ret = 0

if (-not ((Get-WmiObject Win32_OperatingSystem).Caption).Contains("Windows 11")) {
    return 1
}

####################################################################################################
# Install Microsoft Teams for the current user
####################################################################################################
$registryPathUser = "HKCU:\Software\Wilmorite\DCIM"
$registryItemUser = "TeamsInstalled"

# Check if Teams is already installed for the current user
if (-not (Test-Path -Path $registryPathUser) -or ((Get-Item -LiteralPath $registryPathUser).GetValue($registryItemUser, 0)) -eq 0) {
    Start-Transcript -Path $ENV:tmp\DCIM-Teams.log -Force
    $ret = RunWebScript -url "https://raw.githubusercontent.com/cello1500/dcim-external/main/Install-MSTeams-User.ps1"
    Stop-Transcript
}

####################################################################################################
# Run winget update command once a day
####################################################################################################
$registryPath = "HKCU:\Software\Wilmorite\DCIM"
$registryItem = "WingetUpdate"

if (-not (Test-Path -Path $registryPath) -or ((Get-Item -LiteralPath $registryPath).GetValue($registryItem, "00000000")) -lt (Get-Date).ToString('yyyyMMdd')) {
    Start-Transcript -Path $ENV:tmp\DCIM-Winget.log -Force
    if (-not (Test-Path -Path $registryPath)) {
        New-Item -Path $registryPath -Force | Out-Null
    }
    Set-ItemProperty -Path $registryPath -Name $registryItem -Type String -Value "00000000" -ErrorAction SilentlyContinue | Out-Null
    
    $out = winget upgrade --all --scope user --accept-package-agreements --accept-source-agreements
    "Winget upgrade output: $out"

    if ($?) {
        Set-ItemProperty -Path $registryPath -Name $registryItem -Type String -Value (get-date).ToString('yyyyMMdd') -ErrorAction SilentlyContinue | Out-Null
    } else {
        $ret = 15
    }
    Stop-Transcript
}

return $ret