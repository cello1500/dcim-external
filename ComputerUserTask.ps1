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
if ($env:COMPUTERNAME -ne "NOAD01" -and $env:COMPUTERNAME -ne "AUTO-J9NH624") {
    return 1
}

if (-not ((Get-WmiObject Win32_OperatingSystem).Caption).Contains("Windows 11")) {
    return 1
}

####################################################################################################
# Install Microsoft Teams for the current user
####################################################################################################
Start-Transcript -Path $ENV:tmp\DCIM-Teams.log -Force

$registryPathUser = "HKCU:\Software\Wilmorite\DCIM"
$registryItemUser = "TeamsInstalled"

# Check if Teams is already installed for the current user
if (-not (Test-Path -Path $registryPathUser) -or ((Get-Item -LiteralPath $registryPathUser).GetValue($registryItemUser, $null)) -eq 0) {
    $ret = RunWebScript -url "https://raw.githubusercontent.com/cello1500/dcim-external/main/Install-MSTeams-User.ps1"
}

Stop-Transcript

####################################################################################################
# Run winget update command once a day
####################################################################################################
Start-Transcript -Path $ENV:tmp\DCIM-Winget.log -Force

"This is Winget"

$registryPath = "HKCU:\Software\Wilmorite\DCIM"
$registryItem = "WingetUpdate"

if (-not (Test-Path -Path $registryPath) -or ((Get-Item -LiteralPath $registryPath).GetValue($registryItem, "00000000")) -le (Get-Date).ToString('yyyyMMdd')) {
    $out = winget upgrade --all --scope user --accept-package-agreements --accept-source-agreements
    "Winget upgrade output: $out"

    if (-not (Test-Path -Path $registryPath)) {
        New-Item -Path $registryPath -Force | Out-Null
    }

    if ($?) {
            Set-ItemProperty -Path $registryPath -Name $registryItem -Type String -Value ((get-date).AddDays(1)).ToString('yyyyMMdd') -ErrorAction SilentlyContinue | Out-Null
    } else {
            Set-ItemProperty -Path $registryPath -Name $registryItem -Type String -Value "00000000" -ErrorAction SilentlyContinue | Out-Null
            $ret = 15
    }
}

Stop-Transcript

return $ret