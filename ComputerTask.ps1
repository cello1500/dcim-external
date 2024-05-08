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

if ($env:COMPUTERNAME -ne "NOAD01" -and $env:COMPUTERNAME -ne "AUTO-J9NH624") {
    return 1
}

####################################################################################################
# Install Microsoft Teams
####################################################################################################
Start-Transcript -Path $ENV:tmp\dcim-teams.log -Force

$registryPath = "HKLM:\Software\Wilmorite\DCIM"
$registryItem = "TeamsInstalled"

if (-not (Test-Path -Path $registryPath) -or ((Get-Item -LiteralPath $registryPath).GetValue($registryItem, $null)) -eq 0) {
    $ret = RunWebScript -url "https://raw.githubusercontent.com/cello1500/dcim-external/main/Install-MSTeams-Computer.ps1"
}

Stop-Transcript

####################################################################################################
# Run winget update command once a day
####################################################################################################
Start-Transcript -Path $ENV:tmp\dcim-winget.log -Force

$registryPath = "HKLM:\Software\Wilmorite\DCIM"
$registryItem = "WingetUpdate"

if (-not (Test-Path -Path $registryPath) -or ((Get-Item -LiteralPath $registryPath).GetValue($registryItem, "00000000")) -le (Get-Date).ToString('yyyyMMdd')) {
    winget upgrade --all --accept-package-agreements --accept-source-agreements

    if (-not (Test-Path -Path $registryPath)) {
        New-Item -Path $registryPath -Force | Out-Null
    }
    Set-ItemProperty -Path $registryPath -Name $registryItem -Type String -Value ((get-date).AddDays(1)).ToString('yyyyMMdd') -ErrorAction SilentlyContinue | Out-Null
}

Stop-Transcript

return $ret