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

if (-not ((Get-WmiObject Win32_OperatingSystem).Caption).Contains("Windows 11")) {
    return 1
}

$ret = 0

$wingetexe = Resolve-Path "C:\Program Files\WindowsApps\Microsoft.DesktopAppInstaller_*_x64__8wekyb3d8bbwe\winget.exe"
    if ($wingetexe){
           $SystemContext = $wingetexe[-1].Path
    }
#create the sysget alias so winget can be ran as system
new-alias -Name sysget -Value "$systemcontext"

####################################################################################################
# Run winget update command once a day
####################################################################################################
$registryPath = "HKLM:\Software\Wilmorite\DCIM"
$registryItem = "WingetUpdate"

if (-not (Test-Path -Path $registryPath) -or ((Get-Item -LiteralPath $registryPath).GetValue($registryItem, "00000000")) -lt (Get-Date).ToString('yyyyMMdd')) {
    Start-Transcript -Path $ENV:tmp\DCIM-Winget.log -Force

    $out = sysget upgrade --all --accept-package-agreements --accept-source-agreements
    "Winget upgrade output: $out"

    if (-not (Test-Path -Path $registryPath)) {
        New-Item -Path $registryPath -Force | Out-Null
    }

    if ($?) {
            Set-ItemProperty -Path $registryPath -Name $registryItem -Type String -Value (get-date).ToString('yyyyMMdd') -ErrorAction SilentlyContinue | Out-Null
    } else {
            Set-ItemProperty -Path $registryPath -Name $registryItem -Type String -Value "00000000" -ErrorAction SilentlyContinue | Out-Null
            $ret = 15
    }

    Stop-Transcript
}

####################################################################################################
# Install Microsoft Teams
####################################################################################################
$registryPath = "HKLM:\Software\Wilmorite\DCIM"
$registryItem = "TeamsInstalled"

if (-not (Test-Path -Path $registryPath) -or ((Get-Item -LiteralPath $registryPath).GetValue($registryItem, 0)) -eq 0) {
    Start-Transcript -Path $ENV:tmp\DCIM-Teams.log -Force
    $ret = RunWebScript -url "https://raw.githubusercontent.com/cello1500/dcim-external/main/Install-MSTeams-Computer.ps1"
    Stop-Transcript
}

####################################################################################################
# Install Dameware Remote Everywhere
####################################################################################################
if ($ENV:COMPUTERNAME -notmatch "^(WIL|ADM|CELLO)") {
    if ((Get-Service -Name "Dameware Remote Everywhere" -ErrorAction SilentlyContinue).Status -eq 'Stopped') {
        Start-Service -Name "mamae" -ErrorAction SilentlyContinue
    }

    if (-not (Get-Service -Name "Dameware Remote Everywhere" -ErrorAction SilentlyContinue | Where-Object {$_.Status -eq 'Running'}) -and
    ((Get-Date) - (gcim Win32_OperatingSystem).LastBootUpTime).TotalMinutes -gt 10) {
        Start-Transcript -Path $ENV:tmp\DCIM-Dameware.log -Force
        Get-WmiObject -Class Win32_Product | Where-Object { $_.Name -like "*dameware*" } | ForEach-Object {
            $_.Uninstall() | Out-Null
        }

        Invoke-WebRequest -Uri https://github.com/wilmorite/artefacts/raw/refs/heads/main/apps/dameware/DamewareAgent.msi -OutFile "$ENV:tmp\DamewareAgent.msi"
        Stop-Process -Name "DamewareAgent" -Force -ErrorAction SilentlyContinue
        Start-Process -FilePath msiexec.exe -ArgumentList "/i $ENV:tmp\DamewareAgent.msi /qn" -Wait
        $ret = $LASTEXITCODE
        Remove-Item -Path "$ENV:tmp\DamewareAgent.msi" -Force
        Stop-Transcript
    }
}

return $ret