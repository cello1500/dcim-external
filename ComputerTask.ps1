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

$wingetpath = Get-ChildItem -Path "$env:ProgramFiles\WindowsApps\Microsoft.DesktopAppInstaller_*" -Filter "winget.exe" -Recurse | Sort-Object LastWriteTime -Descending | Select-Object -First 1 -ExpandProperty DirectoryName
#create the sysget alias so winget can be ran as system
new-alias -Name sysget -Value "$wingetpath\winget.exe" -Force

####################################################################################################
# Run winget update command once a day
####################################################################################################
$registryPath = "HKLM:\Software\Wilmorite\DCIM"
$registryItem = "WingetUpdate"

if (-not (Test-Path -Path $registryPath) -or ((Get-Item -LiteralPath $registryPath).GetValue($registryItem, "00000000")) -lt (Get-Date).ToString('yyyyMMdd')) {
    Start-Transcript -Path $ENV:tmp\DCIM-Winget.log -Force

    $out = sysget upgrade --all --silent --accept-package-agreements --accept-source-agreements
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
if ($ENV:COMPUTERNAME -notmatch "^(WIL|ADM|CELLO)" -AND ($ENV:COMPUTERNAME -eq "WMG-DONK" -OR $ENV:COMPUTERNAME -eq "AUTO-96CN704")) {
    if ((Get-Service -Name "Dameware Remote Everywhere" -ErrorAction SilentlyContinue).Status -eq 'Stopped') {
        Start-Service -Name "Dameware Remote Everywhere" -ErrorAction SilentlyContinue
    }

    if (((Get-Service -Name "Dameware Remote Everywhere" -ErrorAction SilentlyContinue).Status -ne 'Running') -and
    ((Get-Date) - (gcim Win32_OperatingSystem).LastBootUpTime).TotalMinutes -gt 10) {
        Start-Transcript -Path $ENV:tmp\DCIM-Dameware.log -Force
        $ProgressPreference = 'SilentlyContinue'
        Invoke-WebRequest -Uri https://api.us3.swi-rc.com/download/getpcinstall.php?iid=34882-16e970c2b7d6f-us3-vLBbYYdySOTtMXBXwOAThXyx-a-25 -OutFile "$ENV:tmp\DamewareAgent.exe"
        Stop-Service "Dameware Remote Everywhere" -ErrorAction SilentlyContinue
        Stop-Process -Name "BASup*" -Force -ErrorAction SilentlyContinue
        $dreInstallPath = "C:\Program Files (x86)\Dameware Remote Everywhere Agent"
        $uninstallExe = "$dreInstallPath\uninstall.exe"

        # Check if the uninstaller exists before proceeding
        if (Test-Path -Path $uninstallExe) {
            # Execute the uninstaller silently
            Start-Process -FilePath $uninstallExe -ArgumentList "/S" -Wait
            Write-Host "Dameware Remote Everywhere agent has been uninstalled."
        } else {
            Write-Host "Dameware Remote Everywhere agent uninstaller not found at $dreInstallPath."
        }

        $timeoutSeconds = 240  # 4 minutes
        $proc = Start-Process -FilePath $ENV:tmp\DamewareAgent.exe -ArgumentList "/S /R" -PassThru
        if (Wait-Process -Id $proc.Id -Timeout $timeoutSeconds -ErrorAction SilentlyContinue) {
            Write-Host "Dameware Agent installation completed within timeout."
        } else {
            Write-Warning "Installation exceeded $($timeoutSeconds / 60) minutes. Terminating msiexec.exe..."
            Stop-Process -Id $proc.Id -Force
        }

        Write-Host "Installation exit code: $($proc.ExitCode)"

        Remove-Item -Path "$ENV:tmp\DamewareAgent.exe" -Force
        Stop-Transcript
    }
}

####################################################################################################
# Remove Shutdown, Sleep and Hybernate options from the Start Menu on conference computers
####################################################################################################

# Check if the computer name ends with "conf" or "conference"
if ($env:COMPUTERNAME -like "*conf" -or $env:COMPUTERNAME -like "*conference") {
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\Start\HideShutDown" -Name "value" -Value 1 -Type DWord
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\Start\HideHibernate" -Name "value" -Value 1 -Type DWord
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\Start\HideSleep" -Name "value" -Value 1 -Type DWord
}


####################################################################################################
# Miscelaneous Registry Settings
####################################################################################################
if ($ENV:COMPUTERNAME -notmatch "^(WIL|ADM|CELLO)") {
    # Hide the messages to sync Consumer OneDrive files
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\OneDrive" -Name "DisableNewAccountDetection" -Value 1 -Type DWord
}

####################################################################################################
# Uninstall Teamviewer
####################################################################################################

if ($ENV:COMPUTERNAME -eq "WMG-ORANGECONF") {
    Start-Transcript -Path $ENV:tmp\DCIM-Teamviewer.log -Force
    "Uninstalling Teamviewer components..."
    Get-Package -AllVersions -Force | Where-Object { $_.Name -match "Teamviewer Host|Teamviewr monitoring|Teamviewer Patch" } | ForEach-Object { $_.Name; sysget uninstall --accept-source-agreements --accept-package-agreements "$_.Name" }
    "What is left..."
    Stop-Transcript
}

return $ret