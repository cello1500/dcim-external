$registryPathMachine = "HKLM:\Software\Wilmorite\DCIM"
$registryItemMachine = "TeamsInstalled"
$registryPathUser = "HKCU:\Software\Wilmorite\DCIM"
$registryItemUser = "TeamsInstalled"
$registryItemProvisionedApp = "TeamsProvisionedApp"

# Check if Teams is already installed on the machine
if (-not (Test-Path -Path $registryPathMachine) -or 
    ((Get-Item -LiteralPath $registryPathMachine).GetValue($registryItemMachine, $null)) -eq 0 -or
    ($null -eq (Get-Item -LiteralPath $registryPathMachine).GetValue($registryItemProvisionedApp, $null))) {
    return
}

# Check if Teams is already installed for the current user
if ((Test-Path -Path $registryPathUser) -and ((Get-Item -LiteralPath $registryPathUser).GetValue($registryItemUser, $null)) -gt 0) {
    return
}

# Install Teams for the current user
$PackageName = Get-ItemPropertyValue -Path $registryPathMachine -Name $registryItemProvisionedApp
Add-AppxPackage -RegisterByFamilyName -MainPackage $PackageName -ErrorAction SilentlyContinue
Start-Process ($ENV:USERPROFILE + '\AppData\Local\Microsoft\WindowsApps\ms-teams.exe')
Start-Sleep -Seconds 30
if (-not (Test-Path -Path "$ENV:LocalAPPDATA\Packages\MSTeams_8wekyb3d8bbwe\LocalCache\Microsoft\MSTeams\app_settings.json")) {
    return
}
# End acitve Teams process
if(Get-Process ms-teams -ErrorAction SilentlyContinue){Get-Process ms-teams | Stop-Process -Force}
# Replace/Set "open_app_in_background" option to true
$SettingsJSON = "$ENV:LocalAPPDATA\Packages\MSTeams_8wekyb3d8bbwe\LocalCache\Microsoft\MSTeams\app_settings.json"
(Get-Content $SettingsJSON -ErrorAction Stop).replace('"open_app_in_background":false', '"open_app_in_background":true') | Set-Content $SettingsJSON -Force

if (-not (Test-Path -Path $registryPathUser)) {
    New-Item -Path $registryPathUser -Force | Out-Null
}

Set-ItemProperty -Path $registryPathUser -Name $registryItemUser -Value 1 -ErrorAction SilentlyContinue | Out-Null

Start-Process ($ENV:USERPROFILE + '\AppData\Local\Microsoft\WindowsApps\ms-teams.exe')
