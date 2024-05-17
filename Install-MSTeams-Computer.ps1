$registryPath = "HKLM:\Software\Wilmorite\DCIM"
$registryItem = "TeamsInstalled"
$registryItemProvisionedApp = "TeamsProvisionedApp"

if ((Test-Path -Path $registryPath) -and ((Get-Item -LiteralPath $registryPath).GetValue($registryItem, $null)) -gt 0) {
    return 10
}

$Appx = Get-AppxPackage -AllUsers | Where-Object {$PSItem. Name -eq "MSTeams"}
$ProvApp = Get-ProvisionedAppPackage -Online | Where-Object {$PSItem. DisplayName -eq "MSTeams"}

if ($Appx -OR $ProvApp) {
    $Appx = Get-AppxPackage -AllUsers | Where-Object {$PSItem.Name -eq "MSTeams"}
    if ($Appx) {
        $Appx | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue
    }
    if ($ProvApp) {
        Try { $ProvApp | Remove-AppxProvisionedPackage -Online -AllUsers -ErrorAction SilentlyContinue } Catch { $null }
    }
    if (-not (Test-Path -Path $registryPath)) {
        New-Item -Path $registryPath -Force | Out-Null
    }
}

Set-ItemProperty -Path $registryPath -Name $registryItem -Type Dword -Value 0 -ErrorAction SilentlyContinue | Out-Null

$wingetexe = Resolve-Path "C:\Program Files\WindowsApps\Microsoft.DesktopAppInstaller_*_x64__8wekyb3d8bbwe\winget.exe"
    if ($wingetexe){
           $SystemContext = $wingetexe[-1].Path
    }
#create the sysget alias so winget can be ran as system
new-alias -Name sysget -Value "$systemcontext"

$out = sysget install Microsoft.Teams --accept-package-agreements --accept-source-agreements --scope machine
"Winget Teams install output: $out"

# Check if the installation was successful
if ($?) {
    if (-not (Test-Path -Path $registryPath)) {
        New-Item -Path $registryPath -Force | Out-Null
    }

    $ProvApp = Get-ProvisionedAppPackage -Online -ErrorAction SilentlyContinue | Where-Object {$PSItem.DisplayName -eq "MSTeams"}

    if( $ProvApp ) {
        Set-ItemProperty -Path $registryPath -Name $registryItem -Type DWord -Value 1 -ErrorAction SilentlyContinue | Out-Null
        Set-ItemProperty -Path $registryPath -Name $registryItemProvisionedApp -Type String -Value $ProvApp.PackageName -ErrorAction SilentlyContinue | Out-Null
    }
}
