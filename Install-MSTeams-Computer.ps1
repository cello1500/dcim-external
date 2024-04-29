"Install-MSTeams-Computer.ps1: $ApiKey`n"

return 8

$EXE = "Teamsbootstrapper.exe"
$DownloadExeURL = "https://go.microsoft.com/fwlink/?linkid=2243204&clcid=0x409"

function Start-DownloadFile {
    param(
        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$URL,

        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Path,

        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Name
    )
    Begin {
        # Construct WebClient object
        $WebClient = New-Object -TypeName System.Net.WebClient
    }
    Process {
        # Create path if it doesn't exist
        if (-not(Test-Path -Path $Path)) {
            New-Item -Path $Path -ItemType Directory -Force | Out-Null
        }

        # Start download of file
        $WebClient.DownloadFile($URL, (Join-Path -Path $Path -ChildPath $Name))
    }
    End {
        # Dispose of the WebClient object
        $WebClient.Dispose()
    }
}

$registryPath = "HKLM:\Software\Wilmorite\DCIM"
$registryItem = "TeamsInstalled"
$registryItemProvisionedApp = "TeamsProvisionedApp"

if ((Test-Path -Path $registryPath) -and ((Get-Item -LiteralPath $registryPath).GetValue($registryItem, $null)) -gt 0) {
    return
}

Start-DownloadFile -URL $DownloadExeURL -Path $env:TEMP -Name $EXE

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
    Set-ItemProperty -Path $registryPath -Name $registryItem -Type Dword -Value 0 -ErrorAction SilentlyContinue | Out-Null
    $Result = & "$env:TEMP\$EXE" -x
}

$Result = & "$env:TEMP\$EXE" -p
$ResultPSO = try { $Result | ConvertFrom-Json } catch {$null}

# Check if the installation was successful
if ($null -ne $ResultPSO -and $ResultPSO.success -eq $true) {
    if (-not (Test-Path -Path $registryPath)) {
        New-Item -Path $registryPath -Force | Out-Null
    }

    $ProvApp = Get-ProvisionedAppPackage -Online -ErrorAction SilentlyContinue | Where-Object {$PSItem.DisplayName -eq "MSTeams"}

    if( $ProvApp ) {
        Set-ItemProperty -Path $registryPath -Name $registryItem -Type DWord -Value 1 -ErrorAction SilentlyContinue | Out-Null
        Set-ItemProperty -Path $registryPath -Name $registryItemProvisionedApp -Type String -Value $ProvApp.PackageName -ErrorAction SilentlyContinue | Out-Null
    }
}

Remove-Item -Path "$env:TEMP\$EXE" -Force -ErrorAction SilentlyContinue
