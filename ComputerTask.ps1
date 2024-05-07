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

Start-Transcript -Path $ENV:tmp\ComputerTask.log -Force

####################################################################################################
# Install Microsoft Teams
####################################################################################################
$registryPath = "HKLM:\Software\Wilmorite\DCIM"
$registryItem = "TeamsInstalled"

if (-not (Test-Path -Path $registryPath) -or ((Get-Item -LiteralPath $registryPath).GetValue($registryItem, $null)) -eq 0) {
    $ret = RunWebScript -url "https://raw.githubusercontent.com/cello1500/dcim-external/main/Install-MSTeams-Computer.ps1"
}

Stop-Transcript

return $ret