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

Start-Transcript -Path $ENV:tmp\ComputeUserTask.log -Force

####################################################################################################
# Install Microsoft Teams for the current user
####################################################################################################
$registryPathUser = "HKCU:\Software\Wilmorite\DCIM"
$registryItemUser = "TeamsInstalled"

# Check if Teams is already installed for the current user
if (-not (Test-Path -Path $registryPathUser) -or ((Get-Item -LiteralPath $registryPathUser).GetValue($registryItemUser, $null)) -eq 0) {
    $ret = RunWebScript -url "https://raw.githubusercontent.com/cello1500/dcim-external/main/Install-MSTeams-User.ps1"
}

Stop-Transcript

return $ret