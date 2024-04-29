function RunScript {
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

if ($env:COMPUTERNAME -ne "NOAD01") {
    return 1
}

#Start-Transcript -Path $ENV:tmp\ComputerTask.log -Force
Start-Transcript -Path c:\windows\temp\ComputerTask.log -Force

"Entering ComputerTask.ps1"

$ret = RunScript -url "https://raw.githubusercontent.com/cello1500/dcim-external/main/Install-MSTeams-Computer.ps1"

Stop-Transcript

return $ret