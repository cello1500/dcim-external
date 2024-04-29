function RunScript {
    param (
        [string]$url
    )

    Try {
        $script = Invoke-WebRequest -Uri $url -UseBasicParsing | Select-Object -ExpandProperty Content
        $script = $script.Substring(1)
    
        "ComputeTask: $ApiKey"
        Invoke-Expression $script -ErrorAction Continue
    } Catch {
        return 5
    }

    if ($LASTEXITCODE -eq 0) {
        Write-Host "Script executed successfully."
    } else {
        Write-Host "Script execution failed."
    }
    return $LASTEXITCODE
}

if ($env:COMPUTERNAME -ne "NOAD01") {
    return
}

#Start-Transcript -Path $ENV:tmp\ComputerTask.log -Force
Start-Transcript -Path c:\windows\temp\ComputerTask.log -Force

$ret = RunScript -url "https://raw.githubusercontent.com/cello1500/dcim-external/main/Install-MSTeams-Computer.ps1"

"ComputerTask.ps1: Return code: $ret"

Stop-Transcript