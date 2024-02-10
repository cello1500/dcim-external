Start-Transcript -Path $ENV:tmp\ComputerUserCollector.log -Force

# set rest api base url and entry points
$ApiURL = "https://dcim-collector.wilmorite.com:8090/v1"
$PostResultURL = $ApiURL + "/computers"
$GetIpURL = $ApiURL + "/externalip"

# allow the use of self-signed SSL certificates on rest api requests
[System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $True }

if (-not ([System.Management.Automation.PSTypeName]"TrustEverything").Type) {
    Add-Type -TypeDefinition  @"
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
public static class TrustEverything
{
private static bool ValidationCallback(object sender, X509Certificate certificate, X509Chain chain,
    SslPolicyErrors sslPolicyErrors) { return true; }
public static void SetCallback() { System.Net.ServicePointManager.ServerCertificateValidationCallback = ValidationCallback; }
public static void UnsetCallback() { System.Net.ServicePointManager.ServerCertificateValidationCallback = null; }
}
"@
}

[TrustEverything]::SetCallback()

# Define the security key for rest api calls
$securityKey = $ApiKey

# Create the headers with the security key
$headers = @{
    "X-WILMORITE-API-KEY" = "$securityKey"
    "Content-Type" = "application/json"
}

$v = New-Object -TypeName PSObject

# Collect printers information
[array]$i = get-printer | Select-Object PrinterStatus, Type, DeviceType, Description, Comment, Name, ComputerName, DriverName, Location, PortName, Shared, ShareName, PrintProcessor |
                 ConvertTo-Csv -NoTypeInformation | ConvertFrom-Csv
$v = $v | Add-Member -Name "Printer" -Value $i -MemberType NoteProperty -PassThru

#########
# Ship collected data to the REST API

Stop-Transcript

$Output = Get-Content -Path $ENV:tmp\ComputerUserCollector.log
#Remove-Item -Path $ENV:tmp\ComputerUserCollector.log

$Output = foreach ($line in $Output) {
    if (-not $line.contains("TerminatingError(New-Object):") -and -not $line.contains("Parameter name: sddlForm") -and -not $line.contains("CommandInvocation(Out-Null):")) {
        $line
    }
}

$i = foreach ($line in $Output) { $line + "`n" }
# Add the script errors
if ($Output.Length -gt 23) {
    $v = $v | Add-Member -Name "ErrorMsg" -Value [string]$i -MemberType NoteProperty -PassThru
}

# Define the REST API endpoint URL
$apiUrl = $ApiURL

# Convert $v to JSON
$jsonData = ConvertTo-Json $v -Depth 4 -Compress

# Send the REST API request
$response = Invoke-RestMethod -Uri $PostResultURL -Method POST -Headers $headers -Body $jsonData -TimeoutSec 5

# Display the response
$response
