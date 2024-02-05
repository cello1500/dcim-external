Start-Transcript -Path $ENV:tmp\ComputerCollector.log -Force

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

# Collect computer information
$i = Get-CimInstance -Class Win32_ComputerSystem |
    Select-Object Name, CurrentTimeZone, DaylightInEffect, EnableDaylightSavingsTime, DNSHostName, PartOfDomain, Domain,
        DomainRole, HypervisorPresent, Manufacturer, Model, NumberOfLogicalProcessors, NumberOfProcessors,
        PCSystemTypeEx, PowerOnPasswordStatus, PrimaryOwnerName, SystemFamily, SystemSKUNumber, SystemType, TotalPhysicalMemory,
        UserName, WakeUpType, NetworkServerModeEnabled
$v = $v | Add-Member -Name "Win32_ComputerSystem" -Value $i[0] -MemberType NoteProperty -PassThru

# Collect BIOS information
$i = Get-CimInstance -Class Win32_BIOS |
    Select-Object Status, Name, Caption, SMBIOSPresent, Description, Manufacturer, SerialNumber, SoftwareElementID, SoftwareElementState, Version, PrimaryBIOS,
        BIOSVersion, EmbeddedControllerMajorVersion, EmbeddedControllerMinorVersion, InstallableLanguages, ReleaseDate, SMBIOSBIOSVersion,
        SMBIOSMajorVersion, SMBIOSMinorVersion, SystemBiosMajorVersion, SystemBiosMinorVersion
$v = $v | Add-Member -Name "Win32_BIOS" $i[0] -MemberType NoteProperty -PassThru

#
$i = Get-CimInstance -Class Win32_ComputerSystemProduct |
    Select-Object Caption, Description, IdentifyingNumber, Name, SKUNumber, Vendor, Version
$v = $v | Add-Member -Name "Win32_ComputerSystemProduct" -Value $i[0] -MemberType NoteProperty -PassThru

# Collect OS information
$i = Get-CimInstance -Class Win32_OperatingSystem |
    Select-Object BuildNumber, Caption, CSName, InstallDate, LastBootUpTime, LocalDateTime, OSType, Version, OSArchitecture, ProductType,
        RegisteredUser, WindowsDirectory, OperatingSystemSKU, OSProductSuite, OSLanguage, BootDevice, SystemDevice,
        SystemDirectory, SystemDrive, CountryCode, CurrentTimeZone,EncryptionLevel,
        FreePhysicalMemory, FreeSpaceInPagingFiles, FreeVirtualMemory, MaxNumberOfProcesses, MaxProcessMemorySize,NumberOfLicensedUsers,
        NumberOfProcesses, NumberOfUsers, Primary, SizeStoredInPagingFiles, Status,
        TotalSwapSpaceSize, TotalVirtualMemorySize, TotalVisibleMemorySize, SuiteMask, Description, SerialNumber
$ubr = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name UBR).UBR
$i = $i | Add-Member -Name "Version2" -Value ($i.Version + "." + $ubr) -MemberType NoteProperty -PassThru
$v = $v | Add-Member -Name "Win32_OperatingSystem" -Value $i[0] -MemberType NoteProperty -PassThru

# Collect CPU information
$i = Get-CimInstance -ClassName Win32_Processor | Where-Object {$_.ProcessorType -eq 3} |
    Select-Object Name, Caption, DeviceID, Description, Manufacturer, MaxClockSpeed, NumberOfCores, NumberOfLogicalProcessors, ProcessorId,
        ProcessorType, Revision, SocketDesignation, Status, ThreadCount, VirtualizationFirmwareEnabled,
        CurrentClockSpeed, L2CacheSize, L3CacheSize, L2CacheSpeed, L3CacheSpeed, LoadPercentage, PowerManagementSupported,
        Architecture, Family, ProcessorSerialNumber, AssetTag, PartNumber, StatusInfo,
        AddressWidth, DataWidth, Level, Version, NumberOfEnabledCore
$v = $v | Add-Member -Name "Win32_Processor" -Value $i[0] -MemberType NoteProperty -PassThru

# Collect physical disk information
[array]$i = Get-CimInstance -ClassName Win32_DiskDrive | Select-Object DeviceID, Capition, Partitions, Name, Size, Model, Manufacturer, InterfaceType, FirmwareRevision
$v = $v | Add-Member -Name "Win32_DiskDrive" -Value $i -MemberType NoteProperty -PassThru

# Collect logical disk information
[array]$i = Get-CimInstance -ClassName Win32_LogicalDisk | Select-Object DeviceID, VolumeName, VolumeSerialNumber, Size, FreeSpace, DriveType, FileSystem, Compressed, Description, MediaType, VolumeDirty
$v = $v | Add-Member -Name "Win32_LogicalDisk" -Value $i -MemberType NoteProperty -PassThru

# Retrieves the associations between logical disks and partitions on the computer
[array]$i = Get-CimInstance -ClassName Win32_LogicalDiskToPartition | Select-Object Antecedent, Dependent

$a = @()

foreach ($element in $i) {
    $t = New-Object -TypeName PSObject
    $t = $t | Add-Member -Name "Drive" -Value $element.Dependent.DeviceID -MemberType NoteProperty -PassThru
    $t = $t | Add-Member -Name "Disk" -Value $element.Antecedent.DeviceID -MemberType NoteProperty -PassThru
    $a += $t
}
$v = $v | Add-Member -Name "Win32_LogicalDiskToPartition" -Value $a -MemberType NoteProperty -PassThru

# Retrieves the associations between physical disks and partitions on the computer
[array]$i = Get-CimInstance -ClassName Win32_DiskDriveToDiskPartition | Select-Object Antecedent, Dependent

$a = @()

foreach ($element in $i) {
    $t = New-Object -TypeName PSObject
    $t = $t | Add-Member -Name "Disk" -Value $element.Dependent.DeviceID -MemberType NoteProperty -PassThru
    $t = $t | Add-Member -Name "Device" -Value $element.Antecedent.DeviceID -MemberType NoteProperty -PassThru
    $a += $t
}
$v = $v | Add-Member -Name "Win32_DiskDriveToDiskPartition" -Value $a -MemberType NoteProperty -PassThru

# Retrieve information about volumes on the computer using the Win32_Volume class
[array]$i = Get-CimInstance -ClassName Win32_Volume |
    Select-Object DeviceID, DriveLetter, FileSystem, FreeSpace, Label, Name, Size, SystemVolume, VolumeDirty, VolumeName,
        Description, Capacity, VolumeSerialNumber, DriveType, BootVolume
$v = $v | Add-Member -Name "Win32_Volume" -Value $i -MemberType NoteProperty -PassThru

# Collect network adapter information
[array]$j = Get-CimInstance -ClassName Win32_NetworkAdapter | Where-Object {$_.PhysicalAdapter -eq $true -or $_.NetEnabled -eq $true} |
    Select-Object caption, description, Availability, DeviceID, InterfaceIndex, MACAddress, Manufacturer, Name, NetConnectionID,
        NetConnectionStatus, NetEnabled, PhysicalAdapter, ProductName, ServiceName, Speed, SystemName, AdapterType, AdapterTypeId
$v = $v | Add-Member -Name "Win32_NetworkAdapter" -Value $j -MemberType NoteProperty -PassThru

# Collect network adapter configuration information
[array]$i = Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration |
    Select-Object caption, description, dhcpenabled, dhcpserver, DHCPLeaseObtained, DHCPLeaseExpires, ipaddress, ipsubnet,
        defaultipgateway, dnsdomain, DNSDomainSuffixSearchOrder, macaddress, DNSServerSearchOrder, interfaceindex, IPFilterSecurityEnabled
$i = $i | Where-Object  {$j.interfaceindex -contains $_.interfaceindex}
$v = $v | Add-Member -Name "Win32_NetworkAdapterConfiguration" -Value $i -MemberType NoteProperty -PassThru

# Collect network login profile information
[array]$i = Get-CimInstance -ClassName Win32_NetworkLoginProfile -ErrorAction SilentlyContinue |
    Select-Object AccountExpires, Caption, Description, FullName, HomeDirectory, HomeDirectoryDrive, InstallDate, LastLogoff,LastLogon,
    LogonServer, MaximumStorage, Name, NumberOfLogons, Comment, PasswordAge, PasswordExpires,Privileges, Profile, UserID, UserType
$i = $i | Where-Object  {$_.Name.StartsWith("NT AUTHORITY") -eq $false -and $_.Name.StartsWith("NT SERVICE") -eq $false}
$v = $v | Add-Member -Name "Win32_NetworkLoginProfile" -Value $i -MemberType NoteProperty -PassThru

# Get computer monitors' information
# [array]$i = Get-CimInstance WmiMonitorID -Namespace root\wmi -ErrorAction SilentlyContinue |
#     Select-Object InstanceName, @{Name="ManufacturerName";Expression={[System.Text.Encoding]::ASCII.GetString($_.ManufacturerName).Trim(0x00)}},
#         @{Name="UserFriendlyName";Expression={[System.Text.Encoding]::ASCII.GetString($_.UserFriendlyName).Trim(0x00)}},
#         @{Name="SerialNumberID";Expression={[System.Text.Encoding]::ASCII.GetString($_.SerialNumberID).Trim(0x00)}}, YearOfManufacture, WeekOfManufacture
# $v = $v | Add-Member -Name "WmiMonitorID" -Value $i -MemberType NoteProperty -PassThru

$adapterTypes = @{ #https://www.magnumdb.com/search?q=parent:D3DKMDT_VIDEO_OUTPUT_TECHNOLOGY
    '-2'         = 'Unknown'
    '-1'         = 'Unknown'
    '0'          = 'VGA'
    '1'          = 'S-Video'
    '2'          = 'Composite'
    '3'          = 'Component'
    '4'          = 'DVI'
    '5'          = 'HDMI'
    '6'          = 'LVDS'
    '8'          = 'D-Jpn'
    '9'          = 'SDI'
    '10'         = 'DisplayPort (external)'
    '11'         = 'DisplayPort (internal)'
    '12'         = 'Unified Display Interface'
    '13'         = 'Unified Display Interface (embedded)'
    '14'         = 'SDTV dongle'
    '15'         = 'Miracast'
    '16'         = 'Internal'
    '2147483648' = 'Internal'
}

[array]$i = @(Get-ciminstance wmimonitorID -namespace root\wmi -ErrorAction SilentlyContinue) |
ForEach-Object {
    $Instance = $_.InstanceName
#   $Sizes = Get-CimInstance -Namespace root\wmi -Class WmiMonitorBasicDisplayParams -ErrorAction SilentlyContinue | where-object { $_.instanceName -like $Instance }
    $connections = (Get-CimInstance WmiMonitorConnectionParams -Namespace root/wmi | where-object { $_.instanceName -like $Instance }).VideoOutputTechnology
    if($_.ManufacturerName -ne $null) { $ManufacturerVar = [System.Text.Encoding]::ASCII.GetString($_.ManufacturerName).Trim(0x00)} else { $ManufacturerVar = ""}
    if($_.UserFriendlyName -ne $null) { $NameVar = [System.Text.Encoding]::ASCII.GetString($_.UserFriendlyName).Trim(0x00) } else { $NameVar = ""}
    if($_.SerialNumberID -ne $null) { $SerialVar = [System.Text.Encoding]::ASCII.GetString($_.SerialNumberID).Trim(0x00) } else { $SerialVar = ""}
    [pscustomobject]@{
        Manufacturer   = $ManufacturerVar
        Name           = $NameVar
        Serial         = $SerialVar
#       Size           = ([System.Math]::Round(([System.Math]::Sqrt([System.Math]::Pow($Sizes.MaxHorizontalImageSize, 2) + [System.Math]::Pow($_.MaxVerticalImageSize, 2)) / 2.54), 0))
        ConnectionType = $adapterTypes."$connections"
        YearOfManufacture = $_.YearOfManufacture
        WeekOfManufacture = $_.WeekOfManufacture
    }
}
$v = $v | Add-Member -Name "WmiMonitorID" -Value $i -MemberType NoteProperty -PassThru

# Collect user profile information. Focus on redirected folders
# It skips profiles where users where deleted from main and the NT AUTHORITY and NT SERVICE profiles
$i = Get-CIMInstance Win32_UserProfile |
        Select-Object -Property @{Name="Username";Expression={([System.Security.Principal.SecurityIdentifier]$_.sid).Translate( [System.Security.Principal.NTAccount])}},
        LocalPath, SID, LastUseTime, HealthStatus, Loaded, @{Name="Desktop";Expression={$_.desktop.redirected}},
        @{Name="Documents";Expression={$_.documents.redirected}}, @{Name="Pictures";Expression={$_.Pictures.redirected}},
        @{Name="Downloads";Expression={$_.Downloads.redirected}}, @{Name="Favorites";Expression={$_.Favorites.redirected}},
        @{Name="Contacts";Expression={$_.Contacts.redirected}}, @{Name="AppDataRoaming";Expression={$_.AppDataRoaming.redirected}},
        @{Name="Links";Expression={$_.Links.redirected}}, @{Name="Music";Expression={$_.Music.redirected}},
        @{Name="Videos";Expression={$_.Videos.redirected}}, @{Name="StartMenu";Expression={$_.StartMenu.redirected}},
        @{Name="Searches";Expression={$_.Searches.redirected}}, @{Name="SavedGames";Expression={$_.SavedGames.redirected}}
$i | ForEach-Object {$_.Username = $_.Username.Value}
$i = $i | Where-Object  {$_.UserName -ne $null -and $_.Username.StartsWith("NT AUTHORITY") -eq $false -and $_.Username.StartsWith("NT SERVICE") -eq $false}
$v = $v | Add-Member -Name "Win32_UserProfile" -Value $i -MemberType NoteProperty -PassThru

# Collect OneDrive information
[array]$i = Get-ChildItem -Path "registry::HKEY_USERS\" | ForEach-Object {Get-ItemProperty -Path Registry::$_\Software\SyncEngines\Providers\OneDrive\* -ErrorAction SilentlyContinue} |
    ForEach-Object {
        $aa=$_.PSPath -match "^.*?\\.*?\\(.*?)\\"
        if ($aa -and $Matches[1] -ne ".DEFAULT") {
            $_ | Add-Member -Name "Username" -Value ([System.Security.Principal.SecurityIdentifier]$Matches[1]).Translate( [System.Security.Principal.NTAccount]) -MemberType NoteProperty -PassThru}} |
                Select-Object * -ExcludeProperty PSParentPath, PSChildName, PSProvider
$i | ForEach-Object {$_.Username = $_.Username.Value}
$v = $v | Add-Member -Name "OneDrive" -Value $i -MemberType NoteProperty -PassThru

[array]$i = Get-ChildItem -Path "registry::HKEY_USERS\" | ForEach-Object {Get-ItemProperty -Path Registry::$_\Software\Microsoft\OneDrive -ErrorAction SilentlyContinue} |
    ForEach-Object {$aa=$_.PSPath -match "^.*?\\.*?\\(.*?)\\"
        if ($aa -and $Matches[1] -ne ".DEFAULT") {
            $_ | Add-Member -Name "Username" -Value ([System.Security.Principal.SecurityIdentifier]$Matches[1]).Translate( [System.Security.Principal.NTAccount]) -MemberType NoteProperty -PassThru}} |
                Select-Object * -ExcludeProperty PSParentPath, PSChildName, PSProvider
$i | ForEach-Object {$_.Username = $_.Username.Value}
$i = $i | Where-Object  {$_.Username.StartsWith("NT AUTHORITY") -eq $false}
$v = $v | Add-Member -Name "OneDriveConfig" -Value $i -MemberType NoteProperty -PassThru

# Collect Services information
$i = Get-CimInstance -ClassName Win32_Service |
    Select-Object Name, DisplayName, Description, PathName, StartMode, State, Status, AcceptPause, AcceptStop, Caption, CheckPoint, CreationClassName, DelayedAutoStart,
    DesktopInteract, ErrorControl, ExitCode, ProcessId, ServiceSpecificExitCode, ServiceType, Started, StartName, SystemCreationClassName, TagId, WaitHint
$v = $v | Add-Member -Name "Win32_Service" -Value $i -MemberType NoteProperty -PassThru

# Collect installed software information from registry
$hklm32 = Get-ItemProperty -Path HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* |
    ForEach-Object {
        Add-Member -InputObject $_ -Name "Architecture" -Value "HKLM32" -MemberType NoteProperty -PassThru
    } | Select-Object DisplayName, Publisher, InstallDate, InstallSource, UninstallString, DisplayVersion, URLInfoAbout, Architecture
$hklm64 = Get-ItemProperty -Path HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* |
    ForEach-Object {
        Add-Member -InputObject $_ -Name "Architecture" -Value "HKLM64" -MemberType NoteProperty -PassThru
    } | Select-Object DisplayName, Publisher, InstallDate, InstallSource, UninstallString, DisplayVersion, URLInfoAbout, Architecture
#$hkcu = Get-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, Publisher, InstallDate, InstallSource, UninstallString, DisplayVersion, URLInfoAbout
$hkcu = Get-ChildItem -Path registry::HKEY_USERS\ |
    ForEach-Object {Get-ItemProperty -Path Registry::$_\Software\Microsoft\Windows\CurrentVersion\Uninstall\* -ErrorAction SilentlyContinue } |
        ForEach-Object {
            $aa=$_.PSPath -match "^.*?\\.*?\\(.*?)\\"
            if ($aa) {
                $_ | Add-Member -Name "Username" -Value ([string]([System.Security.Principal.SecurityIdentifier]$Matches[1]).Translate( [System.Security.Principal.NTAccount])) -MemberType NoteProperty -PassThru
            }
        } | Select-Object DisplayName, Publisher, InstallDate, InstallSource, UninstallString, DisplayVersion, URLInfoAbout, Username
$hkcu = $hkcu | ForEach-Object { $_ | Add-Member -Name "Architecture" -Value "HKCU" -MemberType NoteProperty -PassThru}
$AppsRegistry = $hklm32 + $hklm64 + $hkcu
$v = $v | Add-Member -Name "AppsRegistry" -Value $AppsRegistry -MemberType NoteProperty -PassThru

# Collect installed software information from Event Log
[array]$i = Get-WinEvent -FilterHashtable @{LogName = "Application"; ProviderName = "MsiInstaller"; Id = 1033; }  -ErrorAction SilentlyContinue |
                Select-Object TimeCreated, Message, @{Name="UserID";Expression={[string]$_.UserID}},
    @{Name="Username";Expression={[string]([System.Security.Principal.SecurityIdentifier]$_.userid).Translate( [System.Security.Principal.NTAccount])}}, RecordId
$v = $v | Add-Member -Name "WinEventApps" -Value $i -MemberType NoteProperty -PassThru

# Collect installed software information from Microsoft Store
[array]$i = Get-AppxPackage -AllUsers -ErrorAction SilentlyContinue  |
    Select-Object Architecture, InstallLocation, IsBundle, IsDevelopmentMode, IsFramework, IsPartiallyStaged, IsResourcePackage, Name, NonRemovable,
        PackageFamilyName, PackageFullName, PackageUserInformation, Publisher, PublisherId, SignatureKind, Status, Version
$v = $v | Add-Member -Name "Get-AppxPackage" -Value $i -MemberType NoteProperty -PassThru

# Get-Package | Where-Object Name -NotMatch "Security Intelligence Update"
[array]$i = Get-Package -AllVersions -Force | Where-Object Name -NotMatch "Security Intelligence Update" |
    ForEach-Object {
        [pscustomobject] @{
            Name = $_.Name
            ProviderName = $_.ProviderName
            Status = $_.Status
            Version = $_.Version
            Publisher = $_.Meta.Attributes['Publisher']
            URLInfoAbaout = $_.Meta.Attributes['URLInfoAbout']
            UninstallString = $_.Meta.Attributes['UninstallString']
            InstallLocation = $_.Meta.Attributes['InstallLocation']
        }
    }
$v = $v | Add-Member -Name "Get-Package" -Value $i -MemberType NoteProperty -PassThru

# Collect printers information
[array]$i = Get-CimInstance -ClassName Win32_Printer |
    Select-Object Status, Name, Caption, DeviceID, Default, Direct, DriverName, ExtendedPrinterStatus, Hidden, Local, Network, PortName, PrinterState
$v = $v | Add-Member -Name "Win32_Printer" -Value $i -MemberType NoteProperty -PassThru

# Get misceleneous information
$externalIP = (Invoke-RestMethod -Uri $GetIpURL -Method GET -Headers $headers -TimeoutSec 3)

# Get Intune device ID
$provider = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\DeviceHealthMonitoring" -name ConfigDeviceHealthMonitoringScope_WinningProvider -ErrorAction SilentlyContinue).ConfigDeviceHealthMonitoringScope_WinningProvider
if ($null -eq $provider) {
    $provider = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows Defender" -name MdmSubscriberIds -ErrorAction SilentlyContinue).MdmSubscriberIds
}
$intuneID = (Get-ItemProperty ("HKLM:\SOFTWARE\Microsoft\Enrollments\" + $provider + "\DMClient\MS DM Server") -name EntDMID -ErrorAction SilentlyContinue).EntDMID

# Collect Azure AD Join information
$status = (cmd /c dsregcmd /status)
$AzureAdJoined = ($status -match "AzureAdJoined").Split(":")[-1].Trim(); if ($AzureAdJoined -eq "YES") {$AzureAdJoined = $true} else {$AzureAdJoined = $false}
$DomainJoined = ($status -match "DomainJoined").Split(":")[-1].Trim(); if ($DomainJoined -eq "YES") {$DomainJoined = $true} else {$DomainJoined = $false}
# Collect routing information
$route = Get-NetRoute -AddressFamily IPv4 -DestinationPrefix "0.0.0.0/0"

$i = New-Object -TypeName PSObject
$i = $i | Add-Member -Name "ExternalIP" -Value $externalIP -MemberType NoteProperty -PassThru
$i = $i | Add-Member -Name "TpmVersion" -Value  (Get-CimInstance -Namespace 'root\cimv2\security\microsofttpm' -Class win32_tpm -ErrorAction SilentlyContinue).PhysicalPresenceVersionInfo -MemberType NoteProperty -PassThru
$i = $i | Add-Member -Name "SecureBootUefi" -Value (Confirm-SecureBootUEFI -ErrorAction Continue) -MemberType NoteProperty -PassThru
$i = $i | Add-Member -Name "IntuneDeviceId" -Value $intuneID -MemberType NoteProperty -PassThru
$i = $i | Add-Member -Name "AzureAdJoined" -Value $AzureAdJoined -MemberType NoteProperty -PassThru
$i = $i | Add-Member -Name "DomainJoined" -Value $DomainJoined -MemberType NoteProperty -PassThru
$i = $i | Add-Member -Name "AzureDeviceId" -Value ($status -match "DeviceId").Split(":")[-1].Trim() -MemberType NoteProperty -PassThru
$i = $i | Add-Member -Name "AzureTenantId" -Value ($status -match "TenantId").Split(":")[-1].Trim() -MemberType NoteProperty -PassThru
$i = $i | Add-Member -Name "AzureTenantName" -Value ($status -match "TenantName").Split(":")[-1].Trim() -MemberType NoteProperty -PassThru
$i = $i | Add-Member -Name "DefaulGateway" -Value @($route.NextHop) -MemberType NoteProperty -PassThru
$i = $i | Add-Member -Name "DefaulGatewayInterfaceIndex" -Value @($route.InterfaceIndex) -MemberType NoteProperty -PassThru
$i = $i | Add-Member -Name "DefaulGatewayInterfaceAlias" -Value @($route.InterfaceAlias) -MemberType NoteProperty -PassThru
$v = $v | Add-Member -Name "Custom" -Value $i[0] -MemberType NoteProperty -PassThru

# Collect logon information from Event Log
$UserProperty = @{n="User";e={[string](New-Object System.Security.Principal.SecurityIdentifier ($_.Properties[1].Value)).Translate([System.Security.Principal.NTAccount])}}
$TypeProperty = @{n="Action";e={if($_.ID -eq 7001) {"Logon"} else {"Logoff"}}}
$TimeProperty = @{n="Time";e={$_.TimeCreated}}
[array]$i = Get-WinEvent -FilterHashtable @{LogName = "System"; Id = 7001, 7002; }  -ErrorAction SilentlyContinue | Select-Object $UserProperty, $TypeProperty, $TimeProperty, RecordId
$i | ForEach-Object { $_.Time = $_.Time.ToString("yyyy-MM-dd HH:mm:ss") }

$v = $v | Add-Member -Name "WinEventLogins" -Value $i -MemberType NoteProperty -PassThru

## Collect system boot and shutdown information from Event Log
$i = Get-WinEvent -FilterHashtable @{LogName = "System"; Id = 1074, 6005, 6006, 6008; } -ErrorAction SilentlyContinue |
    Select-Object ID, RecordID, ProviderName, LogName,
    @{Name="Username";Expression={[string]([System.Security.Principal.SecurityIdentifier]$_.userid).Translate( [System.Security.Principal.NTAccount])}},
    TimeCreated, ContainerLog, LevelDisplayName, Message
$v = $v | Add-Member -Name "WinEventBootShutdown" -Value $i -MemberType NoteProperty -PassThru
# $i = Get-WinEvent -ProviderName Microsoft-Windows-Kernel-General | Where-Object { $_.id -eq 12 -OR $_.id -eq 13} | Select-Object TimeCreated, Id, Message

# Collect current Windows Sesssion information
$QUserToRichObject = ((Invoke-Expression quser) -replace '\s{2,}', ',' | ConvertFrom-Csv)

If($QUserToRichObject){

    $UserSessions = @()

    ForEach($Record in $QUserToRichObject){

        # If the active session, remove the '>' character from Username value
        If($Record.USERNAME -Like ">*"){$Record.USERNAME = ($Record.USERNAME -Replace ">", "")}

        if ([string]$Record.'LOGON TIME' -ne "") {
            $UserSessions += @{
                Username        = [string]$Record.USERNAME
                SessionName     = [string]$Record.SESSIONNAME
                ID              = [string]$Record.ID
                State           = [string]$Record.STATE
                Idle            = [string]$Record.'IDLE TIME'
                LogonTime       = [string]$Record.'LOGON TIME'
            }
        } else {
            $UserSessions += @{
                Username        = [string]$Record.USERNAME
                SessionName     = ""
                ID              = [string]$Record.SESSIONNAME
                State           = [string]$Record.ID
                Idle            = [string]$Record.STATE
                LogonTime       = [string]$Record.'IDLE TIME'
            }
        }
    }
}
$v = $v | Add-Member -Name "WindowsSessions" -Value $UserSessions -MemberType NoteProperty -PassThru

# Collect Teamviewer information from registry
$hklm = Get-ItemProperty -Path HKLM:\Software\Wow6432Node\TeamViewer -ErrorAction SilentlyContinue |
    Select-Object IsHostModule, InstallationDirectory, Always_Online, Version, ClientID, LicenseType, LastUpdateCheck,UpdateVersion, MonitoringInstallationType,
        PatchManagementInstallationType, MonitoringV2Active, MonitoringServiceRegistered, PatchManagementActive, UpdateChannel
if ($null -eq $hklm) {
    $hklm = Get-ItemProperty -Path HKLM:\Software\TeamViewer -ErrorAction SilentlyContinue |
        Select-Object IsHostModule, InstallationDirectory, Always_Online, Version, ClientID, LicenseType, LastUpdateCheck,UpdateVersion, MonitoringInstallationType,
            PatchManagementInstallationType, MonitoringV2Active, MonitoringServiceRegistered, PatchManagementActive, UpdateChannel
}

$v = $v | Add-Member -Name "TeamviewerRegistry" -Value $hklm -MemberType NoteProperty -PassThru

Stop-Transcript

$Output = Get-Content -Path $ENV:tmp\ComputerCollector.log
Remove-Item -Path $ENV:tmp\ComputerCollector.log

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

## return register item property value for all users on the computer
# Get-ChildItem -Path HKU:\ | ForEach-Object {Get-ItemProperty -Path Registry::$_\Software\Microsoft\Windows\CurrentVersion\Run -Name *}

## Find users who have authenticated with different login types

# get-eventlog -ComputerName "localhost" -logname ’security’ -instanceid 4624 -after (get-date).adddays(-10) | % {
#     [array] $login += [pscustomobject] @{

#         account = $_.replacementstrings[5]
#         time = $_.timewritten
#         type = $_.replacementstrings[8]
#         ip = $_.replacementstrings[18]
# }}

# $login | ft -auto