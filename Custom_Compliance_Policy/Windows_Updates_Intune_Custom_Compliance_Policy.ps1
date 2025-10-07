<#

    =======================================================================================
    Title      : Intune Custom Compliance Script - Windows Update Readiness Health Check
    Author     : Vishal Navgire [VishalNavgire54@Gmail.Com]
    Date       : 2025-09-30
    Version    : 1.0
    File Name  : Windows_Updates_Intune_Custom_Compliance_Policy
    =======================================================================================
    PURPOSE:
    --------
    This script is intended to be deployed as part of an Intune Custom Compliance Policy. 
    Its role is to proactively detect whether a Windows device meets specific health 
    criteria that are critical for reliable update installation, MDM management, and 
    security compliance. 

    If any of the defined conditions are not met, the device will be marked as 
    **NonCompliant**, allowing organizations to enforce Conditional Access policies or 
    trigger user and IT notifications.

    The goal is to improve update reliability, reduce IT support issues, and align 
    with organizational baselines for Windows servicing and Intune management.

    =======================================================================================
    CHECKS PERFORMED:
    -----------------
    1. ✅ Pending Reboot:
        - Detects whether a restart is required using registry paths commonly associated 
            with Windows updates and servicing operations.
        - If a reboot is pending, the device is marked non-compliant.

    2. ✅ Low Disk Space (C:\ drive):
        - Checks available space on the system drive (C:).
        - If free space is ≤ 5 GB, the device is marked non-compliant.
        - This ensures there is sufficient space to download and install updates.

    3. ✅ Critical Windows Services:
        Verifies that the following services are running and responsive:
        - `dmwappushservice` → WAP Push Service (required for MDM sync triggers)
        - `intunemanagementextension` → Intune Management Extension (executes Win32 apps, scripts)
        - `wuauserv` → Windows Update Service (fetches and installs updates)
        - `wlidsvc` → Microsoft Account Sign-In Assistant (generates device identifiers for updates)
    
        - If any of these are **Stopped**, **Disabled**, or **Missing**, the device is 
            marked non-compliant.

    4. ✅ Registry Settings for Update Deferral:
        - Registry Path: `HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate`
        - Verifies that the following values are set:
            - `DeferQualityUpdatesPeriodInDays` = 0 - 7
            - `PauseQualityUpdates` = 0

        - If any of these values are not present, it may prevent timely quality 
            updates, and the device will be marked non-compliant.

    =======================================================================================
    OUTPUT:
    -------
    The script outputs a JSON object required by Intune Custom Compliance:

    Final Result JSON: {
                        "PendingReboot":true,
                        "SystemDriveFreeGB":true,
                        "WapPushServiceHealthy":true,
                        "IMEHealthy":true,"WindowsUpdateServiceHealthy":true,
                        "MSAServiceHealthy":true,
                        "DeferQualityUpdatesPeriodInDays":7,
                        "PauseQualityUpdates":0
                        }

    =======================================================================================
    DEPLOYMENT INSTRUCTIONS:
    ------------------------
        1. Save this file as a `.ps1` file (e.g., Intune_CustomCompliance_UpdateReadiness.ps1).

        2. In Microsoft Intune:
        - Go to **Devices > Compliance Policies > Scripts**.
        - Upload this PowerShell script.
        - Create a **Custom Compliance Policy** and associate this script.
        - Assign the policy to your target device groups.

        3. Configure **Actions for Noncompliance**:
        - Send email to end users
        - Notify IT or trigger Logic App alert
        - Block access via Conditional Access if desired

    =======================================================================================

    Docs: https://learn.microsoft.com/intune/intune-service/protect/compliance-custom-script

    =======================================================================================
    CHANGE HISTORY:
    ---------------
    v1.0 - 2025-09-30 - Initial version with all required checks as per design.
    =======================================================================================
#>

# Define N and N-1 values. Update these variables manually each month after Patch Tuesday i.e. on 2nd Wed of every month.
$CurrentBuildNumber_N    = "26200"
$CurrentFeatureVersion_N = "25H2"
$Current_UBR_N           = "6584"
$Current_UBR_N_1         = $Null

$PreviousBuildNumber_N    = "26100"
$PreviousFeatureVersion_N = "24H2"
$Previous_UBR_N           = "6584"
$Previous_UBR_N_1         = "4946"

#https://learn.microsoft.com/en-us/windows/release-health/windows11-release-information
$ErrorActionPreference = 'Stop'

# Get current Windows Feature Update and Quality version
$Installed_BuildNumber = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion")

# --- Lightweight logging ---
$LogDir  = 'C:\ProgramData\Microsoft\IntuneManagementExtension\Logs\ComplianceLogs'
$LogFile = 'CustomCompliance_DeviceHealth_' + $($ENV:ComputerName) +'.log'
$Global:LogFile = Join-Path -Path $LogDir -ChildPath $LogFile

Function Write-Log()
    {

        <#
            .Author         - Vishal Navgire
            .Created on     - 05-Mar-2025
            .Co-Author(s)   - NA
            .Reviwer(s)     - NA


            .DESCRIPTION


                Script is designed to write custom log messages to a particular location.


            Pre-reqs:
                N/A


            Version Control:
                05-Mar-2025 : v1.0
        #>


            [CmdletBinding()]
            param
            (
                [Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True)]
                [ValidateNotNullOrEmpty()]
                [Alias("LogContent")]
                [string]$Message,

                [Parameter(Mandatory=$False)]
                # [ValidateScript({$_ -like 'C:\ProgramData\Microsoft\IntuneManagementExtension\Logs\*'})]
                # [Alias("LogFileLocation")]
                [string]$LogFile = $Global:LogFile,

                [Parameter(Mandatory=$False)]
                [ValidateSet("Error","Warning","Info")]
                [string]$Level = "Info"
            )
            Begin
                {
                }
            Process
            {
                If (Test-Path $LogFile)
                    {
                        $LogSize = (Get-Item -Path $LogFile).Length/1MB
                        $MaxLogFileSize = 10

                        # Check for file size of the log. If greater than 10MB, it will delete the old and create a new one.
                            If (($LogSize -gt $MaxLogFileSize))
                                {
                                    Remove-Item $LogFile -Recurse -Force | Out-Null
                                    New-Item $LogFile -Force -ItemType File | Out-Null
                                }
                    }

                # If attempting to write to a log file in a folder path that doesn't exist create the file including the path.
            Else
                    {
                        New-Item $LogFile -Force -ItemType File | Out-Null
                    }

                # Write message to error, warning, or verbose pipeline and specify $LevelText
                Switch ($Level)
                    {
                        'Error'
                            {
                                $LevelText = 'ERROR:'
                            }
                        'Warning'
                            {
                                $LevelText = 'WARNING:'
                            }
                        'Info'
                            {
                                $LevelText = 'INFO:'
                            }
                    }


                # Write log entry to $LogFile
                "$(Get-Date -Format "dd:MMMM:yyyy hh:mm:ss tt ")[$((Get-TimeZone).StandardName)]____$LevelText $Message" | Out-File -PSPath $LogFile -Append -Force
            }
            End
            {


            }
    }

Function Get-WindowsReleaseDate 
    {
        <#
            .SYNOPSIS
            Converts Windows ReleaseId and DisplayVersion into a human-readable release date.

            .DESCRIPTION
            Reads the registry to extract ReleaseId and DisplayVersion, then formats them into a date string
            using the custom logic: ReleaseId → Day and Month, DisplayVersion → Year.

            .OUTPUTS
            PSCustomObject with Day, Month, Year, and FormattedDate.

            .EXAMPLE
            $releaseInfo = Get-WindowsReleaseDate
            Write-Output $releaseInfo.FormattedDate
        #>

        [CmdletBinding()]
        param ()

        Try 
            {
                $WinVer = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion"

                If (-not $WinVer.ReleaseId -or -not $WinVer.DisplayVersion) 
                    {
                        throw "ReleaseId or DisplayVersion not found in registry."
                    }

                # Parse day, month, and year
                $Day = [int]$WinVer.ReleaseId.Substring(0, 2)
                $Month = [int]$WinVer.ReleaseId.Substring(2, 2)
                $Year = 2000 + [int]$WinVer.DisplayVersion.Substring(0, 2)

                # Convert month number to month name
                $MonthName = (Get-Culture).DateTimeFormat.GetMonthName($month)

                # Format the date
                $FormattedDate = "$Day-$MonthName-$Year"

                Return [PSCustomObject]@{
                                            Day           = $Day
                                            Month         = $MonthName
                                            Year          = $Year
                                            FormattedDate = $FormattedDate
                                        }
            }
        Catch 
            {
                Write-Warning "Failed to retrieve or parse Windows release information: $_"
                Return $null
            }
    }
$WindowsReleaseDate = Get-WindowsReleaseDate
#Access N and N-1 for Feature and Quality updates of the Latest BUILD NUmber. If Feature and Qaulity update is older than N-1, return False.    
Function Test-LatestFeatureAndQualityStatus 
    {
        Param 
            (
                $Installed_BuildNumber
            )

        If (($CurrentBuildNumber_N -eq $Installed_BuildNumber.CurrentBuildNumber) -And ($CurrentFeatureVersion_N -eq $Installed_BuildNumber.DisplayVersion))
            { 
                Write-Log "Installed Feature update is: $($Installed_BuildNumber.CurrentBuildNumber) and its display version is: $($Installed_BuildNumber.DisplayVersion). "
                
                If (($Current_UBR_N -eq $Installed_BuildNumber.UBR) -or ($Current_UBR_N_1 -eq $Installed_BuildNumber.UBR))
                    {
                        Write-Log  "Latest Installed Feature update is: $($Installed_BuildNumber.CurrentBuildNumber) and its Update Build Revision is: $($Installed_BuildNumber.UBR). "
                        Write-Log  "Release Date is: $($WindowsReleaseDate.FormattedDate)"
                        Return $True
                    }
                Else 
                    {
                        Write-Log "Latest Installed Feature update is: $($Installed_BuildNumber.CurrentBuildNumber) and its Update Build Revision is: $($Installed_BuildNumber.UBR). " -Level Warning
                        Return $False
                    }
            }
        Else 
            {
                Write-Log "Latest Installed Feature update is: $($Installed_BuildNumber.CurrentBuildNumber) and its display version is: $($Installed_BuildNumber.DisplayVersion). " -Level Warning
                Return $False
            }
    }

$Latest_Feature_And_Quality_Status = Test-LatestFeatureAndQualityStatus -Installed_BuildNumber $Installed_BuildNumber

#Access N and N-1 for Feature and Quality updates of the Previous BUILD NUmber. If Feature and Qaulity update is older than N-1, return False.
Function Test-PreviousFeatureAndQualityStatus 
    {
        Param 
            (
                $Installed_BuildNumber
            )

            If (($PreviousBuildNumber_N -eq $Installed_BuildNumber.CurrentBuildNumber) -And ($PreviousFeatureVersion_N -eq $Installed_BuildNumber.DisplayVersion))
            {
              Write-Log "Previous Installed Feature update is: $($Installed_BuildNumber.CurrentBuildNumber) and its display version is: $($Installed_BuildNumber.DisplayVersion). "
                If (($Previous_UBR_N -eq $Installed_BuildNumber.UBR) -or ($Previous_UBR_N_1 -eq $Installed_BuildNumber.UBR))
                    {
                        Write-Log "Previous Installed Feature update is: $($Installed_BuildNumber.CurrentBuildNumber) and its Update Build Revision is: $($Installed_BuildNumber.UBR). "
                        Write-Log "Previous Release Date is: $($WindowsReleaseDate.FormattedDate)"
                        Return $True
                    }
                Else 
                    {
                        Write-Log  "Previous Installed Feature update is: $($Installed_BuildNumber.CurrentBuildNumber) and its Update Build Revision is: $($Installed_BuildNumber.UBR). " -Level Warning
                        Return $False
                    }
            }
        Else 
            {
                Write-Log "Previous Installed Feature update is: $($Installed_BuildNumber.CurrentBuildNumber) and its display version is: $($Installed_BuildNumber.DisplayVersion). " -Level Warning
                Return $False
            }
    }
#Below function would only run if $Latest_Feature_And_Quality_Status IS NOT True.
If ($Latest_Feature_And_Quality_Status -eq $False) 
    {
        $Previous_Feature_And_Quality_Status = Test-PreviousFeatureAndQualityStatus -Installed_BuildNumber $Installed_BuildNumber
    }

#Feature and Qualit Update Compliance Result.
$FeatureAndQualityUpdateCompliant = $False
If ( $Latest_Feature_And_Quality_Status -Or $Previous_Feature_And_Quality_Status)
    {
        $FeatureAndQualityUpdateCompliant = $True
    }


Function Test-PendingReboot 
    {
        $paths = @(
                    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending',
                    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired'
                )
        Foreach ($EachPath in $paths) 
            { 
                If (Test-Path $EachPath) 
                    { return $True } 
            }
        $Pfr = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -Name 'PendingFileRenameOperations' -ErrorAction SilentlyContinue
        If ($Pfr) 
            { Return $True }
        Return $False
    }
$PendingReboot = Test-PendingReboot
Write-Log "PendingReboot: $PendingReboot"

Try 
    {
        $LastBoot       = (Get-CimInstance Win32_OperatingSystem -ErrorAction STOP).LastBootUpTime
        $LastRebootDays = (New-TimeSpan -Start $LastBoot -End (Get-Date)).Days
    } 
Catch 
    { 
        $LastRebootDays = -1 
        Write-Log "Failed to get LastBootUpTime: $($_.Exception.Message)" -Level "Error"
    }
Write-Log "LastRebootDays: $LastRebootDays"

# --- B. C: free space ---
    Try 
        {
            $DiskSpaceCheck = Get-PSDrive -Name C -ErrorAction Stop
            $SystemDriveFreeGB = [math]::Round(($DiskSpaceCheck.Free / 1GB), 0)
        } 
    Catch 
        {
            $SystemDriveFreeGB = -1
            Write-Log "Failed to read C: free space: $($_.Exception.Message)"
        }
Write-Log "SystemDriveFreeGB: $SystemDriveFreeGB"

# --- C. Service health ---
$WindowsServicePolicy = @(
                            @{ 
                                Names=@('dmwappushservice'); 
                                Label='WapPush'; 
                                RequireRunning=$True
                            },
                            @{ 
                                Names=@('IntuneManagementExtension');       
                                Label='IME';     
                                RequireRunning=$True
                            },
                            @{ 
                                Names=@('wuauserv');                        
                                Label='WUA';     
                                RequireRunning=$True
                            },
                            @{ 
                                Names=@('wlidsvc');                         
                                Label='MSA';     
                                RequireRunning=$True
                            }
                        )
Function Get-ServiceHealth
            {
                
                param (
                        [string[]]$Names,
                        [bool]$RequireRunning
                    )

                Foreach ($EachWindowsService in $Names) 
                {
                    $ServiceName = Get-CimInstance -ClassName Win32_Service -Filter "Name='$EachWindowsService'" -ErrorAction SilentlyContinue
                    If ($ServiceName)
                        {
                            $Running     = $ServiceName.State -eq 'Running'
                            $NotDisabled = $ServiceName.StartMode -ne 'Disabled'
                            $DisplayName = $ServiceName.DisplayName
                            $Healthy     = If ($RequireRunning) 
                                                {$Running -and $NotDisabled} 
                                            Else {$NotDisabled}
                            Return [pscustomobject]@{ 

                                                    Found       =$True; 
                                                    DisplayName = $DisplayName;
                                                    Running     =$Running; 
                                                    StartMode   =$ServiceName.StartMode; 
                                                    Healthy     =$Healthy 
                                                }
                        }
                }
                Return [pscustomobject]@{ 
                                        ServiceName ='NotFound'
                                        Found       =$False; 
                                        Running     =$False; 
                                        StartMode   ='NotFound'; 
                                        Healthy     =$False 
                                    }
            }
$Dmwappushservice = Get-ServiceHealth -Names $WindowsServicePolicy[0].Names -RequireRunning $WindowsServicePolicy[0].RequireRunning
If ($Dmwappushservice.Healthy -ne $True)
    {
        Write-Log -Message "Status of 'Device Management Wireless Application Protocol (WAP) Push message Routing Service' $($Dmwappushservice)" -Level Warning
    }
Else 
    {
        Write-Log -Message "Status of 'Device Management Wireless Application Protocol (WAP) Push message Routing Service' $($Dmwappushservice)"
    }

$IME = Get-ServiceHealth -Names $WindowsServicePolicy[1].Names -RequireRunning $WindowsServicePolicy[1].RequireRunning
If ($IME.Healthy -ne $True)
    {
        Write-Log -Message "Status of 'Intune Management Extension Service' $($IME)" -Level Warning
    }
Else 
    {
        Write-Log -Message "Status of 'Intune Management Extension Service' $($IME)"
    }

$WUA = Get-ServiceHealth -Names $WindowsServicePolicy[2].Names -RequireRunning $WindowsServicePolicy[2].RequireRunning
If ($WUA.Healthy -ne $True)
    {
        Write-Log -Message "Status of 'Windows Update Service' $($WUA)" -Level Warning
    }
Else 
    {
        Write-Log -Message "Status of 'Windows Update Service' $($WUA)"
    }

$MSA = Get-ServiceHealth -Names $WindowsServicePolicy[3].Names -RequireRunning $WindowsServicePolicy[3].RequireRunning
If ($MSA.Healthy -ne $True)
    {
        Write-Log -Message "Status of 'Microsoft Account Sign-in Assistant Service' $($MSA)" -Level Warning
    }
Else 
    {
        Write-Log -Message "Status of 'Microsoft Account Sign-in Assistant Service' $($MSA)"
    }


# --- D. Windows Update policy registry (return -1 if missing) ---
$WUKey = 'HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\Update'

Function Get-PolicyDword($Name) 
    {
        Try 
            {
                $value = Get-ItemProperty -Path $WUKey -Name $Name -ErrorAction Stop
                Return [int]$value.$Name
            } 
        Catch {Return -1}
    }

$DeferQualityUpdatesPeriodInDays = Get-PolicyDword 'DeferQualityUpdatesPeriodInDays'  # expect anything greater than 0 but less than 7
$PauseQualityUpdates             = Get-PolicyDword 'PauseQualityUpdates'              # expect 0

Write-Log "DeferQualityUpdatesPeriodInDays: $DeferQualityUpdatesPeriodInDays"
Write-Log "PauseQualityUpdates: $PauseQualityUpdates"

# --- Compose output (names match JSON rules) ---
$Result = [ordered]@{

                        FeatureAndQualityUpdateCompliant     = $FeatureAndQualityUpdateCompliant 
                        PendingReboot                        = If ($PendingReboot -And ($LastRebootDays -gt 7)) {$True} Else {$False}
                        SystemDriveFreeGB                    = $SystemDriveFreeGB
                        DmWapPushServiceHealthy              = ($DMwappushservice.Healthy)
                        IMEHealthy                           = ($IME.Healthy)
                        WindowsUpdateServiceHealthy          = ($WUA.Healthy)
                        MSAServiceHealthy                    = ($MSA.Healthy)
                        DeferQualityUpdatesPeriodInDays      = $DeferQualityUpdatesPeriodInDays
                        PauseQualityUpdates                  = $PauseQualityUpdates
                    }

Write-Log "Final Result JSON: $($Result | ConvertTo-Json -Compress -Depth 3)"

# --- Return single-line JSON ---
$Result | ConvertTo-Json -Depth 3 -Compress


