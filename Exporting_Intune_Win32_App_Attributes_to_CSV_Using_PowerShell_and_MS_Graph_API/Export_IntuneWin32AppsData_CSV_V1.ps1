<#
.SYNOPSIS
    Generates detailed list of all win32 apps with their properties including all detection and requirement rules.
.DESCRIPTION
    This script performs the following actions:
    1. Checks for and installs the required Microsoft.Graph.Beta module if needed
    2. Connects to Microsoft Graph with required permissions
    3. Retrieves all Win32 apps from Intune
    4. Extracts comprehensive properties of each application including all detection and requirement rules
    5. Logs all the data into CSV format

.NOTES
    File Name      : GetIntuneWin32Appsdata.ps1
    Author         : Eswar Koneti @eskonr
    Prerequisite   : PowerShell 5.1 or later
    Modules        : Microsoft.Graph.Beta.Devices.CorporateManagement
    Scopes         : DeviceManagementApps.Read.All
#>

#region Initialization
$Scriptpath = $MyInvocation.MyCommand.Path
$Directory = Split-Path $scriptpath
$Date = (Get-Date -Format 'ddMMyyyy')
$Csvfile = "$directory\ListofWin32Apps_$date.csv"
$AssignmentIncludeAllUsers="#microsoft.graph.allLicensedUsersAssignmentTarget"    #Target type of assignment that represents an 'All users' inclusion assignment
$AssignmentExclusionTarget="#microsoft.graph.exclusionGroupAssignmentTarget"  #Target type of assignment that represents an exclusion assignment
$AssignmentIncludeAllDevices="FUTURE"    #Target type of assignment that represents an 'All device' inclusion assignment
$ModuleNameV1 = "Microsoft.Graph.Devices.CorporateManagement"

#endregion

#region Module Check and Installation
Function Install-MgGraph-WithUsageTracking 
    {

        <#
            .Author - Vishal Navgire
            .Created on - 31-May-2025
            .Co-Author(s)       - N/A
            .Reviwer(s)         - N/A
            .Intended Audience  - 
            .Target Device Type - Windows Machines. 

        .DESCRIPTION 
         1. Installs Microsoft.Graph.Devices.CorporateManagement.
               
        2. Scope of module installation :  
        The scope (CurrentUser vs AllUsers) only determines where the module is installed:
        CurrentUser: Installs to the user's profile ($env:USERPROFILE\Documents\PowerShell\Modules)
        AllUsers: Installs to a system-wide location (C:\Program Files\PowerShell\Modules)

        3. Tracks N/w consumption. 

    Pre-reqs :
    Register an Enterprise application in your tenant with Delegated access. 

    Version Control:
    31-May-2025 :: v1.0

        #>
        [CmdletBinding()]
            Param 
                (
                    [Parameter(Mandatory=$true)]
                    [string]$TenantId,

                    [Parameter(Mandatory=$true)]
                    [string]$EnterpriseAppId
                )

        Function Get-NetworkUsage 
            {
                $Stats = Get-NetAdapterStatistics
                return  ($Stats | Measure-Object -Property ReceivedBytes -Sum).Sum +
                        ($Stats | Measure-Object -Property SentBytes -Sum).Sum
            }

        # Ensure script is running as Administrator
        If (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) 
            {
                Write-Error "Please run this script as Administrator."
                return
            }

        # Record network usage before operation
        $BeforeUsage = Get-NetworkUsage

        # Check Microsoft.Graph module status
        $InstalledVersion = (Get-InstalledModule -Name $ModuleNameV1 -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Version)
        $OnlineVersion    = (Find-Module -Name $ModuleNameV1 -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Version)

        If ($InstalledVersion -eq $OnlineVersion)
            {
                Write-Host " "
                Write-Host "$($ModuleNameV1) module version '$InstalledVersion' is already installed." -ForegroundColor Cyan
            } 
        Else 
            {
                Write-Host "Installing or updating $($ModuleNameV1) module..." -ForegroundColor Yellow
                Install-Module -Name $ModuleNameV1 -Scope CurrentUser -Force -AllowClobber

                $AfterUsage = Get-NetworkUsage
                $DataUsedBytes = $AfterUsage - $BeforeUsage
                $DataUsedMB = [math]::Round($DataUsedBytes / 1MB, 2)
                $DataUsedGB = [math]::Round($DataUsedBytes / 1GB, 2)

                Write-Host "Data consumed for $($ModuleNameV1) module installation: $DataUsedMB MB / $DataUsedGB GB" -ForegroundColor Green
            }

        # Connect to Microsoft Graph
        Try 
            {

                Write-Host "Authentication with Microsoft Graph is in progress. Please wait...." -F Yellow
                Write-Host " "
                Connect-MgGraph -Scopes "DeviceManagementApps.Read.All" -TenantId $TenantId -ClientId $EnterpriseAppId -NoWelcome -ErrorAction Stop

                $Authenticated_UPN = (Get-MgContext | Select-Object -Property Account).Account

                # Check if $Authenticated_UPN has a value (is NOT null or empty)
                If (!([string]::IsNullOrEmpty($Authenticated_UPN))) 
                    {
                        # If $Authenticated_UPN is NOT null or empty (meaning it has a value), then return $True
                        Return $True

                    } 
            }
        Catch 
            {
                Write-Warning "Failed to connect to Microsoft Graph. Check credentials or permissions."
                Return $False
            }
    }
    
$TenantId            = Read-Host "`nEnter you Tenant ID here"
$Ent_App_Id          = Read-Host "`nEnter you Enterprise App ID here"
$Ms_Garph_Connection = Install-MgGraph-WithUsageTracking -TenantId $TenantId -EnterpriseAppId $Ent_App_Id 
$stopwatch           = [System.Diagnostics.Stopwatch]::StartNew()

If ($Ms_Garph_Connection -eq $True)
    { 

        Write-Host ("---" * 25) -F Yellow
        Write-Host "`nConnected to Microsoft Graph:`n" -ForegroundColor Green
        Get-MgContext | Select-Object -Property Account, TenantId, ClientId, AppName | Format-List
        Write-Host ("---" * 25) -F Yellow

        # Invoke-IntuneManagedWindowsDevicesDiscoveredApps

        $Stopwatch.Stop()
        $ElapsedTime = "{0:00 Hours}:{1:00 Minutes}:{2:00 Seconds}" -f $stopwatch.Elapsed.Hours, $stopwatch.Elapsed.Minutes, $stopwatch.Elapsed.Seconds
        Write-Host "`nTotal execution time of this Powershell code : $ElapsedTime`n" -F Yellow
        
        # Start-Process 'C:\Temp\Intune_ManagedApps_Reporting'
    }
Else 
    {
        Write-Host "Failed to authenticate with Microsoft Graph API. Rerun this powershell code with valid credentials." -F Red
        Start-Sleep 5
        Exit

    }

# Initialize an array to store the app information
$appInfoList = @()

# Get all Win32 applications
Write-Host "Getting the list of win32 apps. Please wait....."
# $apps = Get-MgDeviceAppManagementMobileApp -Filter "isof('microsoft.graph.win32LobApp')" -All -ExpandProperty Assignments  -ErrorAction Stop
$apps = Get-MgDeviceAppManagementMobileApp -All -ExpandProperty Assignments  -ErrorAction Stop
Write-Host "Total Win32 apps found: $($apps.Count), extracting the data of each application" -ForegroundColor Cyan

foreach ($app in $apps) {

    #Set initial values
    $Apps=@()

    #What about assignments?
        If ($app.Assignments)
            {
            #This application is assigned.  Lets capture each group that it is assigned to and indicate include / exclude, required / available / uninstall
            $Assignments=""
            foreach ($Assignment in $app.assignments)
                {
                #for each assignment, get the intent (required / available / uninstall)
                $AssignmentIntent=$Assignment.intent
                if ($Assignment.target.AdditionalProperties."@odata.type" -eq $AssignmentExclusionTarget)
                    {
                    #This is an exclusion assignment
                    $AssignmentMode="exclude"
                    $AssignmentGroupName=""
                    }
                elseif ($Assignment.target.AdditionalProperties."@odata.type" -eq $AssignmentIncludeAllUsers)
                    {
                    #This is the all users assignment!
                    $AssignmentMode="include"
                    $AssignmentGroupName="All users"
                    }
                elseif ($Assignment.target.AdditionalProperties."@odata.type" -eq $AssignmentIncludeAllDevices)
                    {
                    #This is the all devices assignment!
                    $AssignmentMode="include"
                    $AssignmentGroupName="All devices"
                    }
                else
                    {
                    #This is an inclusion assignment
                    $AssignmentMode="include"
                    $AssignmentGroupName=""
                    }
                #Get the name corresponding to the assignment groupID (objectID in Azure)
                if ($AssignmentGroupName -eq "")
                    {
                    $AssignmentGroupID=$($Assignment.target.AdditionalProperties."groupId")   #"groupId" is case sensitive!
                    if ($null -ne $AssignmentGroupID)
                        {
                        <#
                        Permissions required as per: https://learn.microsoft.com/en-us/powershell/module/microsoft.graph.groups/get-mggroup?view=graph-powershell-1.0
                        GroupMember.Read.All
                        #>
                        try
                            {
                            $AssignmentGroupName=$(Get-MgGroup -GroupId $AssignmentGroupID -ErrorAction Stop).displayName
                            #If here, the group assignment on the app is still valid
                            }
                        catch
                            {
                            #If here, the group assignment on the app is invalid (the group no longer exists)
                            Write-Host "Group ID $($AssignmentGroupID) on app $($Title) no longer exists!"
                            $AssignmentGroupName=$AssignmentGroupID + "_NOTEXIST"
                            }
                        }
                    else
                        {
                        #if we cannot search for it
                        $AssignmentGroupName="UNKNOWN"
                        }
                    }
                #Save the assignment info
                If ($Assignments -eq "")
                    {
                    #First assignment for this app
                    $Assignments="$AssignmentIntent / $AssignmentMode / " + $AssignmentGroupName
                    }
                else
                    {
                    #additional assignment for this app
                    $Assignments=$Assignments + "`n" + "$AssignmentIntent / $AssignmentMode / " + $AssignmentGroupName
                    }
                }
            }
        else
            {
            #This application isn't assigned
            $Assignments="NONE"
            }

# Process detection rules
# Process detection rules
$detectionRules = @()
$detectionDetails = @()

if ($null -ne $app.AdditionalProperties.detectionRules) {
    foreach ($rule in $app.AdditionalProperties.detectionRules) {
        switch ($rule.'@odata.type') {
            "#microsoft.graph.win32LobAppProductCodeDetection" {
                $detectionRules += "MSI"
                $detectionDetails += "MSI ProductCode: $($rule.productCode)"
            }
            "#microsoft.graph.win32LobAppRegistryDetection" {
                $detectionRules += "Registry"
                $detectionDetails += "Registry: $($rule.keyPath)\$($rule.valueName) | Type: $($rule.detectionType)"
            }
            "#microsoft.graph.win32LobAppFileSystemDetection" {
                $detectionRules += "FileSystem"
                $detectionDetails += "FileSystem: $($rule.path)\$($rule.fileOrFolderName) | Type: $($rule.detectionType)"
            }
            "#microsoft.graph.win32LobAppPowerShellScriptDetection" {
                $detectionRules += "Script"
                $detectionDetails += "Script: $($rule.scriptContent)"
            }
            default {
                $detectionRules += "Unknown"
                $detectionDetails += "Unknown rule type: $($rule.'@odata.type')"
            }
        }
    }
}

# Convert to strings for CSV output
$detectionRulesString = $detectionRules -join ", "
$detectionDetailsString = $detectionDetails -join " | "

    # Process requirement rules
    $requirementRules = @()
    $requirementDetails = @()
    $requirementRuleScript = "NONE"

    if ($null -ne $app.AdditionalProperties.requirementRules) {
        foreach ($rule in $app.AdditionalProperties.requirementRules) {
            $ruleType = switch ($rule.'@odata.type') {
                "#microsoft.graph.win32LobAppPowerShellScriptRequirement" {
                    $requirementDetails += "Script: $($rule.displayName)"
                    "Script"
                    break
                }
                "#microsoft.graph.win32LobAppRegistryRequirement" {
                    $requirementDetails += "Registry: $($rule.keyPath)\$($rule.valueName)"
                    "Registry"
                    break
                }
                "#microsoft.graph.win32LobAppFileSystemRequirement" {
                    $requirementDetails += "FileSystem: $($rule.path)\$($rule.fileOrFolderName)"
                    "FileSystem"
                    break
                }
                "#microsoft.graph.win32LobAppProductCodeRequirement" {
                    $requirementDetails += "MSI"
                    "MSI"
                    break
                }
                default { "Unknown"; break }
            }
            $requirementRules += $ruleType
        }
    }

    $requirementRulesString = $requirementRules -join ", "
    $requirementDetailsString = $requirementDetails -join " | "

    # Check dependencies
    $HasDependencies = if ($app.dependentAppCount -gt 0) { "Yes" } else { "No" }

    # Add the app information to the list
    $appInfoList += [PSCustomObject]@{
        displayName            = $app.DisplayName
        displayVersion         = $app.AdditionalProperties.displayVersion
        description           = $app.description
        publisher             = $app.publisher
        setupFilePath         = $app.AdditionalProperties.setupFilePath
        installCommandLine    = $app.AdditionalProperties.installCommandLine
        uninstallCommandLine  = $app.AdditionalProperties.uninstallCommandLine
        allowedArchitectures=$app.AdditionalProperties.allowedArchitectures
        detectionRules        = $detectionRulesString
        detectionDetails      = $detectionDetailsString
        requirementRules      = $requirementRulesString
        requirementDetails    = $requirementDetailsString
        hasDependencies       = $HasDependencies
        createdDateTime       = (([datetime]$app.createdDateTime).ToLocalTime()).ToString("MM/dd/yyyy HH:mm:ss")
        lastModifiedDateTime  = (([datetime]$app.lastModifiedDateTime).ToLocalTime()).ToString("MM/dd/yyyy HH:mm:ss")
        owner                 = $app.owner
        developer             = $app.developer
        notes                 = $app.notes
        uploadState           = $app.uploadState
        publishingState       = $app.publishingState
        isAssigned            = $app.isAssigned
        Assignments           = $Assignments
        Appid                 = $app.id

    }
}

# Export the app information to a CSV file
$appInfoList | Export-Csv -Path $csvfile -NoTypeInformation -Encoding UTF8

Write-Host ""
Write-Host "Script completed, Log file created at '$csvfile'" -ForegroundColor 'Green'
Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
Write-Host ""