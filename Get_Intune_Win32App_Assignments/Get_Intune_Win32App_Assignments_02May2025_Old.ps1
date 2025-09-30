<#
.Author         - Vishal Navgire [VishalNavgire54@Gmail.Com]
.Company        - 
.Created on     - 02-May-2025
.Co-Author(s)   -
.Reviewer(s)    -  

.Requirement
    1. Microsoft Entra App needs to be registered in to your Tenant first with permission type as 'Delegated'. After you complete App's registration please 
        update App's ID in the line no# 48 or search variable name 👉  $Registered_Entra_App_ID = "App ID". To read more on how to create / register an MS Entra App Id with Delegated rights - https://learn.microsoft.com/en-us/graph/auth-register-app-v2#register-an-application 
    2. Set API Permission - 'DeviceManagementApps.Read.All'. To read more about this API permission - https://learn.microsoft.com/en-us/graph/permissions-reference#devicemanagementappsreadall
    3. Use an account that has Admin rights to run this script on a device.
    4. To interact with Intune's data, log in with an account that has sufficient permissions to read Intune's Win32 App.
    

.Description
    This script fetches and processes application assignment data from Microsoft Graph API, specifically for Win32 applications managed through Intune. 
    It then formats and exports this data to a CSV file.

.Version Control:
    02-May-2025 :: v1.0 
    24-Sep-2025 :: V1.1 
#>

Function Set-HostBackgroundColor 
{
    param (
        [Parameter(Mandatory=$true)]
        [string]$Color
    )

    Clear-Host
    $Host.UI.RawUI.BackgroundColor = $Color
    $SetBG_Colour = $Color

    While ($Host.UI.RawUI.BackgroundColor -ne $SetBG_Colour) 
        {
            $Host.UI.RawUI.BackgroundColor = $Color
            Start-Sleep -Seconds 5
        }

    Clear-Host
    Start-Sleep 5
}

Set-HostBackgroundColor -Color "Black"

#Enter valid MS Entra Registered Application ID. 
$Registered_Entra_App_ID = $null

# Install MS Graph Intune Module and Connect to MS Graph for Authentication.
Function Install-MSGraphIntuneModule 
    {
        [CmdletBinding()]
                param (
                    [Parameter(Mandatory=$false)]
                    [string]$InstallModuleName = "Microsoft.Graph.Intune",
                    
                    [Parameter(Mandatory = $false)]
                    [string]$ApiVersion = "Beta",

                    [Parameter(Mandatory = $false)]
                    $Application_Id = $Registered_Entra_App_ID
                )

        # Clear-Host

        $Module = Get-Module -Name $InstallModuleName -ListAvailable

        If ($Module.Count -eq 0) 
        {
            "`n"
            Write-Host "Microsoft Intune Graph Module not found. " -NoNewline -ForegroundColor Red
            Write-Host "Required module will be installed to device '$($Env:COMPUTERNAME)'. Installing '$InstallModuleName' module, please wait...." -ForegroundColor Yellow

            Try 
                {
                    Install-Module -Name $InstallModuleName -Repository PSGallery -Force -ErrorAction Stop
                    "`n"
                    Write-Host "Enter your credentials to connect to Microsoft Intune..." -ForegroundColor Cyan
                    "`n"
                    Update-MSGraphEnvironment -AppId $($Application_Id) -SchemaVersion $ApiVersion -Quiet -ErrorAction Stop
                    $Global:IntuneId = Connect-MSGraph -ErrorAction Stop
                    $TenantId = ($IntuneId.TenantId).ToUpper()
                    If (![string]::IsNullOrEmpty($IntuneId)) 
                        {
                            Write-Host "Connected to Microsoft Tenant ID $TenantId using $($IntuneId.UPN)" -ForegroundColor Green
                            "`n"
                        }
                    Else 
                        {
                            Write-Host "Connection to Microsoft Intune Tenant ID $TenantId failed on device '$($Env:COMPUTERNAME)'. Try again..." -ForegroundColor Red
                            "`n"
                            $($Error.Exception.Message)
                            "`n"
                            $(Write-Host "Press ENTER key to exit from PowerShell console!!!" -ForegroundColor Red; Read-Host)
                            Exit
                        }

                } 
            Catch 
                {
                    Write-Host "Failed to install module name: $InstallModuleName." -ForegroundColor Red
                    "`n"
                    Write-Host "Error Details: $($_.Exception.Message)" -ForegroundColor Yellow
                    $(Write-Host "Press ENTER key to exit from PowerShell console!!!" -ForegroundColor Yellow; Read-Host)
                    Exit
                }
        }
        
        Elseif ($Module.Count -eq 1) 
            {
                Try 
                    {
                            "`n"
                            Write-Host "Enter your credentials to connect to Microsoft Intune..." -ForegroundColor Cyan
                            "`n"
                            Update-MSGraphEnvironment -AppId $($Application_Id) -SchemaVersion $ApiVersion -Quiet -ErrorAction Stop
                            $IntuneId = Connect-MSGraph -ErrorAction Stop
                            $TenantId = ($IntuneId.TenantId).ToUpper()
                        If (![string]::IsNullOrEmpty($IntuneId)) 
                            {
                                Write-Host "Connected to Microsoft Tenant ID $TenantId using $($IntuneId.UPN)" -ForegroundColor Green
                                "`n"
                            }
                        Else 
                            {
                                Write-Host "Connection to Microsoft Intune Tenant ID $TenantId failed on device '$($Env:COMPUTERNAME)'. Try again..." -ForegroundColor Red
                                "`n"
                                $($Error.Exception.Message)
                                "`n"
                                $(Write-Host "Press ENTER key to exit from PowerShell console!!!" -ForegroundColor Red; Read-Host)
                                Exit
                            }

                    }
                Catch 
                    {
                        Write-Host "Connection to Microsoft Intune Tenant ID $TenantId failed on device $($Env:COMPUTERNAME). Try again..." -ForegroundColor Yellow
                        "`n"
                        Write-Host "Error Details: $($_.Exception.Message)" -ForegroundColor Red
                        $(Write-Host "Press ENTER key to exit from PowerShell console!!!" -ForegroundColor Yellow; Read-Host)
                        Exit
                    }
            }
            return [PSCustomObject]@{
                                    User_UPN = $IntuneId.UPN
                                    TenantId = $IntuneId.TenantId
                                    Device = $env:COMPUTERNAME
                }
            
    }
$Connect_To_Tenant = Install-MSGraphIntuneModule

Write-Host "`n"

# Prompt user for CSV report save location
Do {
        Write-Host "Location to save CSV report (Ex: C:\Temp OR C:\IntuneReports) and press Enter:" -ForegroundColor White
        $Location_To_Save_Csv_Report = Read-Host
        Write-Host "`n"
    
     If (-not [string]::IsNullOrWhiteSpace($Location_To_Save_Csv_Report)) 
     {
            If (-not (Test-Path -Path $Location_To_Save_Csv_Report)) 
            {
                Try 
                    {
                        New-Item -ItemType Directory -Path $Location_To_Save_Csv_Report -Force | Out-Null
                        Write-Host "Created new directory: $Location_To_Save_Csv_Report" -ForegroundColor Green
                    } 
                Catch 
                    {
                        Write-Host "Failed to create directory: $($_.Exception.Message)" -ForegroundColor Red
                        $Location_To_Save_Csv_Report = $null # Reset to re-prompt
                    }
            }
    } 
    Else 
        {
            Write-Host "Path cannot be empty. Please enter a valid location." -ForegroundColor Yellow
        }
    }
While ([string]::IsNullOrWhiteSpace($Location_To_Save_Csv_Report))
    

# Function retrieves the display name of a group given its Group ID by making a request to the Microsoft Graph API.
Function Get-GroupMsEntraGroupDisplayName 
    {
        Param 
        (
            [Parameter(Mandatory = $True)]
            $GroupId
        )

        $Resource = "Groups"
        $GraphApiVersion = "Beta"
        $Uri = "https://graph.microsoft.com/$GraphApiVersion/$Resource/$($GroupId)"

        Try 
        {
            $Win32_App_Deployed_To_Group_Name = Invoke-MSGraphRequest -HttpMethod GET -Url $Uri
            Return $Win32_App_Deployed_To_Group_Name.DisplayName
        } 
        Catch 
        {
            Write-Error "Failed to retrieve group information: $($Error[0].Exception.Message)"
        }
    }

# Array to hold all data processed
$AllWin32AppDeployment = @()

# Initial API request to gather Win32App info from Intune.
$Resource = "DeviceAppManagement/MobileApps"
$GraphApiVersion = "Beta"
$Uri = "https://graph.microsoft.com/$GraphApiVersion/$($Resource)?`$expand=assignments"
$Win32AppDeployment = Invoke-MSGraphRequest -HttpMethod GET -Url $Uri
$App_Counter = 0

#Do While loop to read through all pages to gather Win32App Deployment status.
Do {
        Try 
            {
                $Win32AppDeployment.value | ForEach-Object {
                    $App_Counter ++
                    # Write-Host "Processing Intune_Win32_App_Name: $($App_Counter). '$(($Name.DisplayName).ToUpper())' " -F Green
                    Write-Host "Processing Intune_Win32_App_Name: $($App_Counter). '$(($Name.DisplayName))' " -F Green
                    Write-Host "==================================================================="
                    $Name = $_
                    $AAD_Group_Names = If ($Name.Assignments) 
                                            {
                                                Try 
                                                    {
                                                        ($Name.Assignments | ForEach-Object { 
                                                                                             
                                                                                            If ($_.Target."@odata.type" -eq "#microsoft.graph.allLicensedUsersAssignmentTarget") 
                                                                                                    {"All Users" }
                                                                                            ElseIf ($_.Target."@odata.type" -eq "#microsoft.graph.allDevicesAssignmentTarget") 
                                                                                                    {"All Devices" }
                                                                                            Else 
                                                                                                {
                                                                                                    Get-GroupMsEntraGroupDisplayName -GroupId $($_.Target.GroupId)
                                                                                                }
                                                                                                
                                                                                            }) -Join "; "
                                                    }
                                                    Catch 
                                                    {
                                                        Write-Host "An Error Occurred. Unable to retreive assignment for App Name '$($(($Name.DisplayName).ToUpper()))'" -F Red
                                                        Write-Output $($Error[0])
                                                    
                                                    }
                                                
                                            } 
                                        Else 
                                            {
                                                "App not assigned to any MS Entra Group"
                                            }

                    $App_Intent = If ($Name.Assignments) 
                                    {
                                        ($Name.Assignments | ForEach-Object { $_.Intent}) -Join "; "
                                    } 
                                Else 
                                    {
                                        "No Results"
                                    }


                    $MsEntra_Group_ID =  If ($Name.Assignments) 
                                            {   
                                                (
                                                    $Name.Assignments | ForEach-Object { 
                                                                                            If ($_.Target.GroupId) 
                                                                                                {
                                                                                                    Return $($_.Target.GroupId)
                                                                                                } 
                                                                                            Else { "Not Available"}              

                                                                                        }
                                                )  -Join "; "

                                            }
                    $AllWin32AppDeployment += [PSCustomObject] @{
                                                                    App_Name          = ($Name.DisplayName).ToUpper()
                                                                    App_Type          = (($Name."@odata.type").Substring(17)).ToUpper()
                                                                    App_Version       = If ([string]::IsNullOrWhiteSpace(($Name.DisplayVersion))) {"No version specified"} Else {$($Name.DisplayVersion)}
                                                                    App_Id            = ($Name.Id).ToUpper()
                                                                    App_LastUpdatedOn = ($Name.LastModifiedDateTime)
                                                                    App_Publish_Status = ($Name.PublishingState)
                                                                    App_IntuneWinFile_Name = ($Name.FileName)
                                                                    App_Install_Command = ($Name.InstallCommandLine)
                                                                    App_Uninstall_Command =($Name.UninstallCommandLine)
                                                                    MsEntra_Group_ID   = If ([string]::IsNullOrWhiteSpace($MsEntra_Group_ID)) {"Nothing to show"} Else {$MsEntra_Group_ID.ToUpper()}
                                                                    MsEntra_Group_Name = $AAD_Group_Names.ToUpper()
                                                                    App_Intent        = $App_Intent.ToUpper()
                                                                    
                                                                }
                    }
# Get the next page of results
$Win32AppDeployment = If ($Win32AppDeployment.'@odata.nextLink') 
                        {
                            Invoke-MSGraphRequest -HttpMethod GET -Url $Win32AppDeployment.'@odata.nextLink'
                        } 
                    Else 
                        {
                            $null
                        }
            }
        Catch 
            {
                Write-Host "===============================" -F Yellow
                Write-Host "An Error Occurred:" -F Red
                Write-Host " " 
                Write-Output $($Error[0])
                Write-Host "===============================" -F Yellow
                Continue
            }
    }

While ($Win32AppDeployment)

#Formated Timestamp for Csv Reporting
$Csv_Report_DateTimeFormat = Get-Date -Format "dd-MMMM-yyyy_hh-mm-ss_tt"
#Export the results to a CSV file
$AllWin32AppDeployment | Export-Csv -Path (Join-Path $Location_To_Save_Csv_Report -ChildPath "\Intune_Win32_Apps_Assignments_Data_$($Csv_Report_DateTimeFormat).Csv") -NoTypeInformation -Force

#Date & Time
$Completion_Date_Time_Of_Ps_Code = (Get-Date -Format "dd:MMMM:yyyy hh:mm:ss tt")

#TimeZone
$Current_TimeZone = (Get-TimeZone).Id

#Message
Write-Host "`n"
$Message = "Data exported to CSV successfully by user name: '$($Connect_To_Tenant.User_UPN)' at $($Completion_Date_Time_Of_Ps_Code) $($Current_TimeZone)."
Write-Host $Message -F Yellow
Start-Sleep 2

#Lauch File explorer where HTML Report was saved.
Start-Process $($Location_To_Save_Csv_Report)