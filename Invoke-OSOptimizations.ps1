#Requires -Version 5.1
<#
.SYNOPSIS
    OS Optimization Script
.DESCRIPTION
    This PowerShell script optimizes the operating system by disabling non-critical services, removing non-essential software,
    and ensuring that the required Visual C++ runtimes are installed.
    At least one of the following parameters must be specified: GetCurrentUser or Username.
.PARAMETER LogDirectory
    The directory where logs will be stored. Default is "C:\OSOptimizations".
    If the directory does not exist, it will be created.
    This parameter is optional and can be customized as needed.
.PARAMETER Username
    The username for which the script will apply certain settings, such as preventing app reinstallation.
    Default is "jdoe". This parameter is optional and can be customized as needed.
.PARAMETER GetCurrentUser
    If specified, the script will retrieve the current user's username instead of using the default.
.PARAMETER DisplaySummary
    If specified, the script will display a summary of actions taken at the end of execution.
    This parameter is optional and can be used to control whether a summary is displayed or not.
.INPUTS
    None. This script does not accept any input parameters from the pipeline.
    It is designed to be run directly with the specified parameters.
.OUTPUTS
    C:\path\to\logs\OptimizationChanges.json
    C:\path\to\logs\OptimizationSummary.log
    C:\path\to\logs\OptimizationTranscript.log
.NOTES
    Author         | Jason Bradley Darling
    Creation Date  | [DMY] 23.12.2021
    Last Edit Date | [DMY] 23.07.2025
    Version        | 0.0.25
    License        | MIT -- https://opensource.org/licenses/MIT -- Copyright (c) 2021-2025 Jason Bradley Darling
    Change Log     | 2021-04-12: Initial version created by Jason Bradley Darling.
                   | 2023-10-02: Added functionality to check and install Visual C++ runtimes.
                   | 2025-07-17: Improved logging and error handling.
                   | 2025-07-20: Corrected Visual C++ installation logic to handle different versions and arguments.
                   | 2025-07-21: Corrected Visual C++ installation logic to ensure both x86 and x64 versions are installed correctly. Updated logic and syntax in various functions.
                   | 2025-07-22: Added various performance optimizations. Updated logic for some functions.
                   | 2025-07-23: Add AppUnpinning function to unpin apps from Start Menu and Taskbar.
    Requirements   | PowerShell 5.1 or later, administrative privileges
    Compatibility  | Windows 10 and later
    Notes          | This script is intended for use in a corporate environment to streamline OS performance and reduce bloat.
                   | It is recommended to test this script in a controlled environment before deploying widely.
    Purpose        | To aid in the increase of productivity in a corporate environment via standardized system configuration and
                   | performance optimizations.
    Disclaimer     | Use this script at your own risk. The author is not responsible for any issues that may arise from its use.
.EXAMPLE
    .\Run-OSOptimization.ps1 -LogDirectory "C:\FolderName" -Username "jdoe"
        This command runs the OS optimization script with specified log directory and username.
.EXAMPLE
    .\Run-OSOptimization.ps1 -LogDirectory "C:\FolderName" -GetCurrentUser
        This command runs the OS optimization script with specified log directory and retrieves the current user's username.
.EXAMPLE
    .\Run-OSOptimization.ps1 -Username "jdoe" -DisplaySummary
        This command runs the OS optimization script and displays a summary of actions taken at the end of execution.
        Note: The script will prompt for administrative privileges if not already running as an administrator.
#>

#-----------------------------------------------------------[Parameters]-----------------------------------------------------------
[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$LogDirectory = "C:\OSOptimizations",
    [Parameter(Mandatory=$false)]
    [string]$Username = "null",
    [Parameter(Mandatory=$false)]
    [switch]$GetCurrentUser,
    [Parameter(Mandatory=$false)]
    [switch]$DisplaySummary,
    [Parameter(Mandatory=$false)]
    [switch]$Revert,
    [Parameter(Mandatory=$false)]
    [switch]$WhatIf
)

#------------------------------------------------------------[Elevation]-----------------------------------------------------------
$myWindowsID=[System.Security.Principal.WindowsIdentity]::GetCurrent()
$myWindowsPrincipal=new-object System.Security.Principal.WindowsPrincipal($myWindowsID)
$adminRole=[System.Security.Principal.WindowsBuiltInRole]::Administrator
if (-Not($myWindowsPrincipal.IsInRole($adminRole))) {
    $newProcess             = new-object System.Diagnostics.ProcessStartInfo "PowerShell";
    $newProcess.Arguments   = $myInvocation.MyCommand.Definition;
    $newProcess.Arguments   = $myInvocation.MyCommand.Path;
    $newProcess.Verb        = "runas";
    [System.Diagnostics.Process]::Start($newProcess);
    exit
}

#----------------------------------------------------------[Declarations]----------------------------------------------------------
$changeLogPath      = Join-Path $LogDirectory "OptimizationChanges.json"
$summaryLogPath     = Join-Path $LogDirectory "OptimizationSummary.log"
$transcriptLogPath  = Join-Path $LogDirectory "OptimizationTranscript.log"
$changeMap          = @{}
$summary            = @()
$start              = $([DateTime]::Now)
$HWND_BROADCAST     = [intptr]0xffff
$WM_SETTINGCHANGE   = 0x001A
$getString          = @'
[DllImport("kernel32.dll", CharSet = CharSet.Auto)]
public static extern IntPtr GetModuleHandle(string lpModuleName);
[DllImport("user32.dll", CharSet = CharSet.Auto)]
internal static extern int LoadString(IntPtr hInstance, uint uID, StringBuilder lpBuffer, int nBufferMax);
public static string GetString(uint strId) {
    IntPtr intPtr = GetModuleHandle("shell32.dll");
    StringBuilder sb = new StringBuilder(255);
    LoadString(intPtr, strId, sb, sb.Capacity);
    return sb.ToString();
}
'@
Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public class NativeMethods {
    [DllImport("user32.dll", SetLastError = true)]
    public static extern IntPtr SendMessage(IntPtr hWnd, int Msg, IntPtr wParam, IntPtr lParam);
}
"@


#---------------------------------------------------------[Initializations]--------------------------------------------------------
$ErrorActionPreference                  = "SilentlyContinue"
if (!(Test-Path $LogDirectory))         { New-Item -Path $LogDirectory -ItemType Directory -Force | Out-Null }
if (-Not(Test-Path $changeLogPath))     { New-Item -Path $changeLogPath -ItemType File | Out-Null }
if (-Not(Test-Path $summaryLogPath))    { New-Item -Path $summaryLogPath -ItemType File | Out-Null }

#region [ Get Current User ]
if ($GetCurrentUser -or $Username -eq "null") {
    # Get Current logged on user
    $userCheck1 = ((Get-WMIObject -ClassName Win32_ComputerSystem).Username).Split('\')[1]
    if ($null -eq $userCheck1) {
        $userCheck2 = ((Get-CimInstance -ClassName Win32_ComputerSystem).UserName).Split('\')[1]
        if ($null -eq $userCheck2) {
            $userCheck3 = ((Get-Process -ProcessName explorer -IncludeUsername).Username).Split('\')[1]
            if ($null -eq $userCheck3) {
                $userCheck4 = (quser | Select-Object -Skip 1 | ForEach-Object { $_.Split(' ')[0] }).Trim("<>.,:;'!@#$%^&*()")
                if ($null -eq $userCheck4) {
                    $explorerprocesses = @(Get-WmiObject -Query "Select * FROM Win32_Process WHERE Name='explorer.exe'" -ErrorAction SilentlyContinue)
                    if ($explorerprocesses.Count -eq 1) {
                        foreach ($i in $explorerprocesses) {
                            $Username = $i.GetOwner().User
                            Write-Host "Detected username using 'WMI Explorer Process Query' method: $($Username)"
                        }
                    } else {
                        Write-Host "ERROR: Zero or multiple users are currently logged in. There can be only 1." -ForegroundColor Red
                        Start-Sleep -Seconds 15
                        exit 09990404
                    }
                } else {
                    $Username = $userCheck4
                    Write-Host "Detected username using 'quser' method: $($Username)"
                }
            } else {
                $Username = $userCheck3
                Write-Host "Detected username using 'Get-Process' method: $($Username)"
            }
        } else {
            $Username = $userCheck2
            Write-Host "Detected username using 'CIM' method: $($Username)"
        }
    } else {
        $Username = $userCheck1
        Write-Host "Detected username using 'WMI' method: $($Username)"
    }
}
#endregion

#region [ Reversion ]
if ($Revert) {
    if (!(Test-Path $changeLogPath)) {
        Write-Warning "No OptimizationChanges.json found for rollback."
        return
    }
    $revertData = Get-Content $changeLogPath | ConvertFrom-Json
    foreach ($path in $revertData.Keys) {
        foreach ($name in $revertData[$path].Keys) {
            $orig = $revertData[$path][$name].original
            if ($null -ne $orig) {
                Set-ItemProperty -Path $path -Name $name -Value $orig -Force
                $summary += "Reverted: $name at $path --> $orig"
            }
        }
    }
    $summary | Set-Content -Path $summaryLogPath
    Write-Host "`nReversion complete. Summary saved to:`n$summaryLogPath"
    return
}
#endregion

#-----------------------------------------------------------[Functions]------------------------------------------------------------
#region [ Functions ]
function Invoke-LogStatus {
    [cmdletbinding()]
    param($Log)
    if ((Get-Item $Log).length -ge 1) {
        Add-Content -Path $Log -Value "---------------------------------------------------------------------------"
        Add-Content -Path $Log -Value "---------------------------------------------------------------------------"
        Add-Content -Path $Log -Value " "
    }
}
function Invoke-RegistryChange {
    param (
        [string]$Path,
        [string]$Name,
        [int]$NewValue,
        [string]$Type
    )
    Write-Host "Applying registry change at $Path for $Name with value $NewValue"
    try {
        $original = Get-ItemPropertyValue -Path $Path -Name $Name
    } catch {
        $original = $null
    }
    if (-not $changeMap.ContainsKey($Path)) {
        $changeMap[$Path] = @{}
    }
    $changeMap[$Path][$Name] = @{ original = $original; new = $NewValue }

    $originalValue = if ($null -ne $original) { $original } else { "N/A" }
    $summary += "$Name at $Path --> original: $originalValue, new: $NewValue"

    if (-not $WhatIf) {
        New-ItemProperty -Path $Path -Name $Name -PropertyType $Type -Value $NewValue -Force | Out-Null
    }
}
function Invoke-NonCriticalServicesDisablement {
    Write-Host "`n--- Disabling non-critical services for user: $Username ---"
    $services = @("Fax", "XblGameSave", "WSearch", "DiagTrack", "RetailDemo")
    foreach ($svc in $services) {
        $service = Get-Service -Name $svc -ErrorAction SilentlyContinue
        if ($service -and $service.Status -ne 'Stopped') {
            Set-Service -Name $svc -StartupType Disabled
            Stop-Service -Name $svc -Force
            $summary += "Disabled service: $svc"
        }
    }
}
function Invoke-AppCleanup {
    Write-Host "`n--- Removing non-essential apps for user: $Username ---"
    $apps = @("Candy", "Cortana", "eBay", "Facebook", "FeedbackHub", "Netflix", "Roblox", "Skype", "Spotify", "TikTok", "Twitter", "Weather", "Xbox", "YouTube")
    foreach ($app in $apps) {
        $packages = Get-AppxPackage -Name "*$app*" -ErrorAction SilentlyContinue
        foreach ($pkg in $packages) {
            Start-Job -Name WaitForJob -ScriptBlock { Remove-AppxPackage -Package $pkg.PackageFullName }
            Wait-Job -Name WaitForJob
            $summary += "Removed app: $($pkg.Name)"
        }
    }
}
function Invoke-AppReinstallBlock {
    Write-Host "`n--- Blocking app reinstallation for user: $Username ---"
    try {
        $sid = (New-Object System.Security.Principal.NTAccount($Username)).Translate([System.Security.Principal.SecurityIdentifier]).Value
        $targetKey = "Registry::HKU\$sid\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"
    } catch {
        Write-Warning "SID resolution failed for $Username"
        return
    }
    $keys = @(
        "ContentDeliveryAllowed","FeatureManagementEnabled","OemPreInstalledAppsEnabled",
        "PreInstalledAppsEnabled","SilentInstalledAppsEnabled","SubscribedContentEnabled"
    )
    foreach ($key in $keys) {
        Set-ItemProperty -Path $targetKey -Name $key -Value 0 -Type DWord -Force
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore" -Name "AutoDownload" -Value 2 -Type DWord -Force
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableWindowsConsumerFeatures" -Value 1 -Type DWord -Force
    $summary += "Blocked app reinstall for user: $Username"
}
function Invoke-AppUnpinning {
    $getstring = Add-Type $getstring -PassThru -Name GetStr -Using System.Text
    $unpinFromStart1 = $getstring[0]::GetString(51394)
    $unpinFromStart2 = $getstring[0]::GetString(5382)
    <#
        Notes :
        5381  : Pin to Start
        5382  : Unpin From Start

        5386  : Pin to Taskbar
        5387  : Unpin from Taskbar

        51201 : Pin to Start
        51394 : Unpin from Start

    #>

    function Pin-App ([string]$appname, [switch]$unpin, [switch]$start, [switch]$taskbar, [string]$path) {
        if ($unpin.IsPresent) {
            $action = "unpin"
        } else {
            $action = "pin"
        }
        if (-not $taskbar.IsPresent -and -not $start.IsPresent) {
            Write-Error "Specify -taskbar and/or -start!"
        }
        if ($taskbar.IsPresent) {
            try {
                $exec = $false
                if ($action -eq "Unpin") {
                    ((New-Object -Com Shell.Application).NameSpace('shell:::{4234d49b-0245-4df3-b780-3893943456e1}').Items() | ?{$_.Name -eq $appname}).Verbs() | ?{$_.Name.replace('&','') -match 'Unpin from taskbar'} | %{$_.DoIt(); $exec = $true}
                    if ($exec) {
                        Write-Host "App '$appname' unpinned from Taskbar"
                    } else {
                        if (-not $path -eq "") {
                            Pin-AppByPath $path -Action $action
                        } else {
                            Write-Host "'$appname' not found or 'Unpin from taskbar' not found on item!"
                        }
                    }
                } else {
                    ((New-Object -Com Shell.Application).NameSpace('shell:::{4234d49b-0245-4df3-b780-3893943456e1}').Items() | ?{$_.Name -eq $appname}).Verbs() | ?{$_.Name.replace('&','') -match 'Pin to taskbar'} | %{$_.DoIt(); $exec = $true}
                    if ($exec) {
                        Write-Host "App '$appname' pinned to Taskbar"
                    } else {
                        if (-not $path -eq "") {
                            Pin-AppByPath $path -Action $action
                        } else {
                            Write-Host "'$appname' not found or 'Pin to taskbar' not found on item!"
                        }
                    }
                }
            } catch {
                Write-Error "Error Pinning/Unpinning '$appname' to/from taskbar!"
            }
        }
        if ($start.IsPresent) {
            try {
                $exec = $false
                if ($action -eq "Unpin") {
                    ((New-Object -Com Shell.Application).NameSpace('shell:::{4234d49b-0245-4df3-b780-3893943456e1}').Items() | ?{$_.Name -eq $appname}).Verbs() | ?{$_.Name.replace('&','') -match 'Unpin from Start'} | %{$_.DoIt(); $exec = $true}
                    if ($exec) {
                        Write-Host "App '$appname' unpinned from Start" -ForegroundColor Green
                    } else {
                        if (-not $path -eq "") {
                            Pin-AppByPath $path -Action $action -start
                        } else {
                            Write-Host "'$appname' not found or 'Unpin from Start' not found on item!"
                        }
                    }
                } else {
                    ((New-Object -Com Shell.Application).NameSpace('shell:::{4234d49b-0245-4df3-b780-3893943456e1}').Items() | ?{$_.Name -eq $appname}).Verbs() | ?{$_.Name.replace('&','') -match 'Pin to Start'} | %{$_.DoIt(); $exec = $true}
                    if ($exec) {
                        Write-Host "App '$appname' pinned to Start"
                    } else {
                        if (-not $path -eq "") {
                            Pin-AppByPath $path -Action $action -start
                        } else {
                            Write-Host "'$appname' not found or 'Pin to Start' not found on item!"
                        }
                    }
                }
            } catch {
                Write-Error "Error Pinning/Unpinning '$appname' to/from Start!"
            }
        }
    }

    function Pin-AppByPath([string]$Path, [string]$Action, [switch]$start) {
        if ($Path -eq "") {
            Write-Error -Message "You need to specify a Path" -ErrorAction Stop
        }
        if ($Action -eq "") {
            Write-Error -Message "You need to specify an action: Pin or Unpin" -ErrorAction Stop
        }
        if ((Get-Item -Path $Path -ErrorAction SilentlyContinue) -eq $null){
            Write-Error -Message "$Path not found" -ErrorAction Stop
        }
        $Shell = New-Object -ComObject "Shell.Application"
        $ItemParent = Split-Path -Path $Path -Parent
        $ItemLeaf = Split-Path -Path $Path -Leaf
        $Folder = $Shell.NameSpace($ItemParent)
        $ItemObject = $Folder.ParseName($ItemLeaf)
        $Verbs = $ItemObject.Verbs()
        if ($start.IsPresent) {
            switch($Action) {
                "Pin"   {$Verb = $Verbs | Where-Object -Property Name -EQ "&Pin to Start"}
                "Unpin" {$Verb = $Verbs | Where-Object -Property Name -EQ "Un&pin from Start"}
                default {Write-Error -Message "Invalid action, should be Pin or Unpin" -ErrorAction Stop}
            }
        } else {
            switch($Action) {
                "Pin"   {$Verb = $Verbs | Where-Object -Property Name -EQ "Pin to Tas&kbar"}
                "Unpin" {$Verb = $Verbs | Where-Object -Property Name -EQ "Unpin from Tas&kbar"}
                default {Write-Error -Message "Invalid action, should be Pin or Unpin" -ErrorAction Stop}
            }
        }
        if($Verb -eq $null) {
            Write-Error -Message "That action is not currently available on this Path" -ErrorAction Stop
        } else {
            $Result = $Verb.DoIt()
        }
    }

    Write-Host "`n--- Unpinning apps from Start Menu and Taskbar for user: $Username ---"
    (New-Object -Com Shell.Application).NameSpace('shell:::{4234d49b-0245-4df3-b780-3893943456e1}').Items() | ForEach-Object{ $_.Verbs() | Where-Object{$_.Name -eq $unpinFromStart1} | ForEach-Object{$_.DoIt()}}
    (New-Object -Com Shell.Application).NameSpace('shell:::{4234d49b-0245-4df3-b780-3893943456e1}').Items() | ForEach-Object{ $_.Verbs() | Where-Object{$_.Name -eq $unpinFromStart2} | ForEach-Object{$_.DoIt()}}

    #$applist = @("3DBuilder", "Adobe Photoshop Express", "Alarms & Clock", "Asphalt 8: Airborne", "Bubble Witch 3 Saga", "Calculator", "Calendar", "Camera", "Candy Crush Soda Saga", "Code Writer", "CommsPhone", "Connect", "ConnectivityStore", "ContentDeliveryManager", "Cortana", "DefaultStartLayout", "Drawboard", "Duolingo", "Eclipse Manager", "Feedback Hub", "Finance", "Flipboard", "FreshPaint", "Fresh Paint", "Get Help", "Get Office", "GetStarted", "Google Chrome", "Groove Music", "Groove Video", "iHeartRadio", "Maps", "Mail", "Mail", "March of Empires: War of Lords", "Messaging", "Microsoft Edge", "MicrosoftOfficeHub", "MicrosoftPowerBIForWindows", "Microsoft Power BI", "Microsoft Solitaire Collection", "MicrosoftStickyNotes", "Microsoft Store", "Microsoft Store", "Microsoft Sway", "Microsoft To-Do", "Microsoft Whiteboard", "Microsoft.Windows.ContentDeliveryManager", "Minecraft", "MinecraftUWP", "Mixed Reality Portal", "Mixed Reality Viewer", "Mobile Plans", "Money", "Movies & TV", "MSPaint", "Music", "My Office", "Network Speed Test", "News", "Notepad", "Office Lens", "OneConnect", "OneNote", "Paid Wi-Fi & Cellular", "Paint 3D", "Pandora", "People", "Phone", "Phone Companion", "Photos", "Plex", "Power BI", "Preinstalled", "Print 3D", "Remote Desktop", "Shazam", "SketchBook", "Skype", "SkypeApp", "Sports", "Spotify", "Stickies", "Sticky Notes", "Store", "Store", "SurfaceHub", "Sway", "TheNewYorkTimes.NYTCrossword", "Tips", "Twitter", "Video", "Voice Recorder", "Weather", "WindowsAlarms", "WindowsCalculator", "WindowsCamera", "windowscommunicationapps", "WindowsMaps", "WindowsSoundRecorder", "Xbox", "Zune Music", "Zune Video")
    #foreach ($app in $applist) {
    #    Pin-App -appname $app -unpin -start
    #    Pin-App -appname $app -unpin -taskbar
    #}
    #Pin-App "Explorer" -pin -taskbar
    #Pin-App "Microsoft Edge" -pin -taskbar
    $summary += "Unpinned apps from Start Menu for user: $Username"
}
function Invoke-VisualCRuntimesCheck {
    $vcRuntimes=@(
        @{ Year = "2005"; Arch = "x86"; Version="8.0.61001"; Display="Microsoft Visual C++ 2005 Redistributable"; Url = "https://download.microsoft.com/download/8/b/4/8b42259f-5d70-43f4-ac2e-4b208fd8d66a/vcredist_x86.EXE"; $Arg = "/q" },
        @{ Year = "2005"; Arch = "x64"; Version="8.0.61000"; Display="Microsoft Visual C++ 2005 Redistributable (x64)"; Url = "https://download.microsoft.com/download/8/b/4/8b42259f-5d70-43f4-ac2e-4b208fd8d66a/vcredist_x64.EXE"; $Arg = "/q" },
        @{ Year = "2008"; Arch = "x86"; Version="9.0.30729.6161"; Display="Microsoft Visual C++ 2008 Redistributable x86"; Url = "https://download.microsoft.com/download/5/D/8/5D8C65CB-C849-4025-8E95-C3966CAFD8AE/vcredist_x86.exe"; $Arg = "/qb" },
        @{ Year = "2008"; Arch = "x64"; Version="9.0.30729.6161"; Display="Microsoft Visual C++ 2008 Redistributable x64"; Url = "https://download.microsoft.com/download/5/D/8/5D8C65CB-C849-4025-8E95-C3966CAFD8AE/vcredist_x64.exe"; $Arg = "/qb" },
        @{ Year = "2010"; Arch = "x86"; Version="10.0.40219"; Display="Microsoft Visual C++ 2010 Redistributable (x86)"; Url = "https://download.microsoft.com/download/1/6/5/165255E7-1014-4D0A-B094-B6A430A6BFFC/vcredist_x86.exe"; $Arg = "/passive /norestart" },
        @{ Year = "2010"; Arch = "x64"; Version="10.0.40219"; Display="Microsoft Visual C++ 2010 Redistributable (x64)"; Url = "https://download.microsoft.com/download/1/6/5/165255E7-1014-4D0A-B094-B6A430A6BFFC/vcredist_x64.exe"; $Arg = "/passive /norestart" },
        @{ Year = "2012"; Arch = "x86"; Version="11.0.61030.0"; Display="Microsoft Visual C++ 2012 Redistributable (x86)"; Url = "https://download.microsoft.com/download/1/6/B/16B06F60-3B20-4FF2-B699-5E9B7962F9AE/VSU_4/vcredist_x86.exe"; $Arg = "/passive /norestart" },
        @{ Year = "2012"; Arch = "x64"; Version="11.0.61030.0"; Display="Microsoft Visual C++ 2012 Redistributable (x64)"; Url = "https://download.microsoft.com/download/1/6/B/16B06F60-3B20-4FF2-B699-5E9B7962F9AE/VSU_4/vcredist_x64.exe"; $Arg = "/passive /norestart" },
        @{ Year = "2013"; Arch = "x86"; Version="12.0.40664.0"; Display="Microsoft Visual C++ 2013 Redistributable (x86)"; Url = "https://aka.ms/highdpimfc2013x86enu"; $Arg = "/passive /norestart" },
        @{ Year = "2013"; Arch = "x64"; Version="12.0.40664.0"; Display="Microsoft Visual C++ 2013 Redistributable (x64)"; Url = "https://aka.ms/highdpimfc2013x64enu"; $Arg = "/passive /norestart" },
        @{ Year = "2015-2022"; Arch = "x86"; Version="14.44.35211.0"; Display="Microsoft Visual C++ 2015-2022 Redistributable (x86)"; Url = "https://aka.ms/vs/17/release/vc_redist.x86.exe"; $Arg = "/passive /norestart" },
        @{ Year = "2015-2022"; Arch = "x64"; Version="14.44.35211.0"; Display="Microsoft Visual C++ 2015-2022 Redistributable (x64)"; Url = "https://aka.ms/vs/17/release/vc_redist.x64.exe"; $Arg = "/passive /norestart" }
    )

    function Get-IsVCppUpToDate($displayName, $targetVersion) {
        $regPaths = @(
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
            "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
        )

        foreach ($path in $regPaths) {
            $regLocations = Get-ItemProperty -Path $path -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -like "*$displayName*" }

            foreach ($location in $regLocations) {
                if ($location.DisplayVersion -ge $targetVersion) {
                    return $true
                }
            }
        }
        return $false
    }

    function Install-VCppExecutable($Url, $Arguments, $Label) {
        try {
            $Temp = "$env:TEMP\$($Label.Replace(' ', '_')).exe"
            Invoke-WebRequest -Uri $Url -OutFile $Temp
            Start-Process -FilePath $Temp -ArgumentList $Arguments -Wait -Verb RunAs
            Remove-Item $Temp -Force
        } catch {
            Write-Warning "Failed to install $($Label): $_"
            $summary += "Failed to install $($Label): $_"
        }
    }

    Write-Host "`n--- Checking Visual C++ Runtimes ---"
    foreach ($vc in $vcRuntimes) {
        $locale = "Visual C++ Runtime Redistributable $($vc.Year) $($vc.Arch)"
        $mini = "VC++ $($vc.Year) $($vc.Arch)"
        Write-Host "Checking $locale ($($vc.Version))..."
        if ( Get-IsVCppUpToDate -displayName $($vc.Display) -targetVersion $($vc.Version) ) {
            Write-Host "$locale is up to date."
            $summary += "$locale is already up to date"
        } else {
            Write-Host "$locale is missing or outdated. Installing..."
            Install-VCppExecutable -Url $vc.Url -Arguments $($vc.Arguments) -Label "$($mini)"
            $summary += "$locale installed"
        }
    }
}
function Invoke-NetworkHardening {
    Write-Host "`n--- Applying network hardening settings ---"
    New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" -Name "NetworkThrottlingIndex" -PropertyType "DWORD" -Value 0xFFFFFFFF -Force
    Disable-NetAdapterRsc -Name "*"
    Enable-NetAdapterRss -Name "*"
    Get-NetAdapterAdvancedProperty -Name "*" | Where-Object DisplayName -Match 'Large Send Offload' | ForEach-Object { Set-NetAdapterAdvancedProperty -Name $_.Name -DisplayName $_.DisplayName -DisplayValue "Disabled" }
    Set-NetOffloadGlobalSetting -Chimney Disabled
    Disable-NetAdapterLso -Name *
    Set-NetTCPSetting -SettingName "Internet" -MaxSynRetransmissions 2
    netsh int tcp set supplemental Template=Internet CongestionProvider=bbr2
    $summary += "Network hardening complete"
}
function Invoke-NetworkOptimizations {
    Write-Host "`n--- Applying network optimizations ---"
    $baseKey = 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces'

    # Get all subkeys under Interfaces
    Get-ChildItem -Path $baseKey | ForEach-Object {
        $interfaceKey = $_.PSPath

        try {
            Set-ItemProperty -Path $interfaceKey -Name 'TcpAckFrequency' -Value 1 -Type DWord -EA SilentlyContinue
            Set-ItemProperty -Path $interfaceKey -Name 'TCPNoDelay' -Value 1 -Type DWord -EA SilentlyContinue
            Write-Host "Updated $interfaceKey with TcpAckFrequency and TCPNoDelay = 1" -ForegroundColor Green
        } catch {
            Write-Warning "Failed to update $($interfaceKey): $_"
        }
    }

    # Disable NetBIOS over TCP/IP
    Get-WmiObject -Class Win32_NetworkAdapterConfiguration | Where-Object { $_.IPEnabled } | ForEach-Object { $_.SetTcpipNetBIOS(0) }
    $summary += "Network optimizations applied"
}
function Invoke-USBSelectiveSuspend {
    Write-Host "`n--- Setting USB Selective Suspend ---"
    param ([bool]$Enabled = $false)
    if ($Enabled) {
        $val = 1
        $state = "Enabled"
    } else {
        $val = 0
        $state = "Disabled"
    }
    powercfg.exe /setacvalueindex SCHEME_CURRENT 2a737441-1930-4402-8d77-b2bebba308a3 48e6b7a6-50f5-4782-a5d4-53bb8f07e226 $val
    powercfg.exe /setdcvalueindex SCHEME_CURRENT 2a737441-1930-4402-8d77-b2bebba308a3 48e6b7a6-50f5-4782-a5d4-53bb8f07e226 $val
    powercfg.exe /setactive SCHEME_CURRENT
    $summary += "USB Selective Suspend set to $state"
}
function Invoke-WinUtilExplorerUpdate {
    Write-Host "`n--- Refreshing Dektop & Environment ---"
    [NativeMethods]::SendMessage($HWND_BROADCAST, $WM_SETTINGCHANGE, [IntPtr]::Zero, [IntPtr]::Zero)
    #$code = '[System.Runtime.InteropServices.Marshal]::WriteInt32([System.IntPtr]::Zero, 0)'
    #Invoke-Expression $code  # Placeholder for broadcast refresh; use SendMessageTimeout if needed
    $summary += "Dektop & Environment refreshed"
}
function Invoke-PowerPlan {
    Write-Host "`n--- Setting optimal power plan ---"
    $type = Get-ChassisType
    Write-Host "Detected chassis type: $type"
    if ($type -contains "laptop") {
        $plan = 'Balanced'
    } else {
        $plan = 'High Performance'
    }

    switch ($plan) {
        'Balanced' { powercfg.exe /setactive "381b4222-f694-41f0-9685-ff5bb260df2e" }
        'High Performance' { powercfg.exe /setactive "8c5e7fda-e8bf-4a96-b3b9-1d6c3d6f4b1a" }
    }
    $summary += "Power plan set to '$plan'"
}
function Get-ChassisType {
    # Returns "laptop" or "desktop"
    # Used to determine optimal power plan for the system
    $chassis = Get-WmiObject -Class win32_systemenclosure | Select-Object chassistypes
    Switch ($chassis) {
        8       {return "laptop"; break}
        9       {return "laptop"; break}
        10      {return "laptop"; break}
        11      {return "laptop"; break}
        14      {return "laptop"; break}
        30      {return "laptop"; break}
        31      {return "laptop"; break}
        32      {return "laptop"; break}
        36      {return "laptop"; break}
        default {return "desktop"; break}
    }
}
#endregion

#-----------------------------------------------------------[Execution]------------------------------------------------------------
Clear-Host
# --- Start Logging ---
Invoke-LogStatus -Log $summaryLogPath
Start-Transcript -Path $transcriptLogPath -Append
Write-Host "Processing started: $start" -ForegroundColor Yellow

# Execute all registry tweaks and optimizations
#region Memory Optimizations
Write-Host "`n--- Applying memory optimizations ---"
if (-not $WhatIf) {
    Invoke-RegistryChange -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" -Name "EnableBoottrace" -NewValue 0 -Type "DWord"
    Invoke-RegistryChange -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" -Name "EnablePrefetcher" -NewValue 0 -Type "DWord"
    Invoke-RegistryChange -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" -Name "EnableSuperfetch" -NewValue 0 -Type "DWord"
    Invoke-RegistryChange -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "ClearPageFileAtShutdown" -NewValue 0 -Type "DWord"
    Invoke-RegistryChange -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "DisablePagingExecutive" -NewValue 1 -Type "DWord"
    Invoke-RegistryChange -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "LargeSystemCache" -NewValue 1 -Type "DWord"
}
#endregion

#region Visual Performance
Write-Host "`n--- Applying visual performance optimizations ---"
if (-not $WhatIf) {
    Invoke-RegistryChange -Path "HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" -Name "TdrDdiDelay" -NewValue 10 -Type "DWord"
    Invoke-RegistryChange -Path "HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" -Name "TdrDelay" -NewValue 10 -Type "DWord"
    Invoke-RegistryChange -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" -Name "VisualFXSetting" -NewValue 3 -Type "DWord"
    Invoke-RegistryChange -Path "HKCU:\Control Panel\Desktop\WindowMetrics" -Name "MinAnimate" -NewValue 0 -Type "DWord"
    Invoke-RegistryChange -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ListviewAlphaSelect" -NewValue 0 -Type "DWord"
    Invoke-RegistryChange -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ListviewShadow" -NewValue 1 -Type "DWord"
    Invoke-RegistryChange -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarAnimations" -NewValue 0 -Type "DWord"
    Invoke-RegistryChange -Path "HKCU:\Control Panel\Desktop" -Name "MenuShowDelay" -NewValue 20
}
#endregion

#region Network Optimizations
Write-Host "`n--- Applying network optimizations ---"
if (-not $WhatIf) {
    Invoke-RegistryChange -Path "HKLM:\System\CurrentControlSet\Services\Tcpip\Parameters" -Name "DefaultTTL" -NewValue 64 -Type "DWord"
    Invoke-RegistryChange -Path "HKLM:\System\CurrentControlSet\Services\Tcpip\Parameters" -Name "MaxUserPort" -NewValue 65534 -Type "DWord"
    Invoke-RegistryChange -Path "HKLM:\System\CurrentControlSet\Services\Tcpip\Parameters" -Name "TcpTimedWaitDelay" -NewValue 30 -Type "DWord"
    Invoke-RegistryChange -Path "HKLM:\Software\Policies\Microsoft\Windows\Psched" -Name "NonBestEffortLimit" -NewValue 0 -Type "DWord"
    Invoke-RegistryChange -Path "HKLM:\System\CurrentControlSet\Services\LanmanServer\Parameters" -Name "Size" -NewValue 3 -Type "DWord"
    Invoke-RegistryChange -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" -Name "NetworkThrottlingIndex" -NewValue 4294967295 -Type "DWord"
    Invoke-RegistryChange -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" -Name "SystemResponsiveness" -NewValue 10 -Type "DWord"
    Invoke-RegistryChange -Path "HKLM:\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MAXCONNECTIONSPER1_0SERVER" -Name "explorer.exe" -NewValue 10 -Type "DWord"
    Invoke-RegistryChange -Path "HKLM:\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MAXCONNECTIONSPERSERVER" -Name "explorer.exe" -NewValue 10 -Type "DWord"
}
#endregion

#region Windows Update Tweaks
Write-Host "`n--- Applying Windows Update optimizations ---"
if (-not $WhatIf) {
    Invoke-RegistryChange -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "DisableDualScan" -NewValue 0 -Type "DWord"
    Invoke-RegistryChange -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "AllowMUUpdateService" -NewValue 1 -Type "DWord"
    Invoke-RegistryChange -Path "HKLM:\SOFTWARE\Microsoft\.NET" -Name "BlockMU" 0
}
#endregion

#region Security Settings
Write-Host "`n--- Applying security settings ---"
if (-not $WhatIf) {
    Invoke-RegistryChange -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "FeatureSettingsOverride" -NewValue 72 -Type "DWord"
    Invoke-RegistryChange -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "FeatureSettingsOverrideMask" -NewValue 3 -Type "DWord"
    Invoke-RegistryChange -Path "HKCU:\Software\Policies\Microsoft\Windows\WindowsCopilot" -Name "TurnOffWindowsCopilot" -NewValue 1 -Type "DWord"
}
#endregion

#region Misc Performance
Write-Host "`n--- Applying miscellaneous performance tweaks ---"
if (-not $WhatIf) {
Invoke-RegistryChange -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Serialize" -Name "StartupDelayInMSec" -NewValue 0 -Type "DWord"
    Invoke-RegistryChange -Path "HKCU:\SOFTWARE\Microsoft\Personalization\Settings" -Name "AcceptedPrivacyPolicy" -NewValue 0 -Type "DWord"
    Invoke-RegistryChange -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization" -Name "RestrictImplicitTextCollection" -NewValue 1 -Type "DWord"
    Invoke-RegistryChange -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization" -Name "RestrictImplicitInkCollection" -NewValue 1 -Type "DWord"
    Invoke-RegistryChange -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore" -Name "HarvestContacts" -NewValue 0 -Type "DWord"
}
#endregion

#region Personalization
Write-Host "`n--- Applying personalization settings ---"
if (-not $WhatIf) {
    Invoke-RegistryChange -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes" -Name "Personalize" -NewValue 0 -Type "DWord"
    Invoke-RegistryChange -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarGlomLevel" -NewValue 1 -Type "DWord"
    Invoke-RegistryChange -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarAnimations" -NewValue 0 -Type "DWord"
    Invoke-RegistryChange -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "NoThemesTab" -NewValue 0 -Type "DWord"
    Invoke-RegistryChange -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "NoSaveSettings" -NewValue 0 -Type "DWord"
}
#endregion

#region Disable Telemetry
Write-Host "`n--- Disabling telemetry and data collection ---"
if (-not $WhatIf) {
    Invoke-RegistryChange -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "AllowTelemetry" -NewValue 0 -Type "DWord"
    Invoke-RegistryChange -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "AllowCortana" -NewValue 0 -Type "DWord"
    Invoke-RegistryChange -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "AllowCloudOptimizedContent" -NewValue 0 -Type "DWord"
    Invoke-RegistryChange -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "AllowDeviceTelemetry" -NewValue 0 -Type "DWord"
    Invoke-RegistryChange -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "AllowTelemetryForApps" -NewValue 0 -Type "DWord"
}
#endregion

#region Disable Office Telemetry
Write-Host "`n--- Disabling Office telemetry and data collection ---"
if (-not $WhatIf) {
    Invoke-RegistryChange -Path "HKCU:\Software\Policies\Microsoft\Office\16.0\osm]" -Name "Enablelogging" -NewValue 0 -Type "DWord"
    Invoke-RegistryChange -Path "HKCU:\Software\Policies\Microsoft\Office\16.0\osm]" -Name "EnableUpload" -NewValue 0 -Type "DWord"
    Invoke-RegistryChange -Path "HKCU:\Software\Microsoft\Office\Common\ClientTelemetry" -Name "DisableTelemetry" -NewValue 1 -Type "DWord"
}
#endregion

#region Explorer Settings
Write-Host "`n--- Applying Explorer settings ---"
if (-not $WhatIf) {
    Invoke-RegistryChange -Path "HKCU:\Software\Policies\Microsoft\Windows\Explorer" -Name "NoUseStoreOpenWith" -NewValue 1 -Type "DWord"
    Invoke-RegistryChange -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "NoUseStoreOpenWith" -NewValue 1 -Type "DWord"
    Invoke-RegistryChange -Path "HKCU:\Software\Policies\Microsoft\Windows\Explorer" -Name "StartupDelayinMSec" -NewValue 1 -Type "DWord"
    Invoke-RegistryChange -Path "HKCU:\Software\Policies\Microsoft\Windows\Explorer" -Name "WaitForIdleState " -NewValue 0 -Type "DWord"
    Invoke-RegistryChange -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowSuperHidden" -NewValue 0 -Type "DWord"
    Invoke-RegistryChange -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Hidden" -NewValue 1 -Type "DWord"
    Invoke-RegistryChange -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideFileExt" -NewValue 0 -Type "DWord"
    Invoke-RegistryChange -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "NavPaneShowAllFolders" -NewValue 0 -Type "DWord"
}
#endregion

#region Miscellaneous Tweaks
Write-Host "`n--- Applying miscellaneous performance tweaks ---"
if (-not $WhatIf) {
    Invoke-RegistryChange -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" -Name "GPU Priority" -NewValue 8 -Type "DWord"
    Invoke-RegistryChange -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" -Name "Priority " -NewValue 6 -Type "DWord"
    Invoke-RegistryChange -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" -Name "Scheduling Category" -NewValue "High" -Type "String"
    Invoke-RegistryChange -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" -Name "SFIO Priority" -NewValue "High" -Type "String"
}
#endregion

#region Subroutines
Invoke-NonCriticalServicesDisablement
Invoke-AppCleanup
Invoke-AppReinstallBlock
Invoke-AppUnpinning
Invoke-TelemetryDisabling
Invoke-VisualCRuntimesCheck
Invoke-NetworkHardening
Invoke-NetworkOptimizations
Invoke-USBSelectiveSuspend -Enabled $true
Invoke-WinUtilExplorerUpdate
Invoke-PowerPlan
#endregion

# Save changes to the change log
$changeMap | ConvertTo-Json -Depth 5 | Set-Content -Path $changeLogPath

if ($WhatIf) { Write-Host "Dry run mode: no changes applied." }

# --- End Processing ---
$end = $([DateTime]::Now)
Write-Host "Processing ended: $end`n" -ForegroundColor Yellow

# --- Write Summary Report ---
$summaryHeader = @(
    "============================================",
    "OS Optimization Summary",
    "Process Started: $start",
    "============================================"
)
$summaryEnding = @(
    "============================================",
    "Process Ended: $end",
    "Total Duration: $((New-TimeSpan -Start $start -End $end).TotalMinutes) minutes",
    "============================================"
)
$summaryHeader + $summary + $summaryEnding | Set-Content -Path $summaryLogPath -Encoding UTF8

# --- End Logging ---
Stop-Transcript

if ($Summarize) {
    # --- Display Summary ---
    Clear-Host
    Write-Host "=== OS Optimization Summary Report ===" -ForegroundColor Magenta
    Write-Host "======================================" -ForegroundColor Yellow
    Get-Content -Path $summaryLogPath | ForEach-Object { Write-Host $_ -ForegroundColor Cyan }
    Write-Host "======================================" -ForegroundColor Yellow
}
Write-Host "`nLogs saved to:`n--> JSON: $($changeLogPath)`n--> Summary: $($summaryLogPath)`n--> Transcript: $($transcriptLogPath)" -ForegroundColor Green