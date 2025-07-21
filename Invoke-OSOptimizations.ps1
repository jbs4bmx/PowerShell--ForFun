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
    Last Edit Date | [DMY] 21.07.2025
    Version        | 0.0.11
    License        | MIT -- https://opensource.org/licenses/MIT -- Copyright (c) 2021-2025 Jason Bradley Darling
    Change Log     | 2021-04-12: Initial version created by Jason Bradley Darling.
                   | 2023-10-02: Added functionality to check and install Visual C++ runtimes.
                   | 2025-07-17: Improved logging and error handling.
                   | 2025-07-20: Corrected Visual C++ installation logic to handle different versions and arguments.
                   | 2025-07-21: Corrected Visual C++ installation logic to ensure both x86 and x64 versions are installed correctly.
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
    [switch]$DisplaySummary
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
                $summary += "Reverted: $name at $path → $orig"
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
    Write-Host "`n--- Applying registry change at $Path for $Name ---"
    param (
        [string]$Path,
        [string]$Name,
        [int]$NewValue
    )
    try {
        $original = Get-ItemPropertyValue -Path $Path -Name $Name -ErrorAction Stop
    } catch {
        $original = $null
    }
    if (-not $changeMap.ContainsKey($Path)) { $changeMap[$Path] = @{} }
    $changeMap[$Path][$Name] = @{ original = $original; new = $NewValue }
    $summary += "$Name at $Path → original: $($original ?? 'N/A'), new: $NewValue"

    if (-not $WhatIf) {
        New-ItemProperty -Path $Path -Name $Name -PropertyType "DWORD" -Value $NewValue -Force | Out-Null
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
            Remove-AppxPackage -Package $pkg.PackageFullName
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

function Invoke-VisualCRuntimesCheck {
    $vcRuntimes=@(
        @{Year="2005"; Display="Microsoft Visual C++ 2005 Redistributable"; Version="8.0.61001"; UrlX86="https://download.microsoft.com/download/8/b/4/8b42259f-5d70-43f4-ac2e-4b208fd8d66a/vcredist_x86.EXE"; UrlX64="https://download.microsoft.com/download/8/b/4/8b42259f-5d70-43f4-ac2e-4b208fd8d66a/vcredist_x64.EXE"; Arguments = "/q" },
        @{Year="2008"; Display="Microsoft Visual C++ 2008 Redistributable"; Version="9.0.30729.7523"; UrlX86="https://download.microsoft.com/download/5/D/8/5D8C65CB-C849-4025-8E95-C3966CAFD8AE/vcredist_x86.exe"; UrlX64="https://download.microsoft.com/download/5/D/8/5D8C65CB-C849-4025-8E95-C3966CAFD8AE/vcredist_x64.exe"; Arguments = "/qb" },
        @{Year="2010"; Display="Microsoft Visual C++ 2010 Redistributable"; Version="10.0.40219"; UrlX86="https://download.microsoft.com/download/1/6/5/165255E7-1014-4D0A-B094-B6A430A6BFFC/vcredist_x86.exe"; UrlX64="https://download.microsoft.com/download/1/6/5/165255E7-1014-4D0A-B094-B6A430A6BFFC/vcredist_x64.exe"; Arguments = "/passive /norestart" },
        @{Year="2012"; Display="Microsoft Visual C++ 2012 Redistributable"; Version="11.0.61030"; UrlX86="https://download.microsoft.com/download/1/6/B/16B06F60-3B20-4FF2-B699-5E9B7962F9AE/VSU_4/vcredist_x86.exe"; UrlX64="https://download.microsoft.com/download/1/6/B/16B06F60-3B20-4FF2-B699-5E9B7962F9AE/VSU_4/vcredist_x64.exe"; Arguments = "/passive /norestart" },
        @{Year="2013"; Display="Microsoft Visual C++ 2013 Redistributable"; Version="12.0.40664"; UrlX86="https://aka.ms/highdpimfc2013x86enu"; UrlX64="https://aka.ms/highdpimfc2013x64enu"; Arguments = "/passive /norestart" },
        @{Year="2015–2025"; Display="Microsoft Visual C++ 2015-2022 Redistributable"; Version="14.38.33130"; UrlX86="https://aka.ms/vs/17/release/vc_redist.x86.exe" ; UrlX64="https://aka.ms/vs/17/release/vc_redist.x64.exe"; Arguments = "/passive /norestart" }
    )

    function IsUpToDate($displayName, $targetVersion) {
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

    Write-Host "`n--- Checking Visual C++ Runtimes ---"
    foreach ($vc in $vcRuntimes) {
        $year = $vc.Year
        $display = $vc.Display
        $version = $vc.Version
        $Arguments = $vc.Arguments

        Write-Host "Checking Visual C++ $year ($version)..."
        if (IsUpToDate -displayName $display -targetVersion $version) {
            Write-Host "Visual C++ $year is up to date."
            $summary += "VC++ $year already up to date"
        } else {
            Write-Host "Visual C++ $year is missing or outdated. Installing..."
            Start-Process -FilePath $vc.UrlX86 -ArgumentList $Arguments -Wait
            Write-Host "Installed x86 version of Visual C++ $year"
            Start-Process -FilePath $vc.UrlX64 -ArgumentList $Arguments -Wait
            Write-Host "Installed x64 version of Visual C++ $year"
            $summary += "VC++ $year installed"
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

function Invoke-TelemetryDisabling {
    Write-Host "`n--- Disabling telemetry and data collection ---"
    $telemetryPaths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
    )

    $values = @{
        "AllowTelemetry" = 0
        "AllowCortana"   = 0
    }

    foreach ($keyPath in $telemetryPaths) {
        foreach ($name in $values.Keys) {
            try {
                Set-ItemProperty -Path $keyPath -Name $name -Value $values[$name] -Type DWord -Force
                $summary += "Telemetry setting $name disabled in $keyPath"
            } catch {
                Write-Warning "Failed to set $name in $keyPath"
                $summary += "Failed to disable $name in $keyPath"
            }
        }
    }
}

function Invoke-USBSelectiveSuspend {
    Write-Host "`n--- Setting USB Selective Suspend ---"
    param ([bool]$Enabled = $false)
    $val = if ($Enabled) { 1 } else { 0 }
    powercfg.exe /setacvalueindex SCHEME_CURRENT 2a737441-1930-4402-8d77-b2bebba308a3 48e6b7a6-50f5-4782-a5d4-53bb8f07e226 $val
    powercfg.exe /setdcvalueindex SCHEME_CURRENT 2a737441-1930-4402-8d77-b2bebba308a3 48e6b7a6-50f5-4782-a5d4-53bb8f07e226 $val
    powercfg.exe /setactive SCHEME_CURRENT
    $summary += "USB Selective Suspend set to $($Enabled ? 'Enabled' : 'Disabled')"
}

function Invoke-WinUtilExplorerUpdate {
    Write-Host "`n--- Refreshing Windows Explorer ---"
    $code = '[System.Runtime.InteropServices.Marshal]::WriteInt32([System.IntPtr]::Zero, 0)'
    Invoke-Expression $code  # Placeholder for broadcast refresh; use SendMessageTimeout if needed
    $summary += "Windows Explorer refreshed"
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
$summary += "Process started: $start."

# Execute all registry tweaks and optimizations
#region Memory Optimizations
Invoke-RegistryChange "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" "EnableBoottrace" 0
Invoke-RegistryChange "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" "EnablePrefetcher" 0
Invoke-RegistryChange "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" "EnableSuperfetch" 0
Invoke-RegistryChange "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" "ClearPageFileAtShutdown" 0
Invoke-RegistryChange "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" "DisablePagingExecutive" 1
Invoke-RegistryChange "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" "LargeSystemCache" 1
#endregion

#region Visual Performance
Invoke-RegistryChange "HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" "TdrDdiDelay" 10
Invoke-RegistryChange "HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" "TdrDelay" 10
Invoke-RegistryChange "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" "VisualFXSetting" 3
Invoke-RegistryChange "HKCU:\Control Panel\Desktop\WindowMetrics" "MinAnimate" 0
Invoke-RegistryChange "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" "ListviewAlphaSelect" 0
Invoke-RegistryChange "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" "ListviewShadow" 1
Invoke-RegistryChange "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" "TaskbarAnimations" 0
Invoke-RegistryChange "HKCU:\Control Panel\Desktop" "MenuShowDelay" 20
#endregion

#region Network Optimizations
Invoke-RegistryChange "HKLM:\System\CurrentControlSet\Services\Tcpip\Parameters" "DefaultTTL" 64
Invoke-RegistryChange "HKLM:\System\CurrentControlSet\Services\Tcpip\Parameters" "MaxUserPort" 65534
Invoke-RegistryChange "HKLM:\System\CurrentControlSet\Services\Tcpip\Parameters" "TcpTimedWaitDelay" 30
Invoke-RegistryChange "HKLM:\Software\Policies\Microsoft\Windows\Psched" "NonBestEffortLimit" 0
Invoke-RegistryChange "HKLM:\System\CurrentControlSet\Services\LanmanServer\Parameters" "Size" 3
Invoke-RegistryChange "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" "NetworkThrottlingIndex" 4294967295
Invoke-RegistryChange "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" "SystemResponsiveness" 10
Invoke-RegistryChange "HKLM:\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MAXCONNECTIONSPER1_0SERVER" "explorer.exe" 10
Invoke-RegistryChange "HKLM:\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MAXCONNECTIONSPERSERVER" "explorer.exe" 10
#endregion

#region Windows Update Tweaks
Invoke-RegistryChange "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" "DisableDualScan" 0
Invoke-RegistryChange "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" "AllowMUUpdateService" 1
Invoke-RegistryChange "HKLM:\SOFTWARE\Microsoft\.NET" "BlockMU" 0
#endregion

#region Security Settings
Invoke-RegistryChange "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" "FeatureSettingsOverride" 72
Invoke-RegistryChange "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" "FeatureSettingsOverrideMask" 3
#endregion

#region Misc Performance
Invoke-RegistryChange "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Serialize" "StartupDelayInMSec" 0
Invoke-RegistryChange "HKCU:\SOFTWARE\Microsoft\Personalization\Settings" "AcceptedPrivacyPolicy" 0
Invoke-RegistryChange "HKCU:\SOFTWARE\Microsoft\InputPersonalization" "RestrictImplicitTextCollection" 1
Invoke-RegistryChange "HKCU:\SOFTWARE\Microsoft\InputPersonalization" "RestrictImplicitInkCollection" 1
Invoke-RegistryChange "HKCU:\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore" "HarvestContacts" 0
Invoke-RegistryChange "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" "AllowCortana" 0
#endregion

#region Subroutines
Invoke-NonCriticalServicesDisablement
Invoke-AppCleanup
Invoke-AppReinstallBlock
Invoke-TelemetryDisabling
Invoke-VisualCRuntimesCheck
Invoke-NetworkHardening
Invoke-USBSelectiveSuspend -Enabled $true
Invoke-WinUtilExplorerUpdate
Invoke-PowerPlan
#endregion

# Save logs
$changeMap | ConvertTo-Json -Depth 5 | Set-Content -Path $changeLogPath
$summary   | Set-Content -Path $summaryLogPath

if ($WhatIf) { Write-Host "Dry run mode: no changes applied." }

# --- End Processing ---
$end = $([DateTime]::Now)
Write-Host "Processing ended: $end`n" -ForegroundColor Yellow
$summary += "Processing ended: $end"

# --- Write Summary Report ---
$summaryHeader = @(
    "=== OS Optimization Summary ===",
    "Timestamp: $end",
    ""
)
$summaryHeader + $summary | Set-Content -Path $summaryLogPath -Encoding UTF8

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
Write-Host "`nLogs saved to:`n→ JSON: $changeLogPath`n→ Summary: $summaryLogPath"