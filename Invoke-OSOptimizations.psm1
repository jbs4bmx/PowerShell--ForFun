function Invoke-OSOptimization {
    param (
        [switch]$WhatIf,
        [switch]$Summarize,
        [switch]$Revert
    )

    $basePath           = Join-Path $env:SystemDrive "QorvoSetup\SPE"
    $changeLogPath      = Join-Path $basePath "OptimizationChanges.json"
    $summaryLogPath     = Join-Path $basePath "OptimizationSummary.log"
    $changeMap          = @{}
    $summary            = @()

    if (!(Test-Path $basePath)) { New-Item -Path $basePath -ItemType Directory -Force | Out-Null }

    # === Reversion ===
    if ($Revert) {
        if (!(Test-Path $changeLogPath)) {
            Write-Warning "Change log not found: $changeLogPath"
            return
        }
        $revertData = Get-Content $changeLogPath | ConvertFrom-Json
        foreach ($path in $revertData.Keys) {
            foreach ($name in $revertData[$path].Keys) {
                $orig = $revertData[$path][$name].original
                if ($null -ne $orig) {
                    Set-ItemProperty -Path $path -Name $name -Value $orig -Force
                    Write-Host "Reverted $name at $path to $orig"
                    $summary += "Reverted: $name at $path → $orig"
                }
            }
        }
        $summary | Set-Content -Path $summaryLogPath
        Write-Host "`nReversion complete. Summary logged to:`n$summaryLogPath"
        return
    }

    # === Helper Function ===
    function Set-RegistryChange {
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

        if (-not $changeMap.ContainsKey($Path)) {
            $changeMap[$Path] = @{}
        }

        $changeMap[$Path][$Name] = @{ original = $original; new = $NewValue }
        $summary += "$Name at $Path → original: $($original ?? 'N/A'), new: $NewValue"

        if (-not $WhatIf) {
            New-ItemProperty -Path $Path -Name $Name -PropertyType "DWORD" -Value $NewValue -Force | Out-Null
        }
    }

    #region Memory Optimizations
    Set-RegistryChange "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" "EnableBoottrace" 0
    Set-RegistryChange "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" "EnablePrefetcher" 0
    Set-RegistryChange "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" "EnableSuperfetch" 0
    Set-RegistryChange "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" "ClearPageFileAtShutdown" 0
    Set-RegistryChange "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" "DisablePagingExecutive" 1
    Set-RegistryChange "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" "LargeSystemCache" 1
    #endregion

    #region Visual Performance
    Set-RegistryChange "HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" "TdrDdiDelay" 10
    Set-RegistryChange "HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" "TdrDelay" 10
    Set-RegistryChange "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" "VisualFXSetting" 3
    Set-RegistryChange "HKCU:\Control Panel\Desktop\WindowMetrics" "MinAnimate" 0
    Set-RegistryChange "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" "ListviewAlphaSelect" 0
    Set-RegistryChange "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" "ListviewShadow" 1
    Set-RegistryChange "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" "TaskbarAnimations" 0
    Set-RegistryChange "HKCU:\Control Panel\Desktop" "MenuShowDelay" 20
    #endregion

    #region Network Optimizations
    Set-RegistryChange "HKLM:\System\CurrentControlSet\Services\Tcpip\Parameters" "DefaultTTL" 64
    Set-RegistryChange "HKLM:\System\CurrentControlSet\Services\Tcpip\Parameters" "MaxUserPort" 65534
    Set-RegistryChange "HKLM:\System\CurrentControlSet\Services\Tcpip\Parameters" "TcpTimedWaitDelay" 30
    Set-RegistryChange "HKLM:\Software\Policies\Microsoft\Windows\Psched" "NonBestEffortLimit" 0
    Set-RegistryChange "HKLM:\System\CurrentControlSet\Services\LanmanServer\Parameters" "Size" 3
    Set-RegistryChange "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" "NetworkThrottlingIndex" 4294967295
    Set-RegistryChange "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" "SystemResponsiveness" 10
    Set-RegistryChange "HKLM:\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MAXCONNECTIONSPER1_0SERVER" "explorer.exe" 10
    Set-RegistryChange "HKLM:\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MAXCONNECTIONSPERSERVER" "explorer.exe" 10
    if (-not $WhatIf) {
        Disable-NetAdapterLso -Name *
        Set-NetTCPSetting -SettingName "Internet" -MaxSynRetransmissions 2
        netsh int tcp set supplemental Template=Internet CongestionProvider=bbr2
    }
    #endregion

    #region Windows Update Tweaks
    Set-RegistryChange "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" "DisableDualScan" 0
    Set-RegistryChange "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" "AllowMUUpdateService" 1
    Set-RegistryChange "HKLM:\SOFTWARE\Microsoft\.NET" "BlockMU" 0
    #endregion

    #region Security Settings
    Set-RegistryChange "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" "FeatureSettingsOverride" 72
    Set-RegistryChange "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" "FeatureSettingsOverrideMask" 3
    #endregion

    #region Misc Performance
    Set-RegistryChange "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Serialize" "StartupDelayInMSec" 0
    Set-RegistryChange "HKCU:\SOFTWARE\Microsoft\Personalization\Settings" "AcceptedPrivacyPolicy" 0
    Set-RegistryChange "HKCU:\SOFTWARE\Microsoft\InputPersonalization" "RestrictImplicitTextCollection" 1
    Set-RegistryChange "HKCU:\SOFTWARE\Microsoft\InputPersonalization" "RestrictImplicitInkCollection" 1
    Set-RegistryChange "HKCU:\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore" "HarvestContacts" 0
    Set-RegistryChange "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" "AllowCortana" 0
    #endregion

    # === Save Output Files ===
    $changeMap | ConvertTo-Json -Depth 5 | Set-Content -Path $changeLogPath
    $summary   | Set-Content -Path $summaryLogPath

    if ($Summarize) {
        Write-Host "`n=== Optimization Summary ==="
        $summary | ForEach-Object { Write-Host $_ }
    }

    Write-Host "`nOptimization log saved to:"
    Write-Host "→ JSON: $changeLogPath"
    Write-Host "→ Text: $summaryLogPath"

    if ($WhatIf) {
        Write-Host "`nDry run complete. No changes were applied."
    }
}
Export-ModuleMember -Function Invoke-OSOptimization
