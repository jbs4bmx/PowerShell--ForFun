# ============ Login ============
# Disable the lock screen, which appears just before the Windows 10 sign-in screen
Invoke-RegistryChange -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization" -Name "NoLockScreen" -NewValue 1 -Type "DWord"


# ============ Spyware ============
#Disable Cortana (Windows 10 Anniversary+)
Invoke-RegistryChange -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowCortana" -NewValue 0 -Type "DWord"
#Turn off Windows Co-Pilot & Recall scanning
Invoke-RegistryChange -Path "HKCU:\Software\Policies\Microsoft\Windows\WindowsCopilot" -Name "TurnOffWindowsCopilot" -NewValue 1 -Type "DWord"


# ============ Start menu ============
#Start menu speed - the default is 400
Invoke-RegistryChange -Path "HKCU:\Control Panel\Desktop" -Name "MenuShowDelay" -NewValue "50" -Type "String"


# ============ Taskbar ============
#No Glomming (keep every icon on the taskbar separate)
Invoke-RegistryChange -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "TaskbarGlomming" -NewValue 0 -Type "DWord"
#Glomming enabled
Invoke-RegistryChange -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "TaskbarGlomming" -NewValue 1 -Type "DWord"
#Always combine Taskbar icons + hide labels
Invoke-RegistryChange -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarGlomLevel" -NewValue 0 -Type "DWord"
#Combine icons when taskbar is full (default)
Invoke-RegistryChange -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarGlomLevel" -NewValue 1 -Type "DWord"
#Never combine Taskbar icons
Invoke-RegistryChange -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarGlomLevel" -NewValue 2 -Type "DWord"
#TaskBar left/right grouping by age (oldest first) (default).
Invoke-RegistryChange -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "TaskbarGroupSize" -NewValue 0 -Type "DWord"
#or group by size largest first
Invoke-RegistryChange -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "TaskbarGroupSize" -NewValue 1 -Type "DWord"
#or group all with 2 or more, or 3 or more:
Invoke-RegistryChange -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "TaskbarGroupSize" -NewValue 2 -Type "DWord"
Invoke-RegistryChange -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "TaskbarGroupSize" -NewValue 3 -Type "DWord"
#or prevent grouping altogether
Invoke-RegistryChange -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "NoTaskGrouping" -NewValue 1 -Type "DWord"
#Don't hide the log-off option from the Start Menu
#    (setting to 0 does not prevent users from using other methods to log off.)
Invoke-RegistryChange -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "StartMenuLogOff" -NewValue 1 -Type "DWord"
#Don't hide the Themes tab in Control Panel Personalisation
Invoke-RegistryChange -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "NoThemesTab" -NewValue 0 -Type "DWord"
# Remember my Explorer views
Invoke-RegistryChange -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "NoSaveSettings" -NewValue 0 -Type "DWord"


# ============ System Tray ============
# System Tray - Show all icons (The default for this can be set under HKLM)
Invoke-RegistryChange -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer" -Name "EnableAutoTray" -NewValue 0 -Type "DWord"
# or hide inactive icons
Invoke-RegistryChange -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer" -Name "EnableAutoTray" -NewValue 1 -Type "DWord"


# ============ Explorer / General ============
#Remove the 'OneDrive' Icon from Windows Explorer for the current user
Remove-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Desktop\NameSpace\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" -Force -ErrorAction SilentlyContinue
#Remove the OneDrive icon for all users, this no longer works if the key above is present.
Invoke-RegistryChange -Path "HKCR:\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" -Name "System.IsPinnedToNameSpaceTree" -NewValue 0 -Type "DWord"
Invoke-RegistryChange -Path "HKCR:\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" -Name "System.IsPinnedToNameSpaceTree" -NewValue 0 -Type "DWord"
#Don't tie new shortcuts to a specific PC
Invoke-RegistryChange -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "LinkResolveIgnoreLinkInfo" -NewValue 1 -Type "DWord"
#Don't use Windows NTFS link tracking to resolve existing shortcuts.
Invoke-RegistryChange -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoResolveTrack" -NewValue 1 -Type "DWord"
#Don't hide any local Drives
Invoke-RegistryChange -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDrives" -NewValue 0 -Type "DWord"
#Don't add "-Shortcut" text to the name of newly created shortcuts.
Invoke-RegistryChange -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "link" -NewValue "00,00,00,00" -Type "Binary"
#or Restore the default adding "-Shortcut" text to the name of newly created shortcuts.
Invoke-RegistryChange -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "link" -NewValue "1e,00,00,00" -Type "Binary"
#Show all folders in Explorer including Recycle Bin, Desktop, Control Panel
Invoke-RegistryChange -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "NavPaneShowAllFolders” -NewValue 1 -Type "DWord"
#or only show current folder path in Explorer
Invoke-RegistryChange -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "NavPaneShowAllFolders” -NewValue 0 -Type "DWord"
#Add Right Click "Open PowerShell window here" Context Menu
#    https://www.tenforums.com/tutorials/59686-open-command-window-here-administrator-add-windows-10-a.html
#Disable Telemetry in Microsoft Office.
Invoke-RegistryChange -Path "HKCU:\Software\Policies\Microsoft\Office\16.0\osm" -Name "Enablelogging" -NewValue 0 -Type "DWord"
Invoke-RegistryChange -Path "HKCU:\Software\Policies\Microsoft\Office\16.0\osm" -Name "EnableUpload" -NewValue 0 -Type "DWord"
Invoke-RegistryChange -Path "HKCU:\Software\Microsoft\Office\Common\ClientTelemetry" -Name "DisableTelemetry" -NewValue 1 -Type "DWord"


# ============ Explorer\Advanced ============
#Show hidden files and folders
Invoke-RegistryChange -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Hidden" -NewValue 1 -Type "DWord"
#or Don't show hidden files and folders:
Invoke-RegistryChange -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Hidden" -NewValue 2 -Type "DWord"
#Don't Hide file extensions
Invoke-RegistryChange -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideFileExt" -NewValue 0 -Type "DWord"
#Don't hide recently opened Programs from the Start menu /Start Run
Invoke-RegistryChange -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Start_TrackProgs" -NewValue 1 -Type "DWord"
#Don't hide recently opened Documents from the Start menu /Start Run
Invoke-RegistryChange -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Start_TrackDocs" -NewValue 1 -Type "DWord"
#Don't add a Games shortcut to the start menu
Invoke-RegistryChange -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Start_ShowMyGames" -NewValue 0 -Type "DWord"
#Don't slow down search by including all public folders
Invoke-RegistryChange -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Start_SearchFiles" -NewValue 1 -Type "DWord"
#Don't show notifications/adverts (OneDrive & new feature alerts) in Windows Explorer
Invoke-RegistryChange -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowSyncProviderNotifications" -NewValue 1 -Type "DWord"
#Don't change the upper/lower case of filenames
Invoke-RegistryChange -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "DontPrettyPath" -NewValue 0 -Type "DWord"
#Disable Bing in Windows 10/11 Start Menu and Search (Search only local files)
Invoke-RegistryChange -Path "HKCU:\Software\Policies\Microsoft\Windows\Explorer" -Name "DisableSearchBoxSuggestions" -NewValue 1 -Type "DWord"


# ============ Personalization ============
#Allow changing Windows Color
Invoke-RegistryChange -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "NoDispAppearancePage" -NewValue 0 -Type "DWord"
#Allow Color scheme changes
Invoke-RegistryChange -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "NoColorChoice" -NewValue 0 -Type "DWord"
#Allow changing the font size
Invoke-RegistryChange -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "NoSizeChoice" -NewValue 0 -Type "DWord"
#Change desktop background (any wallpaper will override this)
Invoke-RegistryChange -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "NoDispBackgroundPage" -NewValue 0 -Type "DWord"
#Allow changing the Screen Saver
Invoke-RegistryChange -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "NoDispScrSavPage" -NewValue 0 -Type "DWord"
#Allow changing the Display
Invoke-RegistryChange -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "NoDispCPL" -NewValue 0 -Type "DWord"
#Allow changing the Display Settings
Invoke-RegistryChange -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "NoDispSettingsPage" -NewValue 0 -Type "DWord"
#Allow changing the wallpaper
#    If a wallpaper value is set here (or via policy) it will override the users choice
#    in the control panel (HKCU\Control Panel\Desktop) so delete the key to allow changes:
Remove-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "Wallpaper" -Force -ErrorAction SilentlyContinue


# ============ Control Panel / Add-Remove Programs ============
#Don't hide any Control Panel applets see Q207750
Remove-Item -Path "HKCU:\Control Panel\don’t load" -Name "appwiz.cpl" -Force -ErrorAction SilentlyContinue
#These keys make sure you can install or uninstall programs:
Remove-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Programs" -Name "NoProgramsAndFeatures" -Force -ErrorAction SilentlyContinue
Remove-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Programs" -Name "NoProgramsCPL" -Force -ErrorAction SilentlyContinue
# or disallow access:
Invoke-RegistryChange -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Programs" -Name "NoProgramsAndFeatures" -NewValue 1 -Type "DWord"


# ============ Windows Update [HKLM] ============
# These affect all users [HKLM] and would typically be set via Group Policy
#Download and install
Invoke-RegistryChange -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" -Name "AUOptions" -NewValue 4 -Type "DWord"
#Download but don’t install
Invoke-RegistryChange -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" -Name "AUOptions" -NewValue 3 -Type "DWord"
#Check but don’t download
Invoke-RegistryChange -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" -Name "AUOptions" -NewValue 2 -Type "DWord"
#Don't check
Invoke-RegistryChange -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" -Name "AUOptions" -NewValue 1 -Type "DWord"
#Disable P2P uploads/downloads (Windows Update>Advanced>Choose how updates are delivered)
Invoke-RegistryChange -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" -Name "DODownloadMode" -NewValue 0 -Type "DWord"


# ============ Misc [HKLM] All users ============
#Set the Screen Saver grace period (this only works if a valid screensaver is set) an alternative is adjusting the power / hibernate settings for the display.
Invoke-RegistryChange -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "ScreenSaverGracePeriod" -NewValue "5" -Type "String"
#When opening files with an unknown extension, dont prompt to 'Look for an app in the Store'
Invoke-RegistryChange -Path "HKCU:\Software\Policies\Microsoft\Windows\Explorer" -Name "NoUseStoreOpenWith" -NewValue 1 -Type "DWord"
#this can also be set for all users
Invoke-RegistryChange -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "NoUseStoreOpenWith" -NewValue 1 -Type "DWord"
#Display verbose messages during login (Group policy, profile loading etc)
Invoke-RegistryChange -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "verbosestatus" -NewValue 1 -Type "DWord"