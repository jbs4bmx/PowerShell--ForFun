<#
.SYNOPSIS
  Windows Setup Script: Installs essential runtimes and downloads optional tools.

.DESCRIPTION
  - Installs Visual C++ Redistributables (2005–2022) x86/x64
  - Installs .NET Desktop Runtimes 8 & 9 and SDKs
  - Installs 7-Zip and Visual Studio Code (User Setup)
  - Enables .NET 3.5 Windows Feature
  - Optionally downloads tools like Gimp, VS Community, Steam, etc.
  - Logs all actions and tracks skipped steps
#>

# region ==== Configuration ====
$DownloadPath = "$env:USERPROFILE\Downloads"
$OptionalDownloads = @{
    Gimp               = $true
    Inkscape           = $true
    VSCommunity        = $true
    Steam              = $true
    ATLauncher         = $true
    Chrome             = $true
    VLC                = $true
    PowerShell7        = $true
    GitHubDesktop      = $true
}
# endregion

# region ==== Helper Functions ====
function Install-Executable {
    param ($Url, $Arguments, $Label)
    try {
        $Temp = "$env:TEMP\$($Label.Replace(' ', '_')).exe"
        Invoke-WebRequest -Uri $Url -OutFile $Temp
        Start-Process -FilePath $Temp -ArgumentList $Arguments -Wait -Verb RunAs
        Remove-Item $Temp -Force
        Write-Host "Installed $Label"
    } catch {
        Write-Warning "Failed to install ${Label}: $_"
    }
}

function Download-ToFolder {
    param ($Url, $Label)
    try {
        $FileName = Split-Path $Url -Leaf
        $Dest = Join-Path $DownloadPath $FileName
        Invoke-WebRequest -Uri $Url -OutFile $Dest
        Write-Host "Downloaded $Label to $Dest"
    } catch {
        Write-Warning "Failed to download ${Label}: $_"
    }
}
# endregion

# region ==== Install VC++ Redistributables ====
$VcRedists = @(
    @{ Year = "2005"; Arch = "x86"; Url = "https://download.microsoft.com/download/8/b/4/8b42259f-5d70-43f4-ac2e-4b208fd8d66a/vcredist_x86.EXE"; $Arg = "/q" },
    @{ Year = "2005"; Arch = "x64"; Url = "https://download.microsoft.com/download/8/b/4/8b42259f-5d70-43f4-ac2e-4b208fd8d66a/vcredist_x64.EXE"; $Arg = "/q" },
    @{ Year = "2008"; Arch = "x86"; Url = "https://download.microsoft.com/download/5/D/8/5D8C65CB-C849-4025-8E95-C3966CAFD8AE/vcredist_x86.exe"; $Arg = "/qb" },
    @{ Year = "2008"; Arch = "x64"; Url = "https://download.microsoft.com/download/5/D/8/5D8C65CB-C849-4025-8E95-C3966CAFD8AE/vcredist_x64.exe"; $Arg = "/qb" },
    @{ Year = "2010"; Arch = "x86"; Url = "https://download.microsoft.com/download/1/6/5/165255E7-1014-4D0A-B094-B6A430A6BFFC/vcredist_x86.exe"; $Arg = "/passive /norestart" },
    @{ Year = "2010"; Arch = "x64"; Url = "https://download.microsoft.com/download/1/6/5/165255E7-1014-4D0A-B094-B6A430A6BFFC/vcredist_x64.exe"; $Arg = "/passive /norestart" },
    @{ Year = "2012"; Arch = "x86"; Url = "https://download.microsoft.com/download/1/6/B/16B06F60-3B20-4FF2-B699-5E9B7962F9AE/VSU_4/vcredist_x86.exe"; $Arg = "/passive /norestart" },
    @{ Year = "2012"; Arch = "x64"; Url = "https://download.microsoft.com/download/1/6/B/16B06F60-3B20-4FF2-B699-5E9B7962F9AE/VSU_4/vcredist_x64.exe"; $Arg = "/passive /norestart" },
    @{ Year = "2013"; Arch = "x86"; Url = "https://aka.ms/highdpimfc2013x86enu"; $Arg = "/passive /norestart" },
    @{ Year = "2013"; Arch = "x64"; Url = "https://aka.ms/highdpimfc2013x64enu"; $Arg = "/passive /norestart" },
    @{ Year = "2015-2022"; Arch = "x86"; Url = "https://aka.ms/vs/17/release/vc_redist.x86.exe"; $Arg = "/passive /norestart" },
    @{ Year = "2015-2022"; Arch = "x64"; Url = "https://aka.ms/vs/17/release/vc_redist.x64.exe"; $Arg = "/passive /norestart" }
)
foreach ($item in $VcRedists) {
    Install-Executable -Url $item.Url -Arguments $($item.Arg) -Label "VC++ Runtime $($item.Year) $($item.Arch)"
}
# endregion

# region ==== Enable .NET 3.5 Feature ====
Write-Host "`nEnabling .NET 3.5..."
Enable-WindowsOptionalFeature -Online -FeatureName NetFx3 -All -NoRestart
# endregion

# region ==== Install .NET Runtimes & SDKs ====
$DotNetPackages = @(
    @{ Name = ".NET Desktop Runtime 8"; Url = "https://builds.dotnet.microsoft.com/dotnet/WindowsDesktop/8.0.18/windowsdesktop-runtime-8.0.18-win-x64.exe"; Arg = "/install /quiet /norestart" },
    @{ Name = ".NET Desktop Runtime 9"; Url = "https://builds.dotnet.microsoft.com/dotnet/WindowsDesktop/9.0.7/windowsdesktop-runtime-9.0.7-win-x64.exe"; Arg = "/install /quiet /norestart" },
    @{ Name = ".NET SDK 8"; Url = "https://builds.dotnet.microsoft.com/dotnet/Sdk/8.0.412/dotnet-sdk-8.0.412-win-x64.exe"; Arg = "/install /quiet /norestart" },
    @{ Name = ".NET SDK 9"; Url = "https://builds.dotnet.microsoft.com/dotnet/Sdk/9.0.303/dotnet-sdk-9.0.303-win-x64.exe"; Arg = "/install /quiet /norestart" }
)
foreach ($pkg in $DotNetPackages) {
    Install-Executable -Url $pkg.Url -Arguments $($pkg.Arg) -Label $($pkg.Name)
}
# endregion

# region ==== Install 7-Zip & VS Code ====
Install-Executable -Url "https://www.7-zip.org/a/7z2500-x64.exe" -Arguments "/s" -Label "7-Zip x64"
Install-Executable -Url "https://code.visualstudio.com/sha/download?build=stable&os=win32-x64-user" -Arguments "/VERYSILENT /MERGETASKS=!runcode" -Label "Visual Studio Code x64 (User Setup)"
# endregion

# region ==== Optional Software Downloads ====
$Downloads = @{
    Gimp           = "https://download.gimp.org/pub/gimp/v2.10/windows/gimp-2.10.34-setup.exe"
    Inkscape       = "https://media.inkscape.org/dl/resources/file/inkscape-1.3-x64.exe"
    VSCommunity    = "https://aka.ms/vs/17/release/vs_community.exe"
    Steam          = "https://cdn.cloudflare.steamstatic.com/client/installer/SteamSetup.exe"
    ATLauncher     = "https://www.atlauncher.com/download/ATLauncher.exe"
    Chrome         = "https://dl.google.com/chrome/install/ChromeSetup.exe"
    VLC            = "https://get.videolan.org/vlc/3.0.20/win64/vlc-3.0.20-win64.exe"
    PowerShell7    = "https://github.com/PowerShell/PowerShell/releases/latest/download/PowerShell-7.4.0-win-x64.msi"
    GitHubDesktop  = "https://central.github.com/deployments/desktop/desktop/latest/win32"
}

foreach ($key in $OptionalDownloads.Keys) {
    if ($OptionalDownloads[$key] -and $Downloads[$key]) {
        Download-ToFolder -Url $Downloads[$key] -Label $key
    } else {
        Write-Host "Skipped download for $key"
    }
}