# Detect system UI language
$culture = [System.Globalization.CultureInfo]::CurrentUICulture.Name
Write-Host "Detected UI culture: $culture"
$targets = @(
    "Clipchamp.Clipchamp",
    "Microsoft.BingNews",
    "Microsoft.BingWeather",
    "Microsoft.Edge.GameAssist",
    "Microsoft.GamingApp",
    "Microsoft.GetHelp",
    "Microsoft.Getstarted",
    "Microsoft.MicrosoftOfficeHub",
    "Microsoft.MicrosoftSolitaireCollection",
    "Microsoft.MicrosoftStickyNotes",
    "Microsoft.OutlookForWindows",
    "Microsoft.People",
    "Microsoft.PowerAutomateDesktop",
    "Microsoft.ScreenSketch",
    "Microsoft.Todos",
    "Microsoft.Windows.DevHome",
    "Microsoft.WindowsAlarms",
    "Microsoft.WindowsCamera",
    "Microsoft.WindowsFeedbackHub",
    "Microsoft.WindowsMaps",
    "Microsoft.WindowsSoundRecorder",
    "Microsoft.Xbox.TCUI",
    "Microsoft.XboxGameOverlay",
    "Microsoft.XboxGamingOverlay",
    "Microsoft.XboxIdentityProvider",
    "Microsoft.XboxSpeechToTextOverlay",
    "Microsoft.YourPhone",
    "Microsoft.ZuneMusic",
    "Microsoft.ZuneVideo",
    "Candy",
    "eBay",
    "Facebook",
    "FeedbackHub",
    "Netflix",
    "Roblox",
    "Skype",
    "Spotify",
    "TikTok",
    "Twitter",
    "Weather",
    "Xbox",
    "YouTube"
)

# Verb Resource ID Mapping (based on observed behavior)
# 51394 - "Unpin from Start" (primary)
# 5382  - "Unpin from Start" (fallback or variant)
# 5387  - "Unpin from Taskbar"

# Optionally add localized GetString support
$getstring = @"
using System;
using System.Runtime.InteropServices;
public class GetStr {
    [DllImport("user32.dll", CharSet=CharSet.Unicode)]
    public static extern int LoadString(IntPtr hInstance, int uID, System.Text.StringBuilder lpBuffer, int nBufferMax);

    public static string GetString(int uID) {
        var buffer = new System.Text.StringBuilder(256);
        LoadString(IntPtr.Zero, uID, buffer, buffer.Capacity);
        return buffer.ToString();
    }
}
"@

try {
    $GetStr = Add-Type -TypeDefinition $getstring -PassThru
} catch {
    Write-Warning "Failed to compile GetString class. Falling back to static strings only."
    $GetStr = $null
}

# Retrieve verb strings (localized and fallback)
$verbSet = @()

if ($GetStr) {
    try {
        $verbSet += $GetStr[0]::GetString(51394) # "Unpin from Start"
        $verbSet += $GetStr[0]::GetString(5382) # "Unpin from Start"
        $verbSet += $GetStr[0]::GetString(5387)  # "Unpin from taskbar"
        Write-Host "Loaded localized verbs: $($verbSet -join ', ')"
    } catch {
        Write-Warning "Localized verb resolution failed. Using fallback verbs."
    }
}

# Add fallback English strings
$verbSet += 'Unpin from Start', 'Unpin from taskbar'

function Remove-ProvisionedPlaceholders {
    param (
        [Parameter(Mandatory)]
        [string[]]$AppNames
    )
    $provisioned = Get-AppxProvisionedPackage -Online
    $matched = @()
    $unmatched = @()

    foreach ($app in $AppNames) {
        $found = $provisioned | Where-Object { $_.DisplayName -like "*$app*" }
        if ($found) {
            $matched += $found
        } else {
            $unmatched += $app
        }
    }

    foreach ($pkg in $matched | Sort-Object DisplayName -Unique) {
        Write-Host "Removing provisioned package: $($pkg.DisplayName)" -ForegroundColor Green
        try {
            Remove-AppxProvisionedPackage -Online -PackageName $pkg.PackageName
        } catch {
            Write-Warning "Failed to remove '$($pkg.DisplayName)': $_"
        }
    }

    foreach ($app in $unmatched) {
        Get-AppxPackage -AllUsers -Name "*$app*" | Remove-AppxPackage -AllUsers
    }
}

Remove-ProvisionedPlaceholders -AppNames $targets


$shellApp = New-Object -ComObject Shell.Application
$appsFolder = $shellApp.Namespace('shell:::{4234d49b-0245-4df3-b780-3893943456e1}')
# Unpin matched items
$appsFolder.Items() | ForEach-Object {
    $name = $_.Name
    $verbs = $_.Verbs() | ForEach-Object { $_.Name.Replace('&','').Trim() }
    $match = $verbs | Where-Object { $_ -in $verbSet }
    if ($match) {
        foreach ($m in $match) {
            Write-Host "Unpinning '$name' using verb '$m'"
            $_.Verbs() | Where-Object { $_.Name.Replace('&','').Trim() -eq $m } | ForEach-Object { $_.DoIt() }
        }
    } else {
        Write-Host "No matching verb found for '$name'. Skipping."
    }
}
