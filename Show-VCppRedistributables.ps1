# Target Redistributable Names
$targets = @(
    "Visual C++ 2005",
    "Visual C++ 2008",
    "Visual C++ 2010",
    "Visual C++ 2012",
    "Visual C++ 2013",
    "Visual C++ 2015",
    "Visual C++ 2017",
    "Visual C++ 2019",
    "Visual C++ 2022"
)

# Registry roots to scan
$regRoots = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
)

Write-Host "`n--- Visual C++ Redistributable Scan (Filtered) ---`n"

foreach ($regRoot in $regRoots) {
    $subKeys = Get-ChildItem -Path $regRoot -ErrorAction SilentlyContinue
    foreach ($subKey in $subKeys) {
        $props = Get-ItemProperty -Path $subKey.PSPath -ErrorAction SilentlyContinue
        if ($props.DisplayName -and $props.DisplayName -like "*Redistributable*") {
            foreach ($target in $targets) {
                if ($props.DisplayName -like "*$target*") {
                    Write-Host "Key: $($subKey.Name)"
                    Write-Host "DisplayName: $($props.DisplayName)"
                    Write-Host "DisplayVersion: $($props.DisplayVersion)"
                    Write-Host ""
                    break
                }
            }
        }
    }
}
