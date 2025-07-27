Get-AppxProvisionedPackage -Online |
    Select-Object DisplayName,PackageName |
    Out-File "$env:USERPROFILE\Downloads\ProvisionedAppsList.txt" -Encoding UTF8
Get-AppxPackage -AllUsers |
    Select-Object Name,PackageFullName |
    Out-File "$env:USERPROFILE\Downloads\InstalledAppsList.txt" -Encoding UTF8
