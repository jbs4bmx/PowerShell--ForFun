# System Information
A collection of scripts for gathering system information.








### NOTES:
```PowerShell
# Pull from a list.
Get-CimInstance -Class CIM_PhysicalMemory -ComputerName (Get-Content -Path C:\Temp\servers.txt) -EA SilentlyContinue | Select-Object * | Out-GridView
# Process localhost.
Get-CimInstance -Class CIM_PhysicalMemory -EA SilentlyContinue | Select-Object * | Out-GridView
# Process on remote system (different methods).
Get-CimInstance -Class CIM_PhysicalMemory -ComputerName $pc -EA SilentlyContinue | Select-Object *

Get-CimInstance -Class CIM_PhysicalMemory -ComputerName $pc -EA SilentlyContinue | Select-Object * | Format-Table
```

```PowerShell
# Cleanest output method.
Get-CimInstance -Class CIM_PhysicalMemory -ComputerName $pc -EA SilentlyContinue | Select-Object PSComputerName,DeviceLocator,Speed,Capacity,Manufacturer,Tag,PartNumber, SerialNumber | Format-Table
# -Or
Get-CimInstance -Class CIM_PhysicalMemory -ComputerName $pc -EA SilentlyContinue | Select-Object PSComputerName,DeviceLocator,Speed,Capacity,Manufacturer,Tag,PartNumber, SerialNumber | Out-GridView
```

```PowerShell
# Wrapped in a foreach for processing multiple computers.
# Write to external file.
$computers = Get-Content $computerList
foreach ($comp in $computers) {
    $pc = $comp
    Get-CimInstance -Class CIM_PhysicalMemory -ComputerName $pc -EA SilentlyContinue | Select-Object PSComputerName,DeviceLocator,Speed,Capacity,Manufacturer,Tag,PartNumber,SerialNumber | Format-Table | Out-File $output -Append
    Add-Content -FilePath $output -Value " "
}
```
