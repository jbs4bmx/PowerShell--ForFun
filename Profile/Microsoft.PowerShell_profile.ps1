<#
.SYNOPSIS
    Microsoft.PowerShell_profile.ps1 - My PowerShell profile
.DESCRIPTION
    Microsoft.PowerShell_profile - Customizes the PowerShell console
.PARAMETER None
    No Parameters are necessary.
.INPUTS
    None
.OUTPUTS
    None
.NOTES
    File Name:      | Microsoft.PowerShell_profile.ps1
    Author:         | Jason B. Darling
    Date:           | 07/11/2019
    Version:        | 0.1
    Help Requests:  | Jason.Darling@qorvo.com
    Help File:      | N/A
    Key Note:       | Self-Elevating Script. See Help File for more information
    License:        | MIT -- https://opensource.org/licenses/MIT -- Copyright (c) 2019 JBS Solutions, LLC
.EXAMPLE
    None
#>

#------------------------------------------------------------[Elevation]-----------------------------------------------------------
# N/A

#---------------------------------------------------------[Initializations]--------------------------------------------------------
# Verify Correct Prompt Size is default
$RegKey = "HKCU:\Console"; Set-ItemProperty -Path "$RegKey" -Name "ForceV2" -Type DWord -Value "00000000"
# Set Prompt Size
$Shell=$Host.UI.RawUI
$size=$Shell.BufferSize
$size.width=120
$size.height=3000
$Shell.BufferSize=$size
$size=$Shell.WindowSize
$size.width=120
$size.height=32
$Shell.WindowSize=$size
# Set Prompt BG Color
$Shell.BackgroundColor="Black"
# Set Working Directory
Set-Location C:\work
# Create Aliases
Set-Alias editor "C:\Program Files\VSCodium\VSCodium.exe"
Set-Alias grep select-string

#----------------------------------------------------------[Declarations]----------------------------------------------------------
# N/A

#-----------------------------------------------------------[Functions]------------------------------------------------------------
function Get-Time { return $(Get-Date | ForEach {$_.ToLongTimeString()}) }
function prompt {
    Write-Host "[" -noNewLine
    Write-Host $(Get-Time) -ForegroundColor DarkYellow -noNewLine
    Write-Host "] " -noNewLine
    Write-Host $($(Get-Location).Path.replace($home,"~")) -ForegroundColor DarkGreen -noNewLine
    Write-Host $(if ($nestedpromptlevel -ge 1) { '>>' }) -noNewLine
    return "> "
}
function ll {
    param ($dir = ".", $all = $false)
    # colors allowed: Black, DarkBlue, DarkGreen, DarkCyan, DarkRed, DarkMagenta, DarkYellow, Gray, DarkGray, Blue, Green, Cyan, Red, Magenta, Yellow, White

    $origFg = $Host.UI.RawUI.ForegroundColor
    if ( $all ) { $toList = ls -force $dir }
    else { $toList = ls $dir }

    foreach ($Item in $toList)
    {
        Switch ($Item.Extension)
        {
            ".exe"  {$Host.UI.RawUI.ForegroundColor="Yellow"}
            ".hta"  {$Host.UI.RawUI.ForegroundColor="Yellow"}
            ".bat"  {$Host.UI.RawUI.ForegroundColor="DarkCyan"}
            ".cmd"  {$Host.UI.RawUI.ForegroundColor="DarkCyan"}
            ".ps1"  {$Host.UI.RawUI.ForegroundColor="Blue"}
            ".html" {$Host.UI.RawUI.ForegroundColor="Cyan"}
            ".htm"  {$Host.UI.RawUI.ForegroundColor="Cyan"}
            ".7z"   {$Host.UI.RawUI.ForegroundColor="Magenta"}
            ".zip"  {$Host.UI.RawUI.ForegroundColor="Magenta"}
            ".gz"   {$Host.UI.RawUI.ForegroundColor="Magenta"}
            ".rar"  {$Host.UI.RawUI.ForegroundColor="Magenta"}
            ".csv"  {$Host.UI.RawUI.ForegroundColor="DarkGreen"}
            ".xls"  {$Host.UI.RawUI.ForegroundColor="DarkGreen"}
            ".xlsx" {$Host.UI.RawUI.ForegroundColor="DarkGreen"}
            ".doc"  {$Host.UI.RawUI.ForegroundColor="DarkBlue"}
            ".docx" {$Host.UI.RawUI.ForegroundColor="DarkBlue"}
            ".pdf"  {$Host.UI.RawUI.ForegroundColor="DarkRed"}
            ".tmp"  {$Host.UI.RawUI.ForegroundColor="Red"}
            ".json" {$Host.UI.RawUI.ForegroundColor="DarkMagenta"}
            Default {$Host.UI.RawUI.ForegroundColor=$origFg}
        }
        if ($item.Mode.StartsWith("d")) {$Host.UI.RawUI.ForegroundColor="Gray"}
        $item
    }
    $Host.UI.RawUI.ForegroundColor = $origFg
}
function Edit-HostsFile {
    Start-Process -FilePath notepad -ArgumentList "$env:windir\system32\drivers\etc\hosts"
}
function rdp ($ip) {
    Start-Process -FilePath mstsc -ArgumentList "/admin /w:1024 /h:768 /v:$ip"
}
function tail ($file) {
    Get-Content $file -Wait
}
function whoami {
    [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
}
function Reload-Profile {
    @(
        $Profile.AllUsersAllHosts,
        $Profile.AllUsersCurrentHost,
        $Profile.CurrentUserAllHosts,
        $Profile.CurrentUserCurrentHost
    ) | % {
        if(Test-Path $_) {
            Write-Verbose "Running $_"
            . $_
        }
    }
}
function Check-SessionArch {
    if ([System.IntPtr]::Size -eq 8) { return "x64" }
    else { return "x86" }
}
function Test-Port {
    [cmdletbinding()]
    param(
    [parameter(mandatory=$true)]
    [string]$Target,
    [parameter(mandatory=$true)]
    [int32]$Port,
    [int32]$Timeout=2000
    )
    $outputobj=New-Object -TypeName PSobject
    $outputobj | Add-Member -MemberType NoteProperty -Name TargetHostName -Value $Target
    if(Test-Connection -ComputerName $Target -Count 2) {$outputobj | Add-Member -MemberType NoteProperty -Name TargetHostStatus -Value "ONLINE"}
    else
    {$outputobj | Add-Member -MemberType NoteProperty -Name TargetHostStatus -Value "OFFLINE"}
    $outputobj | Add-Member -MemberType NoteProperty -Name PortNumber -Value $Port
    $Socket=New-Object System.Net.Sockets.TCPClient
    $Connection=$Socket.BeginConnect($Target,$Port,$null,$null)
    $Connection.AsyncWaitHandle.WaitOne($timeout,$false) | Out-Null
    if($Socket.Connected -eq $true) {$outputobj | Add-Member -MemberType NoteProperty -Name ConnectionStatus -Value "Success"}
    else
    {$outputobj | Add-Member -MemberType NoteProperty -Name ConnectionStatus -Value "Failed"}
    $Socket.Close | Out-Null
    $outputobj | Select TargetHostName, TargetHostStatus, PortNumber, Connectionstatus | Format-Table -AutoSize
}

#-----------------------------------------------------------[Execution]------------------------------------------------------------
$MaximumHistoryCount=1024
$IPAddress=@(Get-WmiObject Win32_NetworkAdapterConfiguration | Where-Object {$_.DefaultIpGateway})[0].IPAddress[0]
$PSVersion=$host | Select-Object -ExpandProperty Version
$PSVersion=$PSVersion -replace '^.+@\s'
$SessionArch=Check-SessionArch
$Shell.WindowTitle="Code Ninja! ($SessionArch)"

Clear-Host
<#
Write-Host "`r`nsssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssss" -ForegroundColor Yellow
Write-Host "s" -ForegroundColor Yellow -nonewline; Write-Host "ssssssssss" -nonewline; Write-Host "`t`t`t`t`t`t`ts" -ForegroundColor Yellow
Write-Host "s" -ForegroundColor Yellow -nonewline; Write-Host "ss  ssssss`tHi Jace!" -nonewline; Write-Host "`t`t`t`t`ts" -ForegroundColor Yellow
Write-Host "s" -ForegroundColor Yellow -nonewline; Write-Host "sss  sssss" -nonewline; Write-Host "`t`t`t`t`t`t`ts" -ForegroundColor Yellow
Write-Host "s" -ForegroundColor Yellow -nonewline; Write-Host "ssss  ssss`tComputerName`t`t" -nonewline
Write-Host $($env:COMPUTERNAME) -nonewline; Write-Host "`t`ts" -ForegroundColor Yellow
Write-Host "s" -ForegroundColor Yellow -nonewline; Write-Host "ssss  ssss`tIP Address`t`t" -nonewline
Write-Host $IPAddress -nonewline; Write-Host "`t`ts" -ForegroundColor Yellow
Write-Host "s" -ForegroundColor Yellow -nonewline; Write-Host "sss  sssss`tUserName`t`t" -nonewline
Write-Host $env:UserDomain\$env:UserName -nonewline; Write-Host "`ts" -ForegroundColor Yellow
Write-Host "s" -ForegroundColor Yellow -nonewline; Write-Host "ss  s   ss`tPowerShell Version`t" -nonewline
Write-Host $PSVersion -nonewline; Write-Host "`t`ts" -ForegroundColor Yellow
Write-Host "s" -ForegroundColor Yellow -nonewline; Write-Host "ssssssssss`tPowerShell Session`t" -nonewline
Write-Host $SessionArch -nonewline; Write-Host "`t`t`ts" -ForegroundColor Yellow
Write-Host "s" -ForegroundColor Yellow -nonewline; Write-Host "ssssssssss" -nonewline; Write-Host "`t`t`t`t`t`t`ts" -ForegroundColor Yellow
Write-Host "sssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssss`n" -ForegroundColor Yellow
#>

Write-Host "`r`nsssssssssssssssssssssssssssssssssssssssssssssssssssssssss" -ForegroundColor Yellow
Write-Host "s" -ForegroundColor Yellow -nonewline; Write-Host "`tComputerName`t`t" -nonewline
Write-Host $($env:COMPUTERNAME) -nonewline; Write-Host "`t`ts" -ForegroundColor Yellow
Write-Host "s" -ForegroundColor Yellow -nonewline; Write-Host "`tIP Address`t`t" -nonewline
Write-Host $IPAddress -nonewline; Write-Host "`t`ts" -ForegroundColor Yellow
Write-Host "s" -ForegroundColor Yellow -nonewline; Write-Host "`tUserName`t`t" -nonewline
Write-Host $env:UserDomain\$env:UserName -nonewline; Write-Host "`t`ts" -ForegroundColor Yellow
Write-Host "s" -ForegroundColor Yellow -nonewline; Write-Host "`tPowerShell Version`t" -nonewline
Write-Host $PSVersion -nonewline; Write-Host "`t`ts" -ForegroundColor Yellow
Write-Host "sssssssssssssssssssssssssssssssssssssssssssssssssssssssss`n" -ForegroundColor Yellow

$LogicalDisk = @()
Get-WmiObject Win32_LogicalDisk -filter "DriveType='3'" | % {
    $LogicalDisk += @($_ | Select @{n="Name";e={$_.Caption}},
    @{n="Volume Label";e={$_.VolumeName}},
    @{n="Size (Gb)";e={"{0:N2}" -f ($_.Size/1GB)}},
    @{n="Used (Gb)";e={"{0:N2}" -f (($_.Size/1GB) - ($_.FreeSpace/1GB))}},
    @{n="Free (Gb)";e={"{0:N2}" -f ($_.FreeSpace/1GB)}},
    @{n="Free (%)";e={if($_.Size) {"{0:N2}" -f (($_.FreeSpace/1GB) / ($_.Size/1GB) * 100 )} else {"NAN"} }})
  }
$LogicalDisk | Format-Table -AutoSize | Out-String
Write-Host "   .-====-." -ForegroundColor Green
Write-Host "  /        \" -ForegroundColor Green
Write-Host " /_        _\" -ForegroundColor Green
Write-Host "// \      / \\" -ForegroundColor Green
Write-Host "|\__\    /__/|" -ForegroundColor Green
Write-Host " \    ||    /" -ForegroundColor Green
Write-Host "  \        /" -ForegroundColor Green
Write-Host "   \      /" -ForegroundColor Green
Write-Host "    '.__.'" -ForegroundColor Green
Write-Host "     |  |" -ForegroundColor Green
