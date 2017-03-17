<#
    .SYNOPSIS
        This script is a wrapper for WinPmem. With it, memory captures are created remotely and are then saved back on the local machine.


    .REQUIREMENTS
        - Winpmem 
        - PowerShell v2
        - Elevated rights
        - C$ access
        - WMI access


    .USAGE
        1. Change the variables on line 27 and 28.
        2. Execute the script from an elevated shell

#>

$date = date -Format yyyyMMddhhmm

$computers = Get-Content c:\users\blue\desktop\computers.txt
$computers = '192.168.60.201'
$winpmem = 'C:\Users\blue\Desktop\Tools\WinPmem.exe'
$winpmem2 = 'c:\winpmem.exe c:\mem.raw' 

foreach($cpu in $computers)
    {
    Copy-Item $winpmem \\$cpu\c$\.

    $Action = [wmiclass] "\\$cpu\ROOT\CIMv2:Win32_Process"

    $Method = $Action.create("powershell /c $winpmem2 ")

    write-host 'Process call initiated on'$cpu'...' -ForegroundColor cyan
    }

