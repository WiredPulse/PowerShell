<#
    .SYNOPSIS
        This script uses reg.exe (c:\windows\system32\reg.exe) to remotely save the SYSTEM, SOFTWARE, or SAM hive on machine this script is ran from. Once the hives are local
        they can be ran through RegRipper (or your favorite Registry parsing tool) to make it human-readable. 
        

    .REQUIREMENTS
        - PowerShell v2
        - Elevated rights
        - C$ access
        - WMI access


    .USAGE
        1. Change the variables on line 23, 34, and 35.
        2. Execute the script from an elevated shell.

#>

# ***** Change this ******
$computers = Get-Content c:\users\blue\desktop\computers.txt

# Don't touch
$system = 'reg save hklm\system c:\users\public\system.hiv'
$software = 'reg save hklm\software c:\users\public\software.hiv'
$sam = 'reg save hklm\sam c:\users\public\sam.hiv'
$hkcu = 'reg save hkcu\ c:\users\public\hkcu.hiv'
$sys = 'system.hiv'
$soft = 'software.hiv'
$sam2 = 'sam.hiv'
$hkcu2 = 'hkcu.hiv'

# ***** Change this ******
$syntax = $hkcu
$syntax2 = $hkcu2

foreach($cpu in $computers)
    {
    $Action = [wmiclass] "\\$cpu\ROOT\CIMv2:Win32_Process"
    $Method = $Action.create("powershell /c $syntax ")

    write-host 'Process call initiated on'$cpu'...' -ForegroundColor cyan
    }

# Allow time for the command to run
sleep 20

new-item c:\users\$env:USERNAME\desktop\Remote_Hives -ItemType directory | out-null
$mft_record = '$mft'

foreach($cpu in $computers)
    {
    rename-item \\$cpu\c$\users\public\$syntax2 \\$cpu\c$\users\public\$cpu-$syntax2
    copy-Item \\$cpu\c$\users\public\$cpu-$syntax2 c:\users\$env:USERNAME\desktop\Remote_Hives

    remove-item \\$cpu\c$\users\public\$cpu-$syntax2

    write-host 'Pulling hive back from'$cpu'...' -ForegroundColor green
    }
