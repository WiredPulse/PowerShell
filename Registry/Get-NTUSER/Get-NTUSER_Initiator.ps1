<#
    .SYNOPSIS
        This script copies 'Get-NTUSER.ps1' and RawCopy.exe (https://github.com/jschicht/RawCopy) to remote systems and initiates a process call for 'Get-NTUSER.ps1' to save each user's NTUSER.dat on the
        the machine th script is ran from.


    .REQUIREMENTS
        - PowerShell v2
        - Elevated rights
        - C$ access
        - WMI access


    .USAGE
        1. Download RawCopy.exe (https://github.com/jschicht/RawCopy).
        2. Change the variables on line 20, 21, 22, and 23 in this script.
        3. Execute the script from an elevated shell.
#>


$computers = gc 'c:\users\blue\desktop\computers.txt'
$rawcopy = 'C:\users\blue\Desktop\Tools\RawCopy64.exe'
$script = 'C:\users\blue\Desktop\Tools\Get-NTUSER.ps1'
$runner = 'c:\get-NTUSER.ps1'

foreach($cpu in $computers)
    {
    Copy-Item $rawcopy \\$cpu\c$\.
    Copy-Item $script \\$cpu\c$\.
    $Action = [wmiclass] "\\$cpu\ROOT\CIMv2:Win32_Process"
    $Method = $Action.create("powershell.exe /c $runner ")
    write-host 'Process call initiated on'$cpu'...' -ForegroundColor cyan
    sleep 2
    }

# Allow time for the command to run
sleep 60

new-item c:\users\$env:USERNAME\desktop\Remote-NTUSER -ItemType directory | out-null

foreach($cpu in $computers)
    {
    copy-Item \\$cpu\c$\users\public\documents\*.dat c:\users\$env:USERNAME\desktop\Remote-NTUSER
    remove-item \\$cpu\c$\users\public\documents\*.dat
    remove-item \\$cpu\c$\rawcopy64.exe
    remove-item \\$cpu\c$\Get-NTUSER.ps1
    write-host 'Pulling hive back from'$cpu'...' -ForegroundColor green
    }
