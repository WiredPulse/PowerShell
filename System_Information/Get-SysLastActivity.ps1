<#
    .SYNOPSIS
        This script is a wrapper to remotely execute UserAssistView.exe (http://www.nirsoft.net/utils/userassist_view.html) across multiple systems and returns the 
        data to the local machine in a csv. The results are consolidated on the local machine and are best read in using 'out-gridview'.

        UserAssistView.exe decrypts and displays the list of all UserAssist entries stored under HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer
        \UserAssist key. The UserAssist key contains information about the exe files and links that you open frequently. The program will only get this data from the user currently logged in. In you want to parse this data for other users on the system, get the 
        NTUSER.dat file and user RegRipper against it. 


    .REQUIREMENTS
        - LastActivityView.exe (http://www.nirsoft.net/utils/userassist_view.html)
        - PowerShell v2
        - Elevated rights
        - C$ access
        - WMI access


    .USAGE
        1. Download LastActivityView.exe (http://www.nirsoft.net/utils/userassist_view.html)
        2. Change the variables on line 27 and 28.
        3. Execute the script from an elevated shell

#>


$computers = Get-Content c:\users\blue\desktop\computers.txt
$UserAssist_copy = 'C:\Users\blue\Desktop\Tools\userassistview\UserAssistView.exe'

$syntax = 'C:\UserAssistView.exe /scomma c:\users\public\UserAssist.csv'

foreach($cpu in $computers)
    {
    Copy-Item $UserAssist_copy \\$cpu\c$\.

    $Action = [wmiclass] "\\$cpu\ROOT\CIMv2:Win32_Process"

    $Method = $Action.create("powershell /c $syntax ")

    write-host 'Process call initiated on'$cpu'...' -ForegroundColor cyan
    }

# Allow time for the command to run
sleep 20

new-item c:\users\$env:USERNAME\desktop\UserAssist -ItemType directory | out-null
$mft_record = '$mft'

foreach($cpu in $computers)
    {
    rename-item \\$cpu\c$\users\public\UserAssist.csv \\$cpu\c$\users\public\$cpu-$env:USERNAME-UserAssist.csv
    copy-Item \\$cpu\c$\users\public\$cpu-$env:USERNAME-UserAssist.csv c:\users\$env:USERNAME\desktop\UserAssist

    #remove-item \\$cpu\c$\UserAssistView.exe
    #remove-item \\$cpu\c$\users\public\$cpu-$env:USERNAME-UserAssist.csv

    write-host 'Pulling data back from'$cpu'...' -ForegroundColor green
    }
