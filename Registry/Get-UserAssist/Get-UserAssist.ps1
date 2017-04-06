<#
.SYNOPSIS
    This script is a wrapper to remotely execute UserAssistView.exe across multiple systems and returns the data to the local machine in a csv. The results 
    are consolidated on the local machine and are best read in using 'out-gridview'.

    UserAssistView.exe decrypts and displays the list of all UserAssist entries stored under HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer
    \UserAssist key. The UserAssist key contains information about the exe files and links that you open frequently. The program will only get this data from the user currently logged in. In you want to parse this data for other users on the system, get the 
    NTUSER.dat file and user RegRipper against it. 

    **** IMPORTANT *****
    This will only get the UserAssist of the user that ran this script. With that said, running it as admin may not be what you want to do.

.NOTES
    http://www.nirsoft.net/utils/userassist_view.html

    $computers = Get-Content c:\users\blue\desktop\computers.txt
$path = 'C:\Users\blue\Desktop\Tools\userassistview\UserAssistView.exe'
#>


param(
    [Parameter(Mandatory=$true)][string]$ComputerName,
    [Parameter(Mandatory=$true)][string]$Path
    )


$syntax = 'C:\UserAssistView.exe /scomma c:\users\public\UserAssist.csv'

if(!(test-path c:\users\$env:USERNAME\desktop\UserAssist))
    {
    new-item c:\users\$env:USERNAME\desktop\UserAssist -ItemType directory | out-null
    }


Function call
    {
    foreach($cpu in $computers)
        {
        if(!(test-path \\$cpu\c$\$path))
            {Copy-Item $path \\$cpu\c$\.}
        $proc = Invoke-WmiMethod -ComputerName $cpu -Class Win32_Process -Name Create -ArgumentList "powershell /c $syntax"
        $my_var = Register-WmiEvent -ComputerName $cpu -Query "Select * from Win32_ProcessStopTrace Where ProcessID=$($proc.ProcessId)" -MessageData $cpu -Action { Write-Host "$($Event.MessageData) Process ExitCode: $($event.SourceEventArgs.NewEvent.ExitStatus)"} 
        if($proc.processid -ne $null)
            {
            # Does nothing
            }
        elseif($proc.processid -eq $null)
            {
            "$cpu : Not accessible via WMI" >> c:\users\$env:USERNAME\desktop\UserAssist\_Log.txt
            }

        write-host 'Process call initiated on'$cpu'...' -ForegroundColor cyan
        }
    # Allow time for the command to run
    sleep 20
    }


Function retrieve
    {
    foreach($cpu in $computers)
        {
        copy-Item \\$cpu\c$\users\public\UserAssist.csv c:\users\$env:USERNAME\desktop\UserAssist\
        rename-item c:\users\$env:USERNAME\desktop\UserAssist\UserAssist.csv c:\users\$env:USERNAME\desktop\UserAssist\$cpu-$env:USERNAME-UserAssist.csv

        remove-item \\$cpu\c$\UserAssistView.exe
        remove-item \\$cpu\c$\users\public\UserAssist.csv

        write-host 'Pulling data back from'$cpu'...' -ForegroundColor green
        }
    }


# Parameters received at the start of running the script
if($ComputerName -like '*.txt')
    {
    $computers = Get-content $computername
    call
    retrieve
    }
elseif($ComputerName -notcontains '.txt')
    {
    $computers = $ComputerName
    call
    retrieve
    }
else{Echo 'No IP or a file containing IPs were specified'}