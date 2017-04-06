<#
.SYNOPSIS
    This script is a wrapper to remotely execute LastActivity.exe across multiple systems and returns the data to the local machine in a csv. The results 
    are consolidated on the local machine and are best read in using 'out-gridview'.

    LastActivityView is a tool for Windows operating system that collects information from various sources on a running system, and displays a log of actions made 
    by the user and events occurred on this computer. The activity displayed by LastActivityView includes: Running .exe file, Opening open/save dialog-box, Opening 
    file/folder from Explorer or other software, software installation, system shutdown/start, application or system crash, network connection/disconnection and more... 

 #   **** IMPORTANT *****
 #  This will only get the UserAssist of the user that ran this script. With that said, running it as admin may not be what you want to do.

.NOTES
    http://www.nirsoft.net/utils/computer_activity_view.html

    $computers = Get-Content c:\users\blue\desktop\computers.txt
$path = 'C:\Users\blue\Desktop\Tools\userassistview\UserAssistView.exe'
#>


param(
    [Parameter(Mandatory=$true)][string]$ComputerName,
    [Parameter(Mandatory=$true)][string]$Path
    )


$syntax = 'C:\LastActivityView.exe /scomma c:\users\public\LastActivity.csv'

if(!(test-path c:\users\$env:USERNAME\desktop\LastActivity))
    {
    new-item c:\users\$env:USERNAME\desktop\LastActivity -ItemType directory | out-null
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
            "$cpu : Not accessible via WMI" >> c:\users\$env:USERNAME\desktop\LastActivity\_Log.txt
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
        copy-Item \\$cpu\c$\users\public\LastActivity.csv c:\users\$env:USERNAME\desktop\LastActivity\
        rename-item c:\users\$env:USERNAME\desktop\LastActivity\LastActivity.csv c:\users\$env:USERNAME\desktop\LastActivity\$cpu-$env:USERNAME-LastActivity.csv

        remove-item \\$cpu\c$\LastActivityView.exe
        remove-item \\$cpu\c$\users\public\LastActivity.csv

        write-host 'Pulling data back from'$cpu'...' -ForegroundColor green
        }
    }


# Parameters received at the start of running the script
if($ComputerName -like '*.txt')
    {
    $cpu = Get-content $computername
    call
    retrieve
    }
elseif($ComputerName -notcontains '.txt')
    {
    $cpu = $ComputerName
    call
    retrieve
    }
else{Echo 'No IP or a file containing IPs were specified'}