<#
.SYNOPSIS
    This script is a wrapper to remotely execute ShellbagsView.exe across multiple systems and returns the data to the local machine in a csv. The results 
    are consolidated on the local machine and are best read in using 'out-gridview'.


    **** IMPORTANT *****
    This will only get Shellbags of the user that ran this script. With that said, running it as admin may not be what you want to do.

.PARAMETER computername
    Used to specify a computer or list of computers

.PATH
    Used to specify the path to shellbagview.exe

.EXAMPLE
    PS C:\> .\Get-UserAssist.ps1 -computername 172.16.155.201 -path c:\shellbagview.exe

    Runs shellbagview.exe on 172.16.155.201.

.NOTES
    http://www.nirsoft.net/utils/shell_bags_view.html

#>


param(
    [Parameter(Mandatory=$true)][string]$ComputerName,
    [Parameter(Mandatory=$true)][string]$Path
    )


$syntax = 'C:\shellbagsview.exe /scomma c:\users\public\shellbags.csv'

if(!(test-path c:\users\$env:USERNAME\desktop\shellbags))
    {
    new-item c:\users\$env:USERNAME\desktop\shellbags -ItemType directory | out-null
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
            "$cpu : Not accessible via WMI" >> c:\users\$env:USERNAME\desktop\shellbags\_Log.txt
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
        copy-Item \\$cpu\c$\users\public\shellbags.csv c:\users\$env:USERNAME\desktop\shellbags\
        rename-item c:\users\$env:USERNAME\desktop\shellbags\shellbags.csv c:\users\$env:USERNAME\desktop\shellbags\$cpu-$env:USERNAME-shellbags.csv

        remove-item \\$cpu\c$\shellbagsView.exe
        remove-item \\$cpu\c$\users\public\shellbags.csv

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