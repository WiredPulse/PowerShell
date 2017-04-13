<#
.SYNOPSIS
    This script is a wrapper for MUICacheView, which displays the list of all MUICache item.

.PARAMETER ComputerName
    Used to specify the remote system to run the script on.
    
.EXAMPLE
    PS C:\> .\Invoke-MUICache.ps1 -ComputerName 172.16.155.10 -Path c:\users\blue\desktop\MUICacheView.exe

    Runs MUICacheView on 172.16.155.10. 

.LINK
    https://github.com/google/rekall/releases

#>

param(
[Parameter(Mandatory=$true)][string]$ComputerName,
[Parameter(Mandatory=$true)][string]$Path
)


$syntax = 'C:\MUICacheView.exe /scomma c:\users\public\MUICache.csv'

if(!(test-path c:\users\$env:USERNAME\desktop\MUICache))
    {
    new-item c:\users\$env:USERNAME\desktop\MUICache -ItemType directory | out-null
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
            "$cpu : Not accessible via WMI" >> c:\users\$env:USERNAME\desktop\MUICache\_Log.txt
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
        copy-Item \\$cpu\c$\users\public\MUICache.csv c:\users\$env:USERNAME\desktop\MUICache\
        rename-item c:\users\$env:USERNAME\desktop\MUICache\MUICache.csv c:\users\$env:USERNAME\desktop\MUICache\$cpu-$env:USERNAME-MUICache.csv

        remove-item \\$cpu\c$\MUICacheView.exe
        remove-item \\$cpu\c$\users\public\MUICache.csv

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