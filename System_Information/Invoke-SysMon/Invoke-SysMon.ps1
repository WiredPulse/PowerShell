<#
.SYNOPSIS
    Deploys SysInternals' Sysmon against remote systems.
    
.PARAMETER ComputerName
    Specify a single IP or a text file containing multiple IPs.

.PARAMETER Path
    Specify path to the executable.

.EXAMPLE
    PS C:\> .\Invoke-Sysmon.ps1 -ComputerName 172.16.155.201 -Path C:\users\blue\Desktop\SysMon64.exe

    Runs SysMon against 172.16.155.201.

.EXAMPLE
    PS C:\> .\Invoke-SysMon.ps1 -ComputerName .\computers.txt -Path C:\users\blue\Desktop\SysMon64.exe

    Runs SysMon against systems in the computers.txt file.

.LINK
    https://technet.microsoft.com/en-us/sysinternals/sysmon
#>


param(
    [Parameter(Mandatory=$true)][string]$ComputerName,
    [Parameter(Mandatory=$true)][string]$Path
     )

$newline = "`r`n"
$current_user = [Environment]::UserName



if(test-path c:\users\$env:USERNAME\desktop\SysMon_Install.txt)
    {
    remove-item c:\users\$env:USERNAME\desktop\SysMon_Install.txt
    }


Function call
{
foreach($cpu in $computers)
    {
    if(test-path \\$cpu\c$\SysMon64.exe)
        {
        remove-item \\$cpu\c$\SysMon64.exe -ErrorAction SilentlyContinue
        }
    if(test-path \\$cpu\c$\SysMon.ps1)
        {
        remove-item \\$cpu\c$\SysMon.ps1 -ErrorAction SilentlyContinue
        }

    Copy-Item $path \\$cpu\c$\.
    copy-item SysMon.ps1 \\$cpu\c$\.

    $proc = Invoke-WmiMethod -ComputerName $cpu -Class Win32_Process -Name Create -ArgumentList "powershell /c c:\SysMon.ps1"
    $my_var = Register-WmiEvent -ComputerName $cpu -Query "Select * from Win32_ProcessStopTrace Where ProcessID=$($proc.ProcessId)" -MessageData $cpu -Action { Write-Host "$($Event.MessageData) Process ExitCode: $($event.SourceEventArgs.NewEvent.ExitStatus)"} 
        if($proc.processid -ne $null)
            {
            # Does nothing
            }
        elseif($proc.processid -eq $null)
            {
            "$cpu : Not accessible via WMI" >> c:\users\$env:USERNAME\desktop\SysMon_Install.txt
            }

    write-host 'Process call initiated on' $cpu'...' -ForegroundColor cyan
    }
}


Function retrieve
    {
    foreach($cpu in $computers)
        {
        remove-item \\$cpu\c$\SysMon.ps1
        remove-item \\$cpu\c$\SysMon64.exe
        remove-item c:\users\$env:USERNAME\Desktop\SysMon.ps1

        write-host 'Pulling data back from' $cpu'...' -ForegroundColor green
        }
    }
   
Function verify
   {
   foreach($computer in $computers)
        {
        Get-WmiObject -ComputerName $Computer -Query 'SELECT * FROM Win32_service WHERE name = "sysmon"'| select PSComputername, Name, State | out-file c:\users\$env:USERNAME\Desktop\SysMon_Installs.txt
        }
   Write-host 'Successful SysMon installation log written to "SysMon_Installs.txt" on the desktop' -ForegroundColor cyan
   }


# making script
"c:\SysMon64.exe -accepteula" >> .\SysMon.ps1
"c:\Sysmon64.exe -i -n -accepteula" >> .\SysMon.ps1


if($ComputerName -like '*.txt')
    {
    $exe = $path.split('\') | select -last 1
    $computers = Get-content $computername
    call
    # Allow time for the command to run
    sleep 5
    retrieve
    verify
    }
elseif($ComputerName -notcontains '.txt')
    {
    $exe = $path.split('\') | select -last 1
    $computers = $ComputerName
    call
    # Allow time for the command to run
    sleep 5
    retrieve
    verify
    }
else{Echo 'No IP or a file containing IPs were specified'}

