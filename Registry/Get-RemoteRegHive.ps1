<#
.SYNOPSIS
    This script uses reg.exe (c:\windows\system32\reg.exe) to remotely save the SYSTEM, SOFTWARE, or SAM hive on machine this script is ran from. Once the hives are local
    they can be ran through RegRipper (or your favorite Registry parsing tool) to make it human-readable. 
    
.PARAMETER ComputerName
    Specify a single IP or a text file containing multiple IPs.

.PARAMETER Software_hive
    Used to specify the script to get the software hive.


.PARAMETER System_hive
    Used to specify the script to get the system hive.

.PARAMETER sam_hive
    Used to specify the script to get the sam hive.

.PARAMETER CurrentUser_Hive
    Used to specify the script to get the currentuser hive.

.EXAMPLE
    PS C:\> Get-RemoteRegHive.ps1 -ComputerName 172.16.155.201 -system_hive

    Grabbing the system hive from 172.16.155.201.

.EXAMPLE
    PS C:\> Get-RemoteRegHive.ps1 -ComputerName c:\users\blue\desktop\computers.txt -system_hive

    Grabbing the system hive from the systems listed in computers.txt

#>

param(
    [Parameter(Mandatory=$true)][string]$ComputerName,
    [switch]$System_Hive,
    [switch]$Software_Hive,
    [switch]$Sam_Hive,
    [switch]$CurrentUser_Hive
    )


if($system_hive)
    {
    $System = 'reg save hklm\system c:\system.hiv'
    $hive = $System
    }

if($software_hive)
    {
    $software = 'reg save hklm\software c:\software.hiv'
    $hive = $software
    }

if($sam_hive)
    {
    $sam = 'reg save hklm\sam c:\sam.hiv'
    $hive = $sam
    }

if($CurrentUser_Hive)
    {
    $hkcu = 'reg save hkcu\ c:\hkcu.hiv'
    $hive = $hkcu
    }


if(!(test-path c:\users\$env:USERNAME\desktop\Remote_Hives))
    {
    new-item c:\users\$env:USERNAME\desktop\Remote_Hives -ItemType directory | out-null
    }

if (test-path c:\users\$env:USERNAME\desktop\grabhive.ps1)
    {
    remove-item c:\users\$env:USERNAME\desktop\grabhive.ps1
    }


Function Call 
    {
    foreach($computer in $cpu)
        {
        if(test-path \\$computer\c$\grabhive.ps1)
            {
            remove-item \\$computer\c$\grabhive.ps1
            }
        Copy-Item .\grabhive.ps1 \\$computer\C$
        $proc = Invoke-WmiMethod -ComputerName $computer -Class Win32_Process -Name Create -ArgumentList "powershell /c c:\GrabHive.ps1"
        $my_var = Register-WmiEvent -ComputerName $computer -Query "Select * from Win32_ProcessStopTrace Where ProcessID=$($proc.ProcessId)" -MessageData $computer -Action { Write-Host "$($Event.MessageData) Process ExitCode: $($event.SourceEventArgs.NewEvent.ExitStatus)"}
        if($proc.processid -ne $null)
            {
            # Does nothing
            }
        elseif($proc.processid -eq $null)
            {
            "$computer : Not accessible via WMI" >> c:\users\$env:USERNAME\desktop\Remote_Hives\_Log.txt
            }
        write-host 'Process call initiated on'$computer'...' -ForegroundColor cyan
        }
    # Allow time for the command to run
    sleep 30
    }


Function retrieve
    {
    foreach($computer in $cpu)
        {
        copy-item \\$computer\c$\$exe c:\users\$env:USERNAME\desktop\Remote_Hives 
        rename-item c:\users\$env:USERNAME\desktop\Remote_Hives\$exe c:\users\$env:USERNAME\desktop\Remote_Hives\$computer-$exe

        Remove-Item \\$computer\c$\$exe
        Remove-Item \\$computer\c$\grabhive.ps1
        Remove-Item c:\users\$env:USERNAME\desktop\grabhive.ps1 -ErrorAction SilentlyContinue
        write-host 'Pulling hive back from'$computer'...' -ForegroundColor green
        }
    }


# Parameters received at the start of running the script
if($ComputerName -like '*.txt')
    {
    $cpu = Get-content $computername
    $exe = $hive.split('\') | select -last 1
    $syntax = $hive
    "$syntax" >> .\GrabHive.ps1
    Call
    Retrieve
    }
elseif($ComputerName -notcontains '.txt')
    {
    $cpu = $ComputerName
    $exe = $hive.split('\') | select -last 1
    $syntax = $hive
    "$syntax" >> .\GrabHive.ps1
    Call
    Retrieve
    }
else{Echo 'No IP or a file containing IPs were specified'}
