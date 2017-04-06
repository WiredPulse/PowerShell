<#
.SYNOPSIS
    This script is a wrapper for WinPmem. With it, memory captures are created remotely to C:\ on the distant end.


.PARAMETER ComputerName
    Used to specify the remote system to run the script on.
    
.EXAMPLE
    PS C:\> .\Invoke-MemCapture.ps1 -ComputerName 172.16.155.10 -Path c:\users\blue\desktop\winpmem.exe

    Runs WinPmem on 172.16.155.10. 

.LINK
    https://github.com/google/rekall/releases

#>

param(
[Parameter(Mandatory=$true)][string]$ComputerName,
[Parameter(Mandatory=$true)][string]$Path
)

Write-host "*** Memory Captures will be copied to C:\ ***" -ForegroundColor Cyan

$newline = "`r`n"
$ErrorActionPreference = "silentlycontinue"

if(test-path .\memcap.ps1)
    {
    remove-item .\memcap.ps1
    }

Function call
    {
    write-host "Executing memory capture on specified system(s)..." -ForegroundColor Cyan
    foreach($computer in $cpu)
        {
        if (!(test-path "\\$computer\c$\$exe"))
            {
            if(!(test-path "\\$computer\c$\"))
                {
                "$computer : No connection path" >> .\MemCapture_Results\_Log.txt
                }
            Copy-item $Path \\$computer\c$\ -force -ErrorAction SilentlyContinue 
            Copy-item .\memcap.ps1 \\$computer\c$\ -force -ErrorAction SilentlyContinue
            }
        $proc = Invoke-WmiMethod -ComputerName $computer -Class Win32_Process -Name Create -ArgumentList "powershell /c c:\memcap.ps1"
        $my_var = Register-WmiEvent -ComputerName $computer -Query "Select * from Win32_ProcessStopTrace Where ProcessID=$($proc.ProcessId)" -MessageData $computer -Action { Write-Host "$($Event.MessageData) Process ExitCode: $($event.SourceEventArgs.NewEvent.ExitStatus)"} 
            if($proc.processid -ne $null)
            {
            # Does nothing
            }
        elseif($proc.processid -eq $null)
            {
            "$computer : Not accessible via WMI" >> .\MemCapture_Results\_Log.txt
            }
        }
    }


# Making script
"c:\winpmem.exe c:\`$env:computername.raw" >> .\memcap.ps1
"remove-item c:\winpmem.exe" >> .\memcap.ps1
"remove-item c:\memcap.ps1" >> .\memcap.ps1

# Parameters received at the start of running the script
if($ComputerName -like '*.txt')
    {
    $exe = $path.split('\') | select -last 1
    $cpu = Get-content $computername
    call
    }
elseif($ComputerName -notcontains '.txt')
    {
    $exe = $path.split('\') | select -last 1
    $cpu = $ComputerName
    call
    }
else{Echo 'No IP or a file containing IPs were specified'}

remove-item .\memcap.ps1