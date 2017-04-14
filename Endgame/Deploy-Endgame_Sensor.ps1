#Requires -runasadministrator

<#
.SYNOPSIS
    EndGame sensor deployment via PowerShell.  
    
.PARAMETER ComputerName
    Specify a single IP or a text file containing multiple IPs.

.PARAMETER API_Key
    Specifiy the API of the Endgame server (Administration > Sensor Management).

.PARAMETER Path
    Specify path to EndGame sensor agent to install.

.EXAMPLE
    .\Deploy-EndGame_Sensor.ps1 -ComputerName c:\users\blue\desktop\computers.txt -API_Key F4B2029D8E4EEA451520 -Path c:\users\blue\SensorInstaller.exe

    Installing Endgame sensor on the specified IPs in computers.txt 

.EXAMPLE
    .\Deploy-EndGame_Sensor.ps1 -ComputerName 192.168.0.26 -API_Key F4B2029D8E4EEA451520 -Path c:\users\blue\SensorInstaller.exe

    Installing Endgame sensor on a specific IP.

.OUTPUTS

.NOTES
    Version:        1.0
    Author:         @wiredPulse or @Wired_Pulse
    Creation Date:  March 25, 2017

.LINK

#>

param(
    [Parameter(Mandatory=$true)][string]$ComputerName,
    [Parameter(Mandatory=$true)][string]$API_Key,
    [Parameter(Mandatory=$true)][string]$Path
     )

$newline = "`r`n"
New-Item .\Endgame_Install_Results -ItemType directory -ErrorAction SilentlyContinue | out-null
$ErrorActionPreference = "silentlycontinue"

function ENDGAME_CALL
    {
    write-host "Installing agent on specified systems..." -ForegroundColor Cyan
    foreach($computer in $cpu)
        {
        # Deletes agent executable we are copying if it already exists on distant machine
        if (!(test-path "\\$computer\c$\$exe"))
            {
            if(!(test-path "\\$computer\c$\"))
                {
                "$computer : No connection path" >> .\Endgame_Install_Results\_Log.txt
                }
            Copy-item $Path \\$computer\c$\ -force -ErrorAction SilentlyContinue 
            Copy-Item .\endgame.ps1 \\$computer\c$\ -force -ErrorAction SilentlyContinue
            }
        $proc = Invoke-WmiMethod -ComputerName $computer -Class Win32_Process -Name Create -ArgumentList "powershell /c c:\endgame.ps1"
        $my_var = Register-WmiEvent -ComputerName $computer -Query "Select * from Win32_ProcessStopTrace Where ProcessID=$($proc.ProcessId)" -MessageData $computer -Action { Write-Host "$($Event.MessageData) Process ExitCode: $($event.SourceEventArgs.NewEvent.ExitStatus)"} 
            if($proc.processid -ne $null)
            {
            # Does nothing
            }
        elseif($proc.processid -eq $null)
            {
            "$computer : Not accessible via WMI" >> .\Endgame_Install_Results\_Log.txt
            }
        }
    sleep 30 
    }


Function ENDGAME_RETRIEVE
    {
    foreach($computer in $cpu)
        {
        # Retrieves the results from the distant machine and saves it locally
        copy-Item \\$computer\c$\e-installer.txt .\Endgame_Install_Results -force -ErrorAction SilentlyContinue 
        rename-item .\Endgame_Install_Results\e-installer.txt $computer-installer.txt
        remove-item \\$computer\c$\$env:COMPUTERNAME-installer.txt -ErrorAction SilentlyContinue
        remove-item \\$computer\c$\$exe -ErrorAction SilentlyContinue
        remove-item \\$computer\c$\endgame.ps1 -ErrorAction SilentlyContinue
        remove-item \\$computer\c$\e-installer.txt -ErrorAction SilentlyContinue
        }

    write-host "Retrieving installer logs from distant machine..." -ForegroundColor Cyan
    sleep 15
    remove-item .\Endgame.ps1
    }


# Parameters received at the start of running the script
if($ComputerName -like '*.txt')
    {
    $exe = $path.split('\') | select -last 1
    $full_path = "& 'c:\$exe' @('-k', 'F4B2029D8E4EEA451520', '-d', 'false', '-l', 'c:\e-installer.txt')"
    $full_path | Out-File .\Endgame.ps1
    $cpu = Get-content $computername
    endgame_call
    endgame_retrieve
    }
elseif($ComputerName -notcontains '.txt')
    {
    $exe = $path.split('\') | select -last 1
    $full_path = "& 'c:\$exe' @('-k', 'F4B2029D8E4EEA451520', '-d', 'false', '-l', 'c:\e-installer.txt')"
    $full_path | Out-File .\Endgame.ps1
    $cpu = $ComputerName
    endgame_call
    endgame_retrieve
    }
else{Echo 'No IP or a file containing IPs were specified'}



