<#

.SYNOPSIS
    Grabs NTUSER.dat on remote systems and stores it in .\Remote-NTUSER on this system.
    
.PARAMETER ComputerName
    Specify a single IP or a text file containing multiple IPs.

.PARAMETER Path
    Specify path to rawcopy.exe.

.EXAMPLE
    PS C:\> .\Get-NTUSER.ps1 -ComputerName 172.16.155.201 -Path C:\users\blue\Desktop\rawcopy.exe

    Getting all the NTUSER.dat files for users on 172.16.155.201.

.LINKS
    https://github.com/jschicht/RawCopy
#>


param(
[Parameter(Mandatory=$true)][string]$ComputerName,
[Parameter(Mandatory=$true)][string]$Path
)

$newline = "`r`n"
$ErrorActionPreference = "silentlycontinue"


if(test-path c:\users\$env:USERNAME\desktop\Remote-NTUSER)
    {
    remove-item c:\users\$env:USERNAME\desktop\Remote-NTUSER -Force -Recurse
    }

new-item c:\users\$env:USERNAME\desktop\Remote-NTUSER -ItemType directory | out-null

if(test-path .\ntuser.ps1)
    {
    remove-item .\ntuser.ps1
    }

Function call
    {
    write-host "Grabbing NTUSER.dat on specified system(s)..." -ForegroundColor Cyan
    foreach($computer in $cpu)
        {
        if (!(test-path "\\$computer\c$\$exe"))
            {
            if(!(test-path "\\$computer\c$\"))
                {
                "$computer : No connection path" >> .\Remote-NTUSER\_Log.txt
                }
            Copy-item $Path \\$computer\c$\ -force -ErrorAction SilentlyContinue 
            Copy-item .\ntuser.ps1 \\$computer\c$\ -force -ErrorAction SilentlyContinue
            }
        $proc = Invoke-WmiMethod -ComputerName $computer -Class Win32_Process -Name Create -ArgumentList "powershell /c c:\ntuser.ps1"
        $my_var = Register-WmiEvent -ComputerName $computer -Query "Select * from Win32_ProcessStopTrace Where ProcessID=$($proc.ProcessId)" -MessageData $computer -Action { Write-Host "$($Event.MessageData) Process ExitCode: $($event.SourceEventArgs.NewEvent.ExitStatus)"} 
            if($proc.processid -ne $null)
            {
            # Does nothing
            }
        elseif($proc.processid -eq $null)
            {
            "$computer : Not accessible via WMI" >> .\Remote-NTUSER\_Log.txt
            }
        }
        write-host "Sleeping for 60 seconds..." -ForegroundColor Cyan
        sleep 60
    }


Function RETRIEVE
    {
    foreach($computer in $cpu)
        {
        # Retrieves the results from the distant machine and saves it locally
        copy-Item \\$computer\c$\users\public\*-ntuser.dat .\Remote-NTUSER -force -ErrorAction SilentlyContinue 
        remove-item \\$computer\c$\users\public\*-ntuser.dat -ErrorAction SilentlyContinue
        remove-item \\$computer\c$\$exe -ErrorAction SilentlyContinue
        remove-item \\$computer\c$\ntuser.ps1 -ErrorAction SilentlyContinue
        }

    write-host "Retrieving NTUSER.dat from distant machine(s)..." -ForegroundColor Cyan
    }


# Make script
"`$ntuser_list = (gci C:\users\*\NTUSER.DAT -force -Exclude 'public', 'all users', 'default', 'default user' ).directoryname"     >> .\ntuser.ps1
"foreach(`$line in `$ntuser_list)"                                                                                                >> .\ntuser.ps1
"    {"                                                                                                                           >> .\ntuser.ps1
"    c:\RawCopy.exe /fileNamePath:`$line\ntuser.dat /OutputPath:c:\users\public"                                                >> .\ntuser.ps1
"    `$dir_name = `$line.Substring(9)"                                                                                            >> .\ntuser.ps1
" "                                                                                                                               >> .\ntuser.ps1
"    rename-item c:\users\public\ntuser.dat c:\users\public\`$env:COMPUTERNAME-`$dir_name-NTUSER.dat"                             >> .\ntuser.ps1
"    }"                                                                                                                           >> .\ntuser.ps1


# Parameters received at the start of running the script
if($ComputerName -like '*.txt')
    {
    $exe = $path.split('\') | select -last 1
    $cpu = Get-content $computername
    Call
    Retrieve
    }
elseif($ComputerName -notcontains '.txt')
    {
    $exe = $path.split('\') | select -last 1
    $cpu = $ComputerName
    Call
    Retrieve
    }
else{Echo 'No IP or a file containing IPs were specified'}

remove-item .\ntuser.ps1


