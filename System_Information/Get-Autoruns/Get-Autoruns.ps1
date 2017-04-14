<#
.SYNOPSIS
    Deploys SysInternals' Autoruns against remote systems and returns the data back to the local machine. The data is then merged together as a csv for easy parsing.
    
.PARAMETER ComputerName
    Specify a single IP or a text file containing multiple IPs.

.PARAMETER Path
    Specify path to the executable.

.EXAMPLE
    PS C:\> .\Get-Autoruns.ps1 -ComputerName 172.16.155.201 -Path C:\users\blue\Desktop\autorunsc64.exe

    Runs autoruns against 172.16.155.201.

.EXAMPLE
    PS C:\> .\Get-Autoruns.ps1 -ComputerName .\computers.txt -Path C:\users\blue\Desktop\autorunsc64.exe

    Runs autoruns against systems in the computers.txt file.

.LINK
    https://technet.microsoft.com/en-us/sysinternals/bb963902.aspx
#>


param(
    [Parameter(Mandatory=$true)][string]$ComputerName,
    [Parameter(Mandatory=$true)][string]$Path
     )

$newline = "`r`n"
$current_user = [Environment]::UserName



if(!(test-path c:\users\$env:USERNAME\desktop\Autoruns))
    {
    new-item c:\users\$env:USERNAME\desktop\Autoruns -ItemType directory | out-null
    }

if(test-path c:\users\$env:USERNAME\desktop\Autoruns.ps1)
    {
    Remove-Item c:\users\$env:USERNAME\desktop\autoruns.ps1 
    }


Function call
{
foreach($cpu in $computers)
    {
    if(test-path \\$cpu\c$\autorunsc64.exe)
        {
        remove-item \\$cpu\c$\autorunsc64.exe -ErrorAction SilentlyContinue
        }
    if(test-path \\$cpu\c$\autoruns.ps1)
        {
        remove-item \\$cpu\c$\autoruns.ps1 -ErrorAction SilentlyContinue
        }
    if(test-path \\$cpu\c$\auto.csv)
        {
        remove-item \\$cpu\c$\auto.csv -ErrorAction SilentlyContinue
        }
    Copy-Item $path \\$cpu\c$\.
    copy-item autoruns.ps1 \\$cpu\c$\.

    $proc = Invoke-WmiMethod -ComputerName $cpu -Class Win32_Process -Name Create -ArgumentList "powershell /c c:\autoruns.ps1"
    $my_var = Register-WmiEvent -ComputerName $cpu -Query "Select * from Win32_ProcessStopTrace Where ProcessID=$($proc.ProcessId)" -MessageData $cpu -Action { Write-Host "$($Event.MessageData) Process ExitCode: $($event.SourceEventArgs.NewEvent.ExitStatus)"} 
        if($proc.processid -ne $null)
            {
            # Does nothing
            }
        elseif($proc.processid -eq $null)
            {
            "$cpu : Not accessible via WMI" >> c:\users\$env:USERNAME\desktop\autoruns\_Log.txt
            }

    write-host 'Process call initiated on' $cpu'...' -ForegroundColor cyan
    }
}


Function retrieve
    {
    foreach($cpu in $computers)
        {
        copy-Item \\$cpu\c$\auto.csv c:\users\$env:USERNAME\Desktop\autoruns

        rename-item c:\users\$env:USERNAME\Desktop\autoruns\auto.csv auto.txt
        remove-item c:\users\$env:USERNAME\Desktop\autoruns\auto.csv -ErrorAction SilentlyContinue
        $conn = Get-Content c:\users\$env:USERNAME\Desktop\autoruns\auto.txt
        $conn2 = $conn | foreach {$cpu + ',' + $_}
        $conn2 | select -skip 1 | out-file c:\users\$env:USERNAME\Desktop\autoruns\$cpu'_'.txt

        remove-item \\$cpu\c$\autoruns.ps1
        remove-item \\$cpu\c$\autorunsc64.exe
        remove-item \\$cpu\C$\auto.csv
        remove-item c:\users\$env:USERNAME\Desktop\autoruns.ps1
        remove-item c:\users\$env:USERNAME\Desktop\autoruns\auto.txt

        write-host 'Pulling data back from' $cpu'...' -ForegroundColor green
        }
    }
   

Function combine 
    {
    Get-Content c:\users\$env:USERNAME\Desktop\autoruns\*_.txt | out-file c:\users\$env:USERNAME\Desktop\autoruns\a.csv
    import-csv "c:\users\$env:USERNAME\Desktop\autoruns\a.csv" -Delimiter ',' -Header 'System','Time', 'Entry Location','Entry','Enabled','Category','Profile','Description','Company','Image Path','Version','Launch String' | export-csv c:\users\$env:USERNAME\Desktop\autoruns\autoruns.csv
    Remove-Item c:\users\$env:USERNAME\Desktop\autoruns\a.csv -ErrorAction SilentlyContinue
    Remove-Item c:\users\$env:USERNAME\Desktop\autoruns\*_.txt
    }


# making script
"c:\autorunsc64.exe /accepteula" >> .\autoruns.ps1
"c:\autorunsc64.exe -a * -nobanner -c > c:\auto.csv" >> .\autoruns.ps1


if($ComputerName -like '*.txt')
    {
    $exe = $path.split('\') | select -last 1
    $computers = Get-content $computername
    call
    # Allow time for the command to run
    sleep 45
    retrieve
    combine
    }
elseif($ComputerName -notcontains '.txt')
    {
    $exe = $path.split('\') | select -last 1
    $computers = $ComputerName
    call
    # Allow time for the command to run
    sleep 45
    retrieve
    combine
    }
else{Echo 'No IP or a file containing IPs were specified'}

