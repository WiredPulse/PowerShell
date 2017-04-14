<#
.SYNOPSIS
    Deploys SysInternals' SigCheck against remote systems and returns the data back to the local machine. The data is then merged together as a csv for easy parsing.
    
.PARAMETER ComputerName
    Specify a single IP or a text file containing multiple IPs.

.PARAMETER Path
    Specify path to the executable.

.EXAMPLE
    PS C:\> .\Get-SigCheck.ps1 -ComputerName 172.16.155.201 -Path C:\users\blue\Desktop\sigcheck64.exe

    Runs sigcheck against 172.16.155.201.

.EXAMPLE
    PS C:\> .\Get-SigCheck.ps1 -ComputerName .\computers.txt -Path C:\users\blue\Desktop\sigcheck64.exe

    Runs sigcheck against systems in the computers.txt file.

.LINK
    https://technet.microsoft.com/en-us/sysinternals/bb897441.aspx
#>


param(
    [Parameter(Mandatory=$true)][string]$ComputerName,
    [Parameter(Mandatory=$true)][string]$Path
     )

$newline = "`r`n"
$current_user = [Environment]::UserName



if(!(test-path c:\users\$env:USERNAME\desktop\SigCheck))
    {
    new-item c:\users\$env:USERNAME\desktop\SigCheck -ItemType directory | out-null
    }

if(test-path c:\users\$env:USERNAME\desktop\SigCheck.ps1)
    {
    Remove-Item c:\users\$env:USERNAME\desktop\SigCheck.ps1 
    }


Function call
{
foreach($cpu in $computers)
    {
    if(test-path \\$cpu\c$\SigCheck64.exe)
        {
        remove-item \\$cpu\c$\autorunsc64.exe -ErrorAction SilentlyContinue
        }
    if(test-path \\$cpu\c$\SigCheck.ps1)
        {
        remove-item \\$cpu\c$\SigCheck.ps1 -ErrorAction SilentlyContinue
        }
    if(test-path \\$cpu\c$\sig.csv)
        {
        remove-item \\$cpu\c$\sig.csv -ErrorAction SilentlyContinue
        }
    Copy-Item $path \\$cpu\c$\.
    copy-item SigCheck.ps1 \\$cpu\c$\.

    $proc = Invoke-WmiMethod -ComputerName $cpu -Class Win32_Process -Name Create -ArgumentList "powershell /c c:\SigCheck.ps1"
    $my_var = Register-WmiEvent -ComputerName $cpu -Query "Select * from Win32_ProcessStopTrace Where ProcessID=$($proc.ProcessId)" -MessageData $cpu -Action { Write-Host "$($Event.MessageData) Process ExitCode: $($event.SourceEventArgs.NewEvent.ExitStatus)"} 
        if($proc.processid -ne $null)
            {
            # Does nothing
            }
        elseif($proc.processid -eq $null)
            {
            "$cpu : Not accessible via WMI" >> c:\users\$env:USERNAME\desktop\SigCheck\_Log.txt
            }

    write-host 'Process call initiated on' $cpu'...' -ForegroundColor cyan
    }
}


Function retrieve
    {
    foreach($cpu in $computers)
        {
        copy-Item \\$cpu\c$\sig.csv c:\users\$env:USERNAME\Desktop\SigCheck

        rename-item c:\users\$env:USERNAME\Desktop\SigCheck\sig.csv sig.txt
        remove-item c:\users\$env:USERNAME\Desktop\SigCheck\sig.csv -ErrorAction SilentlyContinue
        $conn = Get-Content c:\users\$env:USERNAME\Desktop\SigCheck\sig.txt
        $conn2 = $conn | foreach {$cpu + ',' + $_}
        $conn2 | select -skip 1 | out-file c:\users\$env:USERNAME\Desktop\SigCheck\$cpu'_'.txt

        remove-item \\$cpu\c$\SigCheck.ps1
        remove-item \\$cpu\c$\SigCheck64.exe
        remove-item \\$cpu\C$\sig.csv
        remove-item c:\users\$env:USERNAME\Desktop\SigCheck.ps1
        remove-item c:\users\$env:USERNAME\Desktop\SigCheck\sig.txt

        write-host 'Pulling data back from' $cpu'...' -ForegroundColor green
        }
    }
   

Function combine 
    {
    Get-Content c:\users\$env:USERNAME\Desktop\SigCheck\*_.txt | out-file c:\users\$env:USERNAME\Desktop\SigCheck\a.csv
    import-csv "c:\users\$env:USERNAME\Desktop\SigCheck\a.csv" -Delimiter ',' -Header 'System','Path', 'Verified','Date','Publisher','Company','Description','Product','Product Version','File Version','Machine Type','Binary Version','Original Name','Internal Name','Copyright','Comments','Entropy','MD5','SHA1','PESHA1','PESHA256','SHA256','IMP' | export-csv c:\users\$env:USERNAME\Desktop\SigCheck\SigCheck.csv
    Remove-Item c:\users\$env:USERNAME\Desktop\SigCheck\a.csv -ErrorAction SilentlyContinue
    Remove-Item c:\users\$env:USERNAME\Desktop\SigCheck\*_.txt
    }


# making script
"c:\sigcheck64.exe /accepteula" >> .\SigCheck.ps1
"c:\sigcheck64.exe -a -h -nobanner -c > c:\sig.csv" >> .\SigCheck.ps1


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

