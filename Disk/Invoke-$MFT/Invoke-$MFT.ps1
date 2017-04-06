<#
.SYNOPSIS
    This script uses RawCopy to get $MFTs on remote systems and pulls that file back to the local machine.

.PARAMETER ComputerName
    Specify a single IP or a text file containing multiple IPs.

.PARAMETER Path
    Specify path to rawcopy.exe.

.EXAMPLE
    PS C:\> .\Invoke-$MFT.ps1 -ComputerName 172.16.155.201 -Path c:\users\blue\desktop\rawcopy.exe

    Runs rawcopy.exe from the local machine's desktop on 172.16.155.201 in order to get the $MFT.

.LINKS
    https://github.com/jschicht/RawCopy
    https://github.com/jschicht/Mft2Csv

#>

param(
    [Parameter(Mandatory=$true)][string]$ComputerName,
    [Parameter(Mandatory=$true)][string]$Path
     )


if(test-path c:\users\$env:USERNAME\desktop\MFTs)
    {
    remove-item c:\users\$env:USERNAME\desktop\MFTs -Recurse -Force
    }

new-item c:\users\$env:USERNAME\desktop\MFTs -ItemType directory | out-null

Function call
{
foreach($cpu in $computers)
    {
    if(test-path \\$cpu\c$\rawcopy.exe)
        {
        remove-item \\$cpu\c$\rawcopy.exe
        }
    Copy-Item $path \\$cpu\c$\.
    copy-item rawcopy.ps1 \\$cpu\c$\.

    $proc = Invoke-WmiMethod -ComputerName $cpu -Class Win32_Process -Name Create -ArgumentList "powershell /c c:\rawcopy.ps1"
    $my_var = Register-WmiEvent -ComputerName $cpu -Query "Select * from Win32_ProcessStopTrace Where ProcessID=$($proc.ProcessId)" -MessageData $cpu -Action { Write-Host "$($Event.MessageData) Process ExitCode: $($event.SourceEventArgs.NewEvent.ExitStatus)"} 
        if($proc.processid -ne $null)
            {
            # Does nothing
            }
        elseif($proc.processid -eq $null)
            {
            "$pu : Not accessible via WMI" >> c:\users\$env:USERNAME\desktop\MFT\_Log.txt
            }

    write-host 'Process call initiated on' $cpu'...' -ForegroundColor cyan
    }
}


Function retrieve
{
foreach($cpu in $computers)
    {
    copy-Item \\$cpu\c$\users\public\$mft_record c:\users\$env:USERNAME\Desktop\MFTs
    rename-item c:\users\$env:USERNAME\Desktop\MFTs\$mft_record c:\users\$env:USERNAME\Desktop\MFTs\$cpu-$mft_record
    remove-item \\$cpu\c$\RawCopy.ps1
    remove-item \\$cpu\c$\RawCopy.exe
    remove-item \\$cpu\c$\users\public\$mft_record

    write-host 'Pulling data back from' $cpu'...' -ForegroundColor green
    }
}


# making script
"c:\RawCopy.exe /FileNamePath:\\.\PhysicalDrive0:0 /ImageVolume:1 /OutputPath:c:\users\public" >> .\rawcopy.ps1

if($ComputerName -like '*.txt')
    {
    $exe = $path.split('\') | select -last 1
    $cpu = Get-content $computername
    call
    # Allow time for the command to run
    sleep 25
    $mft_record = '$mft'
    retrieve
    }
elseif($ComputerName -notcontains '.txt')
    {
    $exe = $path.split('\') | select -last 1
    $cpu = $ComputerName
    call
    # Allow time for the command to run
    sleep 25
    $mft_record = '$mft'
    retrieve
    }
else{Echo 'No IP or a file containing IPs were specified'}




