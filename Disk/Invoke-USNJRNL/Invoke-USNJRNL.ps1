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


if(!(test-path c:\users\$env:USERNAME\desktop\USNJRNL))
    {
    new-item c:\users\$env:USERNAME\desktop\USNJRNL -ItemType directory | out-null
    }

if(test-path .\usnjrnl.ps1)
    {
    remove-item .\usnjrnl.ps1 -ErrorAction SilentlyContinue
    }


Function call
{
foreach($cpu in $computers)
    {
    if(test-path \\$cpu\c$\ExtractUsnJrnl.exe)
        {
        remove-item \\$cpu\c$\ExtractUsnJrnl.exe
        }
    Copy-Item $path \\$cpu\c$\.
    copy-item usnjrnl.ps1 \\$cpu\c$\.

    $proc = Invoke-WmiMethod -ComputerName $cpu -Class Win32_Process -Name Create -ArgumentList "powershell /c c:\usnjrnl.ps1"
    $my_var = Register-WmiEvent -ComputerName $cpu -Query "Select * from Win32_ProcessStopTrace Where ProcessID=$($proc.ProcessId)" -MessageData $cpu -Action { Write-Host "$($Event.MessageData) Process ExitCode: $($event.SourceEventArgs.NewEvent.ExitStatus)"} 
        if($proc.processid -ne $null)
            {
            # Does nothing
            }
        elseif($proc.processid -eq $null)
            {
            "$pu : Not accessible via WMI" >> c:\users\$env:USERNAME\desktop\USNJRNL\_Log.txt
            }

    write-host 'Process call initiated on' $cpu'...' -ForegroundColor cyan
    }
}


Function retrieve
{
foreach($cpu in $computers)
    {
    copy-Item \\$cpu\c$\users\public\*-jrnl.cab c:\users\$env:USERNAME\Desktop\usnjrnl
    remove-item \\$cpu\c$\usnjrnl.ps1
    remove-item \\$cpu\c$\ExtractUsnJrnl.exe
    remove-item \\$cpu\c$\users\public\*J.bin
    remove-item \\$cpu\c$\users\public\*-jrnl.cab
    Remove-Item .\usnjrnl.ps1

    write-host 'Pulling data back from' $cpu'...' -ForegroundColor green
    }
}


# making script
"C:\ExtractUsnJrnl.exe /DevicePath:c: /OutputPath:C:\users\public | out-null " >> .\usnjrnl.ps1
"makecab 'C:\users\public\`$UsnJrnl_`$J.bin' C:\users\public\`$env:COMPUTERNAME-jrnl.cab | Out-Null " >> .\usnjrnl.ps1

if($ComputerName -like '*.txt')
    {
    $computers = Get-content $computername
    call
    # Allow time for the command to run
    sleep 45
    retrieve
    }
elseif($ComputerName -notcontains '.txt')
    {
    $computers = $ComputerName
    call
    # Allow time for the command to run
    sleep 45
    retrieve
    }
else{Echo 'No IP or a file containing IPs were specified'}




