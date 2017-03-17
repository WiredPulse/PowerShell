<#
    .SYNOPSIS
        This script uses RawCopy (https://github.com/jschicht/RawCopy) to get $MFTs on remote systems and pulls that file back to the local machine.

    .REQUIREMENTS
        - RawCopy (https://github.com/jschicht/RawCopy)
        - PowerShell v2
        - Elevated rights
        - C$ access
        - WMI access

    .USAGE
        1. Change the variables on line 18 and 19.
        2. Execute the script from an elevated shell
#>


$computers = Get-Content c:\users\blue\desktop\computers.txt
$mft_copy = 'C:\users\blue\Desktop\tools\RawCopy64.exe'

$syntax = 'c:\RawCopy64.exe /FileNamePath:\\.\PhysicalDrive0:0 /ImageVolume:1 /OutputPath:c:\users\public\'

foreach($cpu in $computers)
    {
    Copy-Item $mft_copy \\$cpu\c$\.

    $Action = [wmiclass] "\\$cpu\ROOT\CIMv2:Win32_Process"

    $Method = $Action.create("powershell /c $syntax ")

    write-host 'Process call initiated on' $cpu'...' -ForegroundColor cyan
    }

# Allow time for the command to run
sleep 20

new-item c:\users\$env:USERNAME\desktop\MFTs -ItemType directory | out-null
$mft_record = '$mft'

foreach($cpu in $computers)
    {
    rename-item \\$cpu\c$\users\public\$mft_record \\$cpu\c$\users\public\$cpu-$mft_record
    copy-Item \\$cpu\c$\users\public\$cpu-$mft_record c:\users\$env:USERNAME\Desktop\MFTs

    remove-item \\$cpu\c$\RawCopy64.exe
    remove-item \\$cpu\c$\users\public\$cpu-$mft_record

    write-host 'Pulling data back from' $cpu'...' -ForegroundColor green
    }


$comms = Get-Command
$i=0
ForEach ($comm in $comms) {
$i++
Write-Host $comm
Write-Progress -activity “Listing Commands” -status “Status: ” -PercentComplete (($i / $comms.count)*100)
} 