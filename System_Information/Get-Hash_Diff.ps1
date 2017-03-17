<#
    .SYNOPSIS
        Reads in baseline hashes previously captured, gets new hashes, and compares the two based on MD5 and SHA1. The difference is output to the screen. 

    .REQUIREMENTS
        - PowerShell version 4 
        - A baseline of hashes made using the following syntax "Get-ChildItem C:\windows\system32 -Recurse | Get-FileHash -Algorithm md5 
        | export-csv .\baseline_MD5_$env:COMPUTERNAME.csv -NoTypeInformation"

#>

#Requires -Version 4.0

Get-ChildItem "C:\windows\system32" -Recurse | Get-FileHash -Algorithm md5 | export-csv .\New_MD5_$env:COMPUTERNAME.csv -NoTypeInformation
Get-ChildItem "C:\windows\system32" -Recurse | Get-FileHash -Algorithm sha1 | export-csv .\New_SHA1_$env:COMPUTERNAME.csv -NoTypeInformation

$base_md5 = import-csv ".\baseline_md5_$env:COMPUTERNAME.csv"
$base_sha1 = import-csv ".\baseline_sha1_$env:COMPUTERNAME.csv"

$New_md5 = import-csv ".\New_MD5_$env:COMPUTERNAME.csv"
$new_sha1 = import-csv ".\New_SHA1_$env:COMPUTERNAME.csv"

Write-host ""
Write-host "###################"-ForegroundColor Cyan
Write-host "# MD5 Differences #"-ForegroundColor Cyan
Write-host "###################"-ForegroundColor Cyan
Compare-Object $base_md5 $New_md5 -Property Hash, Path | format-table -AutoSize

Write-host ""
Write-host "####################"-ForegroundColor Cyan
Write-host "# SHA1 Differences #"-ForegroundColor Cyan
Write-host "####################"-ForegroundColor Cyan
Compare-Object $base_sha1 $New_sha1 -Property Hash, Path | format-table -AutoSize