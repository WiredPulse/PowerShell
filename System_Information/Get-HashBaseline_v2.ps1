<#
    .SYNOPSIS:
        Gets file hash of files in a directory recursively. The system name, hash, and file with path are exported to a CSV that is best read back into
        PowerShell using out-gridview.

    .USAGE:
        - Change variables on line 12
        - Execute script from elevated shell

    .REQUIREMENTS
        - PowerShell Version 2

#>

#Requires -Version 2

# Variable to change. This specifies what directory recursively to hash files
$file_list = Get-ChildItem "c:\windows\system32\*.*" -Recurse -Force -ErrorAction SilentlyContinue

# Don't touch!
$md5 = New-Object -TypeName System.Security.Cryptography.MD5CryptoServiceProvider
$sha1 = New-Object -TypeName System.Security.Cryptography.sha1CryptoServiceProvider
$newline = "`r`n"

# Loops through and returns system name, hash type (MD5 or SHA1), hash, and file path
foreach($file in $file_list.fullname)
    {
    try
        {
        $hash_md5 += $env:COMPUTERNAME + "+MD5+" + [System.BitConverter]::ToString($md5.ComputeHash([System.IO.File]::ReadAllBytes($file))) + "+" + $file + $newline
        }
    Catch
        {
        # Only here to catch errors from "Access denied" or "in use" messages
        }
    }

    foreach($file in $file_list.fullname)
    {
    try
        {
        $hash_sha1 += $env:COMPUTERNAME + "+SHA1+" + [System.BitConverter]::ToString($md5.ComputeHash([System.IO.File]::ReadAllBytes($file))) + "+" + $file + $newline
        }
    Catch
        {
        # Only here to catch errors from "Access denied" or "in use" messages
        }
    }

$hash_md5 | Out-File .\Base_MD5_$env:COMPUTERNAME.txt
$hash_sha1 | Out-File .\Base_SHA1_$env:COMPUTERNAME.txt
Import-csv ".\Base_MD5_$env:COMPUTERNAME.txt" -Delimiter '+' -Header 'System', 'Type', 'Hash', 'File' |export-csv .\Base_Hash_MD5_$env:COMPUTERNAME.csv
Import-csv ".\Base_SHA1_$env:COMPUTERNAME.txt" -Delimiter '+' -Header 'System', 'Type', 'Hash', 'File' |export-csv .\Base_Hash_SHA1_$env:COMPUTERNAME.csv

Clear-Variable hash_md5, hash_Sha1
Remove-Item .\Base_MD5_HUNTER.txt
Remove-Item .\Base_SHA1_HUNTER.txt
