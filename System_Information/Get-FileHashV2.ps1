<#
    .SYNOPSIS  
        Gets MD5 hash of specified file.

    .NOTES  
        File Name      : Get-Hash.ps1
        Version        : v.0.1  
        Prerequisite   : PowerShell v2 or higher
        Created        : 06 July 16
     
     .EXAMPLE
        Get-hash

     .REFERENCE
        http://jongurgul.com/blog/get-stringhash-get-filehash/
        

    ####################################################################################

#>

$input = Read-Host "Input path to file to hash"

Function Get-Hash([String] $FileName,$HashName = "MD5")
{
$FileStream = New-Object System.IO.FileStream($FileName,[System.IO.FileMode]::Open)
$StringBuilder = New-Object System.Text.StringBuilder
[System.Security.Cryptography.HashAlgorithm]::Create($HashName).ComputeHash($FileStream)|%{[Void]$StringBuilder.Append($_.ToString("x2"))}
$FileStream.Close()
$StringBuilder.ToString()
}

Get-Hash $input