<#
.SYNOPSIS  
    Gets MD5 hash of specified file.

.LINKS
    http://jongurgul.com/blog/get-stringhash-get-filehash/
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