<# 
.SYNOPSIS
    Gets hashes used for baselines.
#>

Get-ChildItem C:\windows\system32 -Recurse | Get-FileHash -Algorithm md5 | export-csv .\baseline_MD5_$env:COMPUTERNAME.csv -NoTypeInformation
Get-ChildItem C:\windows\system32 -Recurse | Get-FileHash -Algorithm sha1 | export-csv .\baseline_SHA1_$env:COMPUTERNAME.csv -NoTypeInformation