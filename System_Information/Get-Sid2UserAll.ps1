<# 
.SYNOPSIS
    Returns all SIDS on a system
#>

(Get-WmiObject -Class Win32_UserProfile -Namespace "root\cimv2"  | select sid,localpath)