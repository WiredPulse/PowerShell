<#
.SYNOPSIS
    This script will return the group name for the specified SID.

.PARAMETER sid
    Used to specify the SID the get the group name for.

.EXAMPLE
    PS C:\> .\Get-ADGroup2SID -sid 's-1-5-32-544'

    Retrieving the group name for the specified SID. 

.LINK
#>


param(
[Parameter(Mandatory=$true)][string]$sid
)


import-module activedirectory
Get-ADGroup -Identity $sid

