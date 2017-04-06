<#
.SYNOPSIS
    This script will return the sid for the specified local user account.

.EXAMPLE
    PS C:\> .\LocalUser2Sid.ps1 -user joe

#>

Param(
  [string]$user
)

$objUser = New-Object System.Security.Principal.NTAccount("$user") 
$strSID = $objUser.Translate([System.Security.Principal.SecurityIdentifier]) 
$strSID.Value