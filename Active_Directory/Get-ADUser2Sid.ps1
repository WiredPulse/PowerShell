<#
.SYNOPSIS
    This script will return the sid for the specified Domain user account.

.EXAMPLE
    DomainUser2Sid.ps1 -domain contoso -user joe
#>

Param(
  [string]$domain,
  [string]$user
)

$objUser = New-Object System.Security.Principal.NTAccount("$domain", "$user") 
$strSID = $objUser.Translate([System.Security.Principal.SecurityIdentifier]) 
$strSID.Value