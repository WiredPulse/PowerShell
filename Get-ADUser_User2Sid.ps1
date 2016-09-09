<#
This script will return the sid for the specified Domain user account.

Usage:
    DomainUser2Sid.ps1 -domain <domain name> -user <username>

Example:
    DomainUser2Sid.ps1 -domain contoso -user joe
#>

Param(
  [string]$domain,
  [string]$user
)

$objUser = New-Object System.Security.Principal.NTAccount("$domain", "$user") 
$strSID = $objUser.Translate([System.Security.Principal.SecurityIdentifier]) 
$strSID.Value