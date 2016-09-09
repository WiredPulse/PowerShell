<#
This script will return the Domain user account for the specified SID.

Usage:
    DomainSid2User.ps1 -domain -sid <sid>

Example:
    DomainSid2User.ps1 -domain -sid S-1-5-21-1489596007-1899944082-3082231942-1000
#>

Param(
  [string]$sid
)

$objSID = New-Object System.Security.Principal.SecurityIdentifier ` 
("$sid") 
$objUser = $objSID.Translate( [System.Security.Principal.NTAccount]) 
$objUser.Value