<#
    .SYNOPSIS  
        Retrieves the last logon time for a domain user. You must supply the domain on line 13 of this script.

    ####################################################################################

#>

##################
#--------Config
##################

$domain = "<Domain_Here>"

##################
#--------Main
##################

import-module activedirectory
cls
"The domain is " + $domain
$samaccountname = Read-Host 'What is the User samaccountname?'
"Processing the checks ..."
$myForest = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()
$domaincontrollers = $myforest.Sites | % { $_.Servers } | Select Name
$RealUserLastLogon = $null
$LastusedDC = $null
$domainsuffix = "*."+$domain
foreach ($DomainController in $DomainControllers) 
{
	if ($DomainController.Name -like $domainsuffix )
	{
		$UserLastlogon = Get-ADUser -Identity $samaccountname -Properties LastLogon -Server $DomainController.Name
		if ($RealUserLastLogon -le [DateTime]::FromFileTime($UserLastlogon.LastLogon))
		{
			$RealUserLastLogon = [DateTime]::FromFileTime($UserLastlogon.LastLogon)
			$LastusedDC =  $DomainController.Name
		}
	}
}
"The last logon for " + $samaccountname + " occured on " + $RealUserLastLogon + ""
"It was done against " + $LastusedDC + ""
