<# 
.SYNOPSIS
    Searches Active Directory for user accounts that end in ".admin"
#>


import-module activedirectory

Get-ADUser -ldapFilter '(SamAccountName=*.admin)' | Select-Object -Property Name,SamAccountName | sort SamAccountName