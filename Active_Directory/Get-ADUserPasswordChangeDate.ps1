<#
.SYNOPSIS
    Searches for accounts containing specified key words and displays the last time their password was changed.

#>

import-module activedirectory

Get-ADUser -Filter 'name -Like "svc*"' | Get-ADUser -Properties PasswordLastSet | Select-Object -Property Name,PasswordLastSet | sort PasswordLastSet