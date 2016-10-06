<# Searches for non-expiring accounts
#>


import-module activedirectory

Get-ADUser -Filter * -Properties passwordneverexpires | sort name | ft Name,passwordneverexpires,ObjectClass -A