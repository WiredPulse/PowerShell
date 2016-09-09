<# Lists all Domain Admins and displays the date the password was last changed.
#>


import-module activedirectory

Get-ADGroupMember -Identity "Domain Admins" | Get-ADUser -Properties PasswordLastSet | Select-Object -Property Name,PasswordLastSet | sort PasswordLastSet 