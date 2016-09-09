<# Lists all users who have been created within the last 30 days and the actual date.
#>

import-module activedirectory

$When = ((Get-Date).AddDays(-30)).Date 
Get-ADUser -Filter {whenCreated -ge $When} -Properties whenCreated