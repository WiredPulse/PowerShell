<# 
.SYNOPSIS
    Lists all users who have been created within the days specified.

.PARAMETER when
    Used to specify the number of days to go back to search for results.

.EXAMPLE
    PS C:\> .\Get-ADUserRecentlyCreated.ps1 -When 30

    Returns accounts created within the last 30 days. 

#>

param(
[Parameter(Mandatory=$true)][string]$when
)


import-module activedirectory

$my_date = ((Get-Date).AddDays(-$when)).Date 
Get-ADUser -Filter {whenCreated -ge $my_date} -Properties whenCreated