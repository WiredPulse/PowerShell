<# 
.SYNOPSIS
    Gets the changes in the domain since a specified date. 

.PARAMETER when
    Used to specify how many days back for include in the search.

.EXAMPLE
    PS C:\> .\Get-DomainChanges.ps1 -when 365

    Specifies to include 365 days back from today's date in the search

#>

param(
[Parameter(Mandatory=$true)][string]$when
)


Import-Module ActiveDirectory

$StartDate = (get-date).AddDays(-$when)

#Find all changes in the domain since the date and assign them to $changes_made
$changes_made = Get-ADObject -Filter 'whenChanged -gt $StartDate' -IncludeDeletedObjects -properties * | sort-object objectclass | format-table deleted, Name, ObjectClass, WhenCreated, WhenChanged

#Loop through all the changes and count them
$x = 0
    foreach ($change in $changes_made)
        {$x = $x + 1}
echo "#########################################" >> .\Domain_Changes_Rolling_Log.txt
echo "Number of Changes made since $StartDate is $x." >> .\Domain_Changes_Rolling_Log.txt
echo "#########################################" >> .\Domain_Changes_Rolling_Log.txt
$changes_made >> .\Domain_Changes_Rolling_Log.txt

