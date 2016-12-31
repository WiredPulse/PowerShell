# Gets the changes in the domain since a specified date. 

Import-Module ActiveDirectory

# Specify date to start from. As shown below, it is March 25, 2016 at 0720
$StartDate = New-Object DateTime(2016, 03, 25, 07, 20, 00, 00)

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