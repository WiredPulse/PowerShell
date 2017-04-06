<#
.SYNOPSIS
    Gets a list of users who have been inactive for 90 days

.LINK
    
#>


Import-Module ActiveDirectory
$date = get-date


$90Days = $date.adddays(-90)
# From those OU's accounts will be checked
#$ou1="OU=insert,DC=insert,DC=com"
#$ou2="OU=insert,OU=insert,DC=insert,DC=com"

$usersAttributes = {(lastlogondate -notlike "*" -OR lastlogondate -le $90days) -AND (passwordlastset -le $90days) -AND (enabled -eq $True) -and (PasswordNeverExpires -eq $false) -and (whencreated -le $90days)}
$oldusers = Get-ADUser -properties * -filter $usersAttributes 

# Create file with information on the disabled accounts
$oldusers | select-object name, SAMaccountname, passwordExpired, PasswordNeverExpires, logoncount, whenCreated, lastlogondate, PasswordLastSet, lastlogontimestamp, CanonicalName | Out-GridView

