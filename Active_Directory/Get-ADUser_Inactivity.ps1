Import-Module ActiveDirectory
$date = get-date

#make resulting filename show the day it was run on
$datefilename = "{0:yyyy-MM-dd HH-mm-ss}" -f $date 
$resultfile = "c:insert.txt"

$90Days = $date.adddays(-90)
#from those OU's accounts will be checked
$ou1="OU=insert,DC=insert,DC=com"
$ou2="OU=insert,OU=insert,DC=insert,DC=com"

$usersAttributes = {(lastlogondate -notlike "*" -OR lastlogondate -le $90days) -AND (passwordlastset -le $90days) -AND (enabled -eq $True) -and (PasswordNeverExpires -eq $false) -and (whencreated -le $90days)}
$oldusers1 = Get-ADUser -properties * -filter $usersAttributes -searchbase $ou1
$oldusers2 = Get-ADUser -properties * -filter $usersAttributes -searchbase $ou2
$oldusers = $oldusers1 + $oldusers2
#create file with information on the disabled accounts
$oldusers | select-object name, SAMaccountname, passwordExpired, PasswordNeverExpires, logoncount, whenCreated, lastlogondate, PasswordLastSet, lastlogontimestamp, CanonicalName | export-csv $resultfile

#disable the accounts and move them to new OU
foreach ($usr in $oldusers){
    Set-ADUser $usr -Enabled 0 
    Move-ADObject $usr -TargetPath "OU=Auto Disabled Users,DC=insert,DC=com"
    }
