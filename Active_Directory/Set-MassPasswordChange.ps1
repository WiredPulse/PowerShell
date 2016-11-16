# Sets a specific password to all users within a specific OU.

# NOTE: If the OU you want to do is the main Users OU, use "CN=users". For all other OUs, use "OU=Texas". 

import-module activedirectory

$searchbase = "CN=Texas,DC=sandbox,DC=local"
$new_pass = "Input New Password to set"

Get-ADUser -Filter * -SearchScope Subtree -SearchBase $searchbase | Set-ADAccountPassword -Reset -NewPassword (ConvertTo-SecureString -AsPlainText $new_pass -Force)