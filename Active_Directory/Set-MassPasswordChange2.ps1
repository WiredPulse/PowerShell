# Sets a specific password to all users that are members of a specified group. 

# NOTE: Be aware the a user can be a member of multiple groups.

import-module activedirectory

$some_group = "Group Name"
$new_pass = "Input New Password to set"

Get-ADGroupMember -Identity $some_group | Set-ADAccountPassword -Reset -NewPassword (ConvertTo-SecureString -AsPlainText $new_pass -Force)
