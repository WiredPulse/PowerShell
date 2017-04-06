<# 
.SYNOPSIS
    Sets a specific password to all users that are members of a specified group. 

    NOTE: Be aware that a user can be a member of multiple groups. For example, admin accounts are commonly part of the Domain Users group as well as a privileged group.

#>

write-host "Input the Group name containing users" -ForegroundColor Cyan
$some_group = Read-host " "
Write-host "Input the new password to set"  -ForegroundColor Cyan
$new_pass = Read-host " "


import-module activedirectory


Get-ADGroupMember -Identity $some_group | Set-ADAccountPassword -Reset -NewPassword (ConvertTo-SecureString -AsPlainText $new_pass -Force)

Get-ADGroupMember -Identity $some_group | Set-aduser -changepasswordatlogon $true