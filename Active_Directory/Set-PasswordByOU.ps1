<# 
.SYNOPSIS
    Sets a specific password to all users within a specific OU.

    NOTE: If the OU you want to do is the main Users OU, use "CN=users". For all other OUs, use "OU=Texas". 

 #>

write-host "Input the OU you want to search in. Example: OU=Texas,DC=sandbox,DC=local" -ForegroundColor Cyan
$searchbase = Read-host " "
Write-host "Input the new password to set"  -ForegroundColor Cyan
$new_pass = Read-host " "


import-module activedirectory

Get-ADUser -Filter * -SearchScope Subtree -SearchBase $searchbase | Set-ADAccountPassword -Reset -NewPassword (ConvertTo-SecureString -AsPlainText $new_pass -Force)

Get-ADUser -Filter * -SearchScope Subtree -SearchBase $searchbase | Set-aduser -changepasswordatlogon $true