<#
.SYNOPSIS
    Gets a baseline list of user accounts that can be used to compare against at a later time. To get a snapshot at another point in
    time, run the Get-BaselineUsersCompare.ps1 script.
#>

import-module activedirectory

# Create directory for baseline file storage.
New-item .\User_Check -ItemType directory
Set-Location .\User_Check

# Gather a list of admins. You may need to alter this to fit your organization's structure.
"Domain Users" >> .\Baseline_Users.txt
get-adgroupmember "Domain Users" -recursive | findstr "distinguishedName" >> .\Baseline_Users.txt

# Add white space and title.
" " >> .\_Domain_Changes_Log.txt
" " >> .\_Domain_Changes_Log.txt
"Domain Users Checked" >> .\_Domain_Changes_Log.txt

# Add date\time stamp to log
Get-Date >> .\_Domain_Changes_Log.txt
