# Gets a baseline list of Admins that can be used to compare against at a later time. To get a snapshot at another point in
# time, run the Get-Baseline_Admins_Compare.ps1 script.

import-module activedirectory

# Create directory for baseline file storage.
New-item .\Admin_Check -ItemType directory
Set-Location .\Admin_Check

# Gather a list of admins. You may need to alter this to fit your organization's structure.
"Domain Admins" > .\Baseline_Admins.txt
get-adgroupmember "Domain Admins" | findstr "distinguishedName" >> .\Baseline_Admins.txt

"Administrators" >> .\Baseline_Admins.txt
get-adgroupmember "Administrators" -recursive | findstr "distinguishedName" >> .\Baseline_Admins.txt

# Add white space and title.
" " >> .\_Domain_Changes_Log.txt
" " >> .\_Domain_Changes_Log.txt
"Domain Admins Checked" >> .\_Domain_Changes_Log.txt

# Add date\time stamp to log
Get-Date >> .\_Domain_Changes_Log.txt
