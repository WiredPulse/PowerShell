<# 
SYNOPSIS:
    Gets a list of admins and compares it with the baseline from the Baseline_Admin.txt from the Get-BaselineAdmin.ps1 script. 

NOTES:
    - This script should be ran from the Admin_Check folder created from the Get-BaselineAdmin.ps1 script.
    - This scripts will run in an infinite loop while doing comparisons at some specified interval. 
#>

Import-Module activedirectory

# Gather a list of admins. You may need to alter this to fit your organization's structure.
"Domain Admins" > .\Baseline_Admins_Compare.txt
get-adgroupmember "Domain Admins" | findstr "distinguishedName" >> .\Baseline_Admins_Compare.txt

"Administrators" >> .\Baseline_Admins_Compare.txt
get-adgroupmember "Administrators" -recursive | findstr "distinguishedName" >> .\Baseline_Admins_Compare.txt

# Add white space and title.
" " >> .\_Domain_Changes_Log.txt
" " >> .\_Domain_Changes_Log.txt
"Domain Admins Checked" >> .\_Domain_Changes_Log.txt

# Add date\time stamp to log.
Get-Date >> .\_Domain_Changes_Log.txt

# Infinite loop to do the comparisons.
While($true)
    {
    # Compare the known good baseline to the new list.
    Compare-Object $(Get-Content .\Baseline_Admins.txt) $(Get-Content .\Baseline_Admins_Compare.txt) >> .\_Domain_Changes_Log.txt
    # Sleeps for a specified time and runs the While script block again and again.
    Start-Sleep -seconds 300
    if ((Compare-Object $(Get-Content .\Baseline_Admins.txt) $(Get-Content .\Baseline_Admins_Compare.txt)) -ne $null)
        {
        $date = Get-Date
        Write-Host $date - "NEW ADMIN ADDED! VERIFY CHANGE IN THE _Domain_Changes_Log.txt AND UPDATE THE Baseline_Admins.txt FILE IF NEEDED." -foregroundColor Red
        }
   }
