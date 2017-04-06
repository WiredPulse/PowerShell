<# 
SYNOPSIS:
    Gets a list of Domain Users and compares it with the baseline from the Baseline_Users.txt from the Get-BaselineUsers.ps1 script. 

NOTES:
    - This script should be ran from the Users_Check folder created from the Get-BaselineUsers.ps1 script.
    - This scripts will run in an infinite loop while doing comparisons at some specified interval. 
#>

Import-Module activedirectory

# Gather a list of Domain Users. You may need to alter this to fit your organization's structure.
"Domain Users" >> .\Baseline_Users_Compare.txt
get-adgroupmember "Domain Users" -recursive | findstr "distinguishedName" >> .\Baseline_Users_Compare.txt

# Add white space and title.
" " >> .\_Domain_Changes_Log.txt
" " >> .\_Domain_Changes_Log.txt
"Domain Users Checked" >> .\_Domain_Changes_Log.txt

# Add date\time stamp to log.
Get-Date >> .\_Domain_Changes_Log.txt

# Infinite loop to do the comparisons.
While($true)
    {
    # Compare the known good baseline to the new list.
    Compare-Object $(Get-Content .\Baseline_Userss.txt) $(Get-Content .\Baseline_Users_Compare.txt) >> .\_Domain_Changes_Log.txt
    # Sleeps for a specified time and runs the While script block again and again.
    Start-Sleep -seconds 300
    if ((Compare-Object $(Get-Content .\Baseline_Users.txt) $(Get-Content .\Baseline_Userss_Compare.txt)) -ne $null)
        {
        $date = Get-Date
        Write-Host $date - "NEW USER ADDED! VERIFY CHANGE IN THE _Domain_Changes_Log.txt AND UPDATE THE Baseline_Users.txt FILE IF NEEDED." -foregroundColor Red
        }
   }
