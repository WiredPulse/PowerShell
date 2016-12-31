<# 
SYNOPSIS:
    Gets a baseline list of Domain Users, Domain Admins, and Administrators that can be used to compare against at a later time. 

USAGE:
    To get the initial baseline, run the script and select option 1. To compare the baseline with the current accounts, select option 2.
 #>

import-module activedirectory

# Menu
Clear-Host  
Write-Host "-----------------------------------------------------------"  -ForegroundColor Yellow
Write-Host "|        " -ForegroundColor Yellow -NoNewline; Write-Host "Active Directory Account Baseline Monitor        " -foregroundcolor Cyan -nonewline; Write-Host "|" -foreground Yellow  
Write-Host "|---------------------------------------------------------|"  -ForegroundColor Yellow 
Write-Host "|                                                         |"  -ForegroundColor Yellow 
Write-Host "|          " -ForegroundColor Yellow -NoNewline; Write-Host "1. Get account baselines" -ForegroundColor Green -NoNewline; Write-Host "                       |" -ForegroundColor Yellow 
Write-Host "|          " -ForegroundColor Yellow -NoNewline; Write-Host "2. Compare current accounts with baselines" -ForegroundColor Green -NoNewline; Write-Host "     |" -ForegroundColor Yellow
Write-Host "|          " -ForegroundColor Yellow -NoNewline; Write-Host "3. Exit" -ForegroundColor Green -NoNewline; Write-Host "                                        |" -ForegroundColor Yellow
Write-Host "|                                                         |"  -ForegroundColor Yellow 
Write-Host "-----------------------------------------------------------"  -ForegroundColor Yellow 

$answer = read-host "Please Make a Selection"   
    if ($answer -eq 1)
        {
        Write-Output "Getting information for baseline..."

        # Create directory for baseline file storage.
        New-item .\AD_Check -ItemType directory | Out-Null
        Set-Location .\AD_Check

        # Gather a list of users. You may need to alter this to fit your organization's structure.
        "Domain Admins" > .\Baseline_Admins.txt
        get-adgroupmember "Domain Admins" | findstr "distinguishedName" > .\Baseline_Admins.txt

        "Administrators" >> .\Baseline_Admins.txt
        get-adgroupmember "Administrators" -recursive | findstr "distinguishedName" >> .\Baseline_Admins.txt

        "Domain Users" >> .\Baseline_AD_Users.txt
        get-adgroupmember "Domain Users" -recursive | findstr "distinguishedName" > .\Baseline_AD_Users.txt

        # Add white space and title.
        " " >> .\_Domain_Changes_Log.txt
        " " >> .\_Domain_Changes_Log.txt
        "Domain Admins, Administrators, and Domain Users Checked" >> .\_Domain_Changes_Log.txt

        # Add date\time stamp to log
        Get-Date >> .\_Domain_Changes_Log.txt
        }  
    if ($answer -eq 2)
        {
        Write-Output " "
        Write-Output "Getting information to compare baselines..."
        Write-Output " "
        Write-Output "Comparing baselines... findings will be output to the screen. Comparisons will continue to happen every 5 minutes as long as this script is running"
            
            # Infinite loop to do the comparisons.
            While($true)
                {
                # Gather a list of admins. You may need to alter this to fit your organization's structure.
                "Domain Admins" > .\Baseline_Admins_Compare.txt
                get-adgroupmember "Domain Admins" | findstr "distinguishedName" > .\Baseline_Admins_Compare.txt
        
                "Administrators" >> .\Baseline_Admins_Compare.txt
                get-adgroupmember "Administrators" -recursive | findstr "distinguishedName" >> .\Baseline_Admins_Compare.txt

                "Domain Users" >> .\Baseline_AD_Users_Compare.txt
                get-adgroupmember "Domain Users" -recursive | findstr "distinguishedName" > .\Baseline_AD_Users_Compare.txt

                # Add white space and title.
                " " >> .\_Domain_Changes_Log.txt
                " " >> .\_Domain_Changes_Log.txt
                "Domain Admins, Administrators, and Domain Users Checked" >> .\_Domain_Changes_Log.txt
        
                # Add date\time stamp to log.
                Get-Date >> .\_Domain_Changes_Log.txt

                # Compare the known good baseline to the new lists.
                Compare-Object $(Get-Content .\Baseline_AD_Users.txt) $(Get-Content .\Baseline_AD_Users_Compare.txt) >> .\_Domain_Changes_Log.txt
                Compare-Object $(Get-Content .\Baseline_Admins.txt) $(Get-Content .\Baseline_Admins_Compare.txt) >> .\_Domain_Changes_Log.txt
                    
                # Sleeps for a specified time and runs the While script block again and again.
                Start-Sleep -seconds 300
                    if ((Compare-Object $(Get-Content .\Baseline_AD_Users.txt) $(Get-Content .\Baseline_AD_Users_Compare.txt)))
                        {
                        $date = Get-Date
                        Write-Host $date -ForegroundColor Green -NoNewline; Write-Host " - " -ForegroundColor white -NoNewline; Write-Host "NEW USER ADDED! " -ForegroundColor Red -NoNewline; Write-Host "VERIFY CHANGE IN THE _Domain_Changes_Log.txt AND UPDATE THE Baseline_Users.txt FILE IF NEEDED." -ForegroundColor Green 
                            if ((Compare-Object $(Get-Content .\Baseline_Admins.txt) $(Get-Content .\Baseline_Admins_Compare.txt)) -ne $null)
                                {
                                $date = Get-Date
                                Write-Host $date -ForegroundColor Green -NoNewline; Write-Host " - " -ForegroundColor white -NoNewline; Write-Host "NEW ADMIN ADDED! " -ForegroundColor Red -NoNewline; Write-Host "VERIFY CHANGE IN THE _Domain_Changes_Log.txt AND UPDATE THE Baseline_Users.txt FILE IF NEEDED." -ForegroundColor Green
                                }
                        }
                    Elseif ((Compare-Object $(Get-Content .\Baseline_Admins.txt) $(Get-Content .\Baseline_Admins_Compare.txt)) -ne $null)
                        {
                        $date = Get-Date
                        Write-Host $date -ForegroundColor Green -NoNewline; Write-Host " - " -ForegroundColor white -NoNewline; Write-Host "NEW ADMIN ADDED! " -ForegroundColor Red -NoNewline; Write-Host "VERIFY CHANGE IN THE _Domain_Changes_Log.txt AND UPDATE THE Baseline_Users.txt FILE IF NEEDED." -ForegroundColor Green
                            if ((Compare-Object $(Get-Content .\Baseline_AD_Users.txt) $(Get-Content .\Baseline_AD_Users_Compare.txt)))
                                {
                                $date = Get-Date
                                Write-Host $date -ForegroundColor Green -NoNewline; Write-Host " - " -ForegroundColor white -NoNewline; Write-Host "NEW USER ADDED! " -ForegroundColor Red -NoNewline; Write-Host "VERIFY CHANGE IN THE _Domain_Changes_Log.txt AND UPDATE THE Baseline_Users.txt FILE IF NEEDED." -ForegroundColor Green
                                }
                        }
                    Else 
                        {
                        write-Host $date " - NO CHANGE" -NoNewline
                        }

                }  
        }
            
           