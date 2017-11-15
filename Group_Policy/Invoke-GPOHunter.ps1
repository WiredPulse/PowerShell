<#
.SYNOPSIS
    Enables an individual to be able to search Group Policy for Scheduled Tasks and logon/logoff scripts. The returned output will highlight which GPO 
    contains the settings we are looking for along with some additional details regarding the settings.   

.USAGE
    1. Run script
    2. Analyze results that are returned to the screen
#>


Import-Module grouppolicy
$ErrorActionPreference ='silentlycontinue'

# Key strings for scheduled tasks and logon/logoff scripts
$schedtasks = "scheduledtask"
$on_off = "command>"

$DomainName = $env:USERDNSDOMAIN
$GPOs = Get-GPO -All -Domain $DomainName
write-host "Finding all the GPOs in $DomainName"

# Search through each GPO's XML for the specific strings
Write-Host "Starting search...."
foreach ($gpo in $GPOs) 
    {
    $report = Get-GPOReport -Guid $gpo.Id -ReportType Xml
    if (($report -match $schedtasks) -or ($report -match $on_off)) 
        {
        write-host "********** Match(es) found in: $($gpo.DisplayName) **********"
        $report1 = $report -split ' '| sls 'name=', 'starthour=', 'args=','startIn=', 'comment=', 'filters'| Get-Unique
        $report2 = $report -split ' '| sls 'command>'

        if ($report1 -ne $null)
            {
            "#######################"
            "#   SCHEDULEDTASKS    #"   
            "#######################"   

             $report_out = ($report1 -replace '"',"")
             for ($i=6;$i -lt $report_out.count;$i+=7) 
                {
                $report_out[$i] = ' '
                }
             $report_out
            "#######################"
            " "
            }
        if ($report2 -ne $null)
            {
            $r2 = [string]$report2
            "#############################"
            "#   LOGON / LOGOFF SCRIPTS  #"   
            "#############################"
            ($r2.Split('<')).split('>')[2,6,10,14,18,22,26,30,34]
            "#############################"
            " "
            }
        }
    }
