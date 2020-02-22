## Login/ logout
## new services
# RDP parser
<#
    Enable necessary audit entries
#>

AUDITPOL /SET /SUBCATEGORY:"Process Creation" /SUCCESS:enable /FAILURE:enable
AUDITPOL /SET /SUBCATEGORY:"Logon" /SUCCESS:enable /FAILURE:enable
AUDITPOL /SET /SUBCATEGORY:"Logoff" /SUCCESS:enable /FAILURE:enable
AUDITPOL /SET /SUBCATEGORY:"Other Logon/Logoff Events" /SUCCESS:enable /FAILURE:enable
AUDITPOL /SET /SUBCATEGORY:"Other Object Access Events" /SUCCESS:enable /FAILURE:enable
AUDITPOL /SET /SUBCATEGORY:"User Account Management" /SUCCESS:enable /FAILURE:enable
AUDITPOL /SET /SUBCATEGORY:"Security Group Management" /SUCCESS:enable /FAILURE:enable
AUDITPOL /SET /SUBCATEGORY:"Security System Extension" /SUCCESS:enable /FAILURE:enable


<#
    Login duration
#>
write-host -ForegroundColor yellow "[+] " -nonewline; write-host -ForegroundColor cyan "Getting necessary logs...this may take a minute..."
$logon = Get-WinEvent -FilterHashtable @{logname='security';id='4624'} | Sort-Object timecreated 
$logoff = Get-WinEvent -FilterHashtable @{logname='security';id='4634', '4647'}
write-host -ForegroundColor yellow "[+] " -nonewline; write-host -ForegroundColor cyan "Parsing events...this may take a minute..."
$obj = @{}
$obj = foreach($evtOff in $logoff){
    foreach($evtOn in $logon){
        if($evtOn.properties.value[7] -eq $evtOff.properties.value[3]){
            [pscustomobject]@{
                Account = $evtOn.properties.value[5]
                Logon = $evtOn.timecreated
                Logoff = $evtOff.timecreated
            }
        }
    }
}


<#
    Logins
#>
Get-WinEvent -FilterHashtable @{logname='security';id='4624'} |
    select timecreated, 
    @{Label="Account Name";Expression={$_.properties.value[5]}}, 
    @{Label="LogonType";Expression={$_.properties.value[8]}}, 
    @{Label="Process Name";Expression={$_.properties.value[17]}},
    @{Label="Process ID";Expression={$_.properties.value[16]}},
    @{Label="Elevated";Expression={if($_.properties.value[26] -eq '%%1842'){Write-Output "Yes"}elseif($_.properties.value[26] -eq '%%1843'){Write-Output "No"}}} | ogv


<#
    Logoff
#>
Get-WinEvent -FilterHashtable @{logname='security';id='4634'} |
    select timecreated, 
    @{Label="Account Name";Expression={$_.properties.value[1]}}


<#
    User sign out
#>
Get-WinEvent -FilterHashtable @{logname='security';id='4647'} |
    select timecreated, 
    @{Label="Account Name";Expression={$_.properties.value[1]}}

<#
    New services
#>
Get-WinEvent -FilterHashtable @{logname='security';id='4697'} |
    select timecreated, 
    @{Label="Account Name";Expression={$_.properties.value[1]}},
    @{Label="Service Name";Expression={$_.properties.value[4]}},
    @{Label="Binary";Expression={$_.properties.value[5]}}

<#
    User deleted
#>
Get-WinEvent -FilterHashtable @{logname='security';id='4726'} |
    select timecreated, 
    @{Label="Account Deleted";Expression={$_.properties.value[0]}},
    @{Label="Actioned By";Expression={$_.properties.value[4]}}

<#
    User created
#>
Get-WinEvent -FilterHashtable @{logname='security';id='4720'} |
    select timecreated, 
    @{Label="Account Created";Expression={$_.properties.value[0]}},
    @{Label="Actioned By";Expression={$_.properties.value[4]}}


<#
    User enabled
#>
Get-WinEvent -FilterHashtable @{logname='security';id='4722'} |
    select timecreated, 
    @{Label="Enabled Account";Expression={$_.properties.value[0]}},
    @{Label="Actioned By";Expression={$_.properties.value[4]}}


<#
    User disabled
#>
Get-WinEvent -FilterHashtable @{logname='security';id='4725'} |
    select timecreated, 
    @{Label="Disabled Account";Expression={$_.properties.value[0]}},
    @{Label="Actioned By";Expression={$_.properties.value[4]}}


<#
    User password reset attempt
#>
Get-WinEvent -FilterHashtable @{logname='security';id='4724'} |
    select timecreated, 
    @{Label="Enabled Account";Expression={$_.properties.value[0]}},
    @{Label="Actioned By";Expression={$_.properties.value[4]}}


<#
    User account changed
#>
Get-WinEvent -FilterHashtable @{logname='security';id='4738'} |
    select timecreated, 
    @{Label="Actioned By";Expression={$_.properties.value[5]}},
    @{Label="Target Account";Expression={$_.properties.value[1]}},
    @{Label="Username";Expression={$_.properties.value[9]}},
    @{Label="Display Name";Expression={$_.properties.value[10]}}


<#
    User account disabled
#>
Get-WinEvent -FilterHashtable @{logname='security';id='4725'} |
    select timecreated, 
    @{Label="Disabled Account";Expression={$_.properties.value[0]}},
    @{Label="Actioned By";Expression={$_.properties.value[4]}}


<#
    User group membership removed
#>
Get-WinEvent -FilterHashtable @{logname='security';id='4733'} |
    select timecreated, 
    @{Label="Group";Expression={$_.properties.value[2]}},
    @{Label="Account Removed";Expression={Get-CimInstance -ClassName win32_useraccount -filter "SID = "$_.properties.value[1]""}},
    @{Label="Actioned By";Expression={$_.properties.value[6]}}


<#
    User group membership added
#>
Get-WinEvent -FilterHashtable @{logname='security';id='4732'}


<#
    Process creations
#>
Get-WinEvent -FilterHashtable @{logname='security';id='4688'} | 
    Select-Object timecreated, 
    @{Label="Account";Expression={$_.properties.value[1]}}, 
    @{Label="Commandline";Expression={$_.properties.value[8]}}, 
    @{Label="ParentProcess";Expression={$_.properties.value[13]}}


<#
    System locked and unlocked
#>
Get-WinEvent -FilterHashtable @{logname='security';id='4800', 4801} | 
    Select-Object timecreated, 
    @{Label="Account";Expression={$_.properties.value[1]}}, 
    @{Label="Action";Expression={if($_.id -eq "4800"){Write-Output "Locked"}else{Write-Output "Unlocked"}}}

