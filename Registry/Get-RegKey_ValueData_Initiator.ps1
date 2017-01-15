<#
    .SYNOPSIS:
        Gets the Value and Value data of a agent Registry Keys. Data from multiple systems is returned in one csv.

    .USAGE:
        - Change the variables in line 11 and 12
        - Execute the script from an evalated prompt with WMI access

#>
# ==============================================================================
# Variables to change
# ==============================================================================
$scriptpath = 'c:\users\blue\desktop'
$script2run = 'Get-RegValues.ps1'
$newline = "`r`n"


# ==============================================================================
# Creating process call
# ==============================================================================
foreach($computer in $computers)
    {
    copy-item $scriptpath\$script2run \\$computer\C$\.
    Invoke-WmiMethod -Class Win32_Process -Name Create -Computername $computer -ArgumentList "powershell.exe /c c:\$script2run > c:\$computer.txt" >$null 2>&1
    Write-Host "Script initiated on $computer" -ForegroundColor green
    }

sleep 5

# ==============================================================================
# Pulling data back
# ==============================================================================
foreach($computer in $computers)
    {
    copy-item \\$computer\c$\$computer.txt .\
    $read = get-content .\$computer.txt
    $stripped_data =$read[2..($read.count - 4)]

    Write-Host "Data pulled back from $computer" -ForegroundColor cyan
    #remove-item \\$computer\c$\$computer.txt
    #remove-item \\$computer\c$\get-regvalues.ps1
    foreach ($data in $stripped_data)
        {
        $new_data += $computer + '+' + $data.Replace(' : ','+') + $newline
        }
    }

# ==============================================================================
# Combining files into a csv
# ==============================================================================
add-content -Path ".\Reg.txt" -Value ($new_data)
Import-csv ".\reg.txt" -Delimiter '+' -Header 'System', 'Value', 'ValueData' | export-csv .\RegKeyList.csv
Remove-Item .\reg.txt


