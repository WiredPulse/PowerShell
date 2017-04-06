<#
.SYNOPSIS:
    Gets the Value data of specified Value.

.PARAMETER computername
    Used to specify a system to retrieve data from.

.EXAMPLE
    PS C:\> .\Get-RegValueData.ps1 -Computername 172.16.155.201
    
    Gets data from 172.16.155.201

.EXAMPLE
    PS C:\> .\Get-RegValueData.ps1 -ComputerName c:\users\blue\desktop\computers.txt 

    Gets data from systems listed in computers.txt

.NOTES
    When prompted for the registry path, use the example below:

        Example 1: hklm:\system\currentcontrolset\services\fax
        Example 2: hklm:\software\microsoft\windows nt\currentversion

#>


param(
    [Parameter(Mandatory=$true)][string]$ComputerName
     )

write-host "Input the path the the Value you want to retrieve data on" -ForegroundColor Cyan
$reg = read-host " "


$newline = "`r`n"

if (test-path .\regvalue.ps1)
    {
    remove-item .\regvalue.ps1
    }

# ==============================================================================
# Making script
# ==============================================================================
"Get-ItemProperty -path $reg" >> .\regvalue.ps1


# ==============================================================================
# Creating process call
# ==============================================================================
Function Call
    {
    foreach($computer in $cpu)
        {
        if (test-path \\$computer\c$\regvalue.ps1)
            {
            remove-item \\$computer\c$\regvalue.ps1
            }
        copy-item .\regvalue.ps1 \\$computer\C$\
        Invoke-WmiMethod -Class Win32_Process -Name Create -Computername $computer -ArgumentList "powershell.exe /c c:\regvalue.ps1 > c:\$computer.txt" >$null 2>&1
        Write-Host "Script initiated on $computer" -ForegroundColor green
        }
    sleep 25   
    }


# ==============================================================================
# Pulling data back
# ==============================================================================
Function Retrieve
    {
    foreach($computer in $cpu)
        {
        copy-item \\$computer\c$\$computer.txt .\
        $read = get-content .\$computer.txt
        $stripped_data =$read[2..($read.count - 4)]

        Write-Host "Data pulled back from $computer" -ForegroundColor cyan
        foreach ($data in $stripped_data)
            {
            $new_data += $computer + '+' + $data.Replace(' : ','+') + $newline
            }
        remove-item \\$computer\c$\$computer.txt
        remove-item \\$computer\c$\regvalue.ps1
        }
    }

# ==============================================================================
# Combining files into a csv
# ==============================================================================

#Function combine
#    {
#    add-content -Path ".\Reg.txt" -Value ($new_data)
#    Import-csv ".\reg.txt" -Delimiter '+' -Header 'System', 'Value', 'ValueData' | export-csv .\RegKeyList.csv
#    Remove-Item .\reg.txt
#    Remove-Variable new_data
#    Remove-Item .\regvalue.ps1
#    }



# ==============================================================================
# Parameters received at the start of running the script
# ==============================================================================
if($ComputerName -like '*.txt')
    {
    $cpu = Get-content $computername
    call
    retrieve
    combine
    }
elseif($ComputerName -notcontains '.txt')
    {
    $cpu = $ComputerName
    call
    retrieve
    combine
    }
else{Echo 'No IP or a file containing IPs were specified'}





