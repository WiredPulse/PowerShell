<#
.SYNOPSIS
    Gets a list of all software installed on a local or remote system.

#>

param(
    [Parameter(Mandatory=$true)][string]$ComputerName
    )

function software{
    Get-WmiObject -Class win32_product -ComputerName $cpu | select PSComputername, Name, PackageCache, Vendor, Version, IdentifyingNumber | Export-CSV .\Software.csv -NoTypeInformation
    }


# Parameters received at the start of running the script
if($ComputerName -like '*.txt')
    {
    $cpu = Get-content $computername
    software
    }
elseif($ComputerName -notcontains '.txt')
    {
    $cpu = $ComputerName
    software
    }
else{Echo 'No IP or a file containing IPs were specified'}