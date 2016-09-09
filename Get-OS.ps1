<#
    .SYNOPSIS  
        Retrieve Operating System version from a single system or a group of systems.

    .NOTES  
        File Name      : Get-OS.ps1
        Version        : v.0.1  
        Prerequisite   : PowerShell
        Created        : 06 MAY 16
     

    ####################################################################################


#>

function Get-OS
{
     param (
           [string]$Title = 'Get-OS'
     )
     cls
     Write-Host "================ $Title ================"
     
     Write-Host "1: Enter an IP"
     Write-Host "2: Read from a file"
     Write-Host " "
    $answer = read-host "Please Make a Selection"  
    if ($answer -eq 1)
        {
        $sServer = Read-host "Enter an IP"
        foreach($sProperty in $sServer)
            {
            Get-WmiObject -class Win32_OperatingSystem -computername $sProperty | select PSComputerName, Caption, OSArchitecture, ServicePackMajorVersion, Description | FT -AutoSize
            }
        }  
    if ($answer -eq 2)
        {
        $reading = Read-host "Enter the path to the text file containing a list of systems"
        $sServer = get-content $reading
        foreach($sProperty in $sServer)
            {
            Get-WmiObject -class Win32_OperatingSystem -computername $sProperty | select PSComputerName, Caption, OSArchitecture, ServicePackMajorVersion, Description | FT -AutoSize
            }
        }  
}

Get-OS