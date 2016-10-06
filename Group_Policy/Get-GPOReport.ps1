
<#
    .SYNOPSIS  
        Retrieves all GPOs in the domain and their settings. The data is saved to a html file. This script needs to be ran on a system 
        with RSAT installed or the server itself.

    .NOTES  
        File Name      : Get-GPOReport.ps1
        Version        : v.0.1  
        Prerequisite   : PowerShell
        Created        : 08 JULY 16


    ####################################################################################

#>

Import-Module GroupPolicy
Get-GPOReport -All -ReportType HTML -Path .\GPOReport.html
