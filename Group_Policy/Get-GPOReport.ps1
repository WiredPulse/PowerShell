<#
.SYNOPSIS  
    Retrieves all GPOs in the domain and their settings. The data is saved to a html file. 


#>

Import-Module GroupPolicy
Get-GPOReport -All -ReportType HTML | out-file .\GPOReport.html
