<#
    .SYNOPSIS  
        Retrieves installed features from a server OS.This script will only work on a server OS.

    .NOTES  
        File Name      : Get-InstalledFeatures.ps1
        Version        : v.0.1  
        Prerequisite   : PowerShell
        Created        : 06 July 16
     

    ####################################################################################

#>


Import-Module ServerManager
Get-WindowsFeature | Where-Object {$_.Installed -match "True"} | Select-Object -ExpandProperty Name
	