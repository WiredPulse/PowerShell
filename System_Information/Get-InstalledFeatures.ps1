<#
.SYNOPSIS  
    Retrieves installed features from a server OS.This script will only work on a server OS.
#>


Import-Module ServerManager
Get-WindowsFeature | Where-Object {$_.Installed -match "True"} | Select-Object -ExpandProperty Name
	