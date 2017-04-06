<# 
.SYNOPSIS
    Gets a table of services that are set to Automatic and are not started.

.PARAMETERS computer
    Used to feed a file containing names or IPs. A single IP can be used as well

.EXAMPLE
    PS C:\> .Get-AutoNotStartedServices.ps1 -computer c:\users\blue\desktop\computers.txt

    Runs the script on all systems in the 'coputers.txt' file.

#>


param(
    [Parameter(Mandatory=$true)][string]$Computer
)

Get-wmiobject win32_service -ComputerName $computer -Filter "startmode = 'Auto' AND state != 'running' "| select PSComputername, name, pathname, startname | Export-CSV .\Get-AutoNotStartedServices.csv -NoTypeInformation