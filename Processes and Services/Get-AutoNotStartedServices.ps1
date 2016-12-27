# Gets a table of services that are set to Automatic and are not started.

$computers = Get-Content C:\users\blue\Desktop\computers.txt
Get-wmiobject win32_service -ComputerName $computers -Filter "startmode = 'Auto' AND state != 'running' "| select PSComputername, name, pathname, startname | Export-CSV .\Get-AutoNotStartedServices.csv -NoTypeInformation