# Gets the environment paths from group of systems and outputs the data as a csv

$computers = Get-Content C:\users\blue\Desktop\computers.txt
Get-WMIObject -Class Win32_Environment -Namespace root\cimv2 -filter "Name = 'Path'" -ComputerName $computers | select PSComputerName, VariableValue | Export-CSV .\tt.csv -NoTypeInformation
   