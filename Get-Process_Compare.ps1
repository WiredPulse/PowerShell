<# Compares two different process list and spits out the difference. 
To get the baseline process list, you would run the following:
     Get-Process | Export-CliXML reference.xml
That will save the current running processes to a file called reference.xml. Utilizing the below script, it will read back in the reference.xml file and compare the difference with the current running processes. The results of those actions will be displayed to the screen depicting the differences.
#>

$compare_2 = diff -reference (import-clixml .\reference.xml) -difference (get-process) -property Name
Write-Host " " " ** LEGEND **" -fore yellow -back green
Write-Host "=> : In the new file, not in the baseline" -fore yellow -back green
Write-Host "<= : In the baseline, not in the new file" -fore yellow -back green | ft -autosize
$compare_2