<#
.SYNOPSIS
    Takes in a text file containing hostnames and returns the IP associated with them in DNS. Results are sent to .\Hostname-2-IP.csv.

#>


Write-Host "Input path to text file containing hostnames" -ForegroundColor Cyan
$cpu_list = Read-Host ' '

if(Test-Path .\sat_ip_addresses.txt)
    {Remove-Item .\sat_ip_addresses.txt}


function Get-HostToIP($hostname) {     
    $result = [system.Net.Dns]::GetHostByName($hostname)     
    $result.AddressList | ForEach-Object {$hostname + ' ' + $_.IPAddressToString} 
} 
 
Get-Content $cpu_list | ForEach-Object {(Get-HostToIP($_)) >> .\sat_ip_addresses.txt}

import-csv ".\sat_ip_addresses.txt" -Delimiter ' ' -Header 'Hostname', 'IP' |export-csv .\Hostname-2-IP.csv

Remove-Item .\sat_ip_addresses.txt

