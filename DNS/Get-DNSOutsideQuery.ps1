<#
.SYNOPSIS
    This script finds all DNS queries that didnt come from domain controllers. The results will show the count and source IP.

.OUTPUT
    Produces a the following files:
        .\DNSOutsideQuery.csv
        .\DNSOutsideWuery_hostnames.csv

#>

#### Variable to Change #####
# Create a pipe separated list of domain controllers in your domain, this will negate them from the search.
$listOfDCs = "192.168.0.40|192.168.5.20|192.168.10.60"
$loopbackIPv6 = [regex]::Escape("::1")
 
$myResults = @()
Get-Content .\dns.log | ?{$_ -match ' PACKET  ' -and $_ -match "UDP Rcv " -and $_ -notmatch $listOfDCs -and $_ -notmatch $loopbackIPv6} | %{
  $sourceIP = (($_ -split("UDP Rcv "))[1] -split(" "))[0]
  $myResults += New-Object psobject -Property @{
    SourceIP = $sourceIP
    FullLine = $_
  } 
}


$myResults | Group-Object -Property SourceIP | Sort-Object Count -Descending | export-csv .\DNSOutsideQuery.csv


$myResults | Group-Object -Property SourceIP | Sort-Object Count -Descending | %{
  $sourceName = try { [system.net.dns]::GetHostByAddress($_.Name).HostName } catch { "UNKNOWN" }
  New-Object psobject -property @{
    HostName = $sourceName
    IP = $_.Name
    Count = $_.Count
  }
} | export-csv .\DNSOutsideQuery_hostnames.csv
