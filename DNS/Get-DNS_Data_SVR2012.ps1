# Retrieves relevant DNS data in Server 2012. The output of each is saved in a newly created DNS folder right off of where this script is ran from.

New-Item .\DNS_Data -type directory
Set-Location DNS

Get-DNSServerStatistics | out-file .\Stats.txt
Get-DnsServer | out-file .\Server_Info.txt
Get-DnsServerDiagnostics | out-file .\Server_Diag.txt
Get-DnsServerDsSetting | out-file .\DirecotyrServices_Settings.txt
Get-DnsServerForwarder | out-file .\Forwarders.txt
Get-DnsServerGlobalNameZone | out-file .\Global_Name_Zone.txt

# The block list automatically applies to all zones for which the server is authoritative. For example, if the DNS server is authoritative for contoso.com and for europe.contoso.com, it ignores queries for wpad.contoso.com as well as for wpad.europe.contoso.com. However, the DNS Server service does not ignore queries for names in zones for which it is not authoritative. 

<# Identify the items in the list. If you want to add more to the list, take note of the items currently listed and as adding more will overwrite the current ones listed. With that said, you will need to add the current ones listed with the additional ones you want to add. To add to the list, use the following syntax:
	dnscmd /config /globalqueryblocklist WKGA1023, wpad, isatap
#>
dnscmd /info /globalqueryblocklist | out-file .\Blocked_items.txt

# Determines if the blocklist is enabled or not. "1" = enabled, "0" = disabled
dnscmd /info /enableglobalqueryblocklist | out-file .\Blocklist_status.txt

# Gets DNS information
dnscmd.exe /info | out-file .\DNS_Info.txt

Get-DnsServerRecursion | out-file .\Recursion.txt
Get-DNSServerRootHint | out-file .\Roothints.txt
Get-DnsServerScavenging | out-file .\Scavenging.txt
Get-DnsServerSetting | out-file .\Server_Settings.txt
Get-DnsServerZone | out-file .\Zones.txt

get-wmiobject -Namespace root\MicrosoftDNS -class microsoftdns_resourcerecord | select __Class, ContainerName, DomainName, RecordData, ownername | Export-CSV ./All_Records.csv

