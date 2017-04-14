<#
.SYNOPSIS
    Takes in a single IP or a text file containing IPs and returns the hostname associated with them in DNS. Single IPs queries are returned to the console while multiple IP
    queries via a text file will be sent to .\IP-2-Hostname.csv.

.PARAMETER ip_address
    Used to specify a single IP or a text file containing multiple IPs.

.EXAMPLE
    PS C:\> .\Get-IP2Hostname -ip_address 172.16.155.201

    Returns the hostname associated with 172.16.155.201 to the console.

.EXAMPLE
    PS C:\> .\Get-IP2Hostname -ip_address c:\computers.txt

    Returns the hostname associated with the IPs in computers.txt to .\IP-2-Hostname.csv.

#>


param(
    [Parameter(Mandatory=$true)][string]$IP_Address
     )



# Parameters received at the start of running the script
if($IP_Address -like '*.txt')
    {
    Get-Content $IP_Address | %{ Get-HostName $_ } | Export-Csv .\IP-2-Hostname.csv -NoTypeInformation
    }
elseif($IP_Address -notcontains '.txt')
    {
    New-Object psobject -Property @{
        IPAddress = $ip_Address
        HostName = try { [system.net.dns]::GetHostByAddress($ip_Address).HostName } catch { "UNKNOWN" }
        }
    }
else{Echo 'No IP or a file containing IPs were specified'}