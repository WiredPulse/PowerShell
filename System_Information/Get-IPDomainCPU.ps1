<#
.SYNOPSIS
    Returns IP and operating system for all computers in a domain

#>

Get-ADComputer -Filter * -Properties ipv4Address, OperatingSystem, OperatingSystemServicePack | Format-table name, ipv4*, oper*| Out-GridView