<#
.SYNOPSIS
    Retrieves the OS architecture or the supplied systems
#>

write-host 'Input the path to the list of systems to retrieve the OS architecture for.' -ForegroundColor Cyan
$list = read-host " "

Get-WmiObject Win32_OperatingSystem -computername $list | select PSComputerName, OSArchitecture