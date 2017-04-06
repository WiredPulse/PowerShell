<# 
.SYNOPSIS
    Checks for the status of a specified service and logs the status of the servicee start time to two local files.

.PARAMETER computer
    Used to feed the script a file containing computer names or IPs. A single IP can be used as well.

.PARAMETER service
    Used to specify a service name.

.PARAMETER process
    Used to specify a process name.

.EXAMPLE
    PS C:\> .\Get-MassServiceStatus.ps1 -computer c:\computers.txt -service 'splunkforwarder service' -process 'splunkd'

#>


param(
    [Parameter(Mandatory=$true)][string]$Computer,
    [Parameter(Mandatory=$true)][string]$Service,
    [Parameter(Mandatory=$true)][string]$Process
    )


$service_stat = "service_status.txt"
$start_times = "service_start_time.txt"

# Gets the status of a service
get-service -computername $computer -name $service| Select MachineName, Name, Status  | ft -AutoSize >> $service_stat

# Gets the start time of a process, which is tied to a service
foreach($cpu in $computer)
    {
    echo $cpu >> $start_times
    get-process -Name $process | select Name, StartTime | ft >> $start_times
    }