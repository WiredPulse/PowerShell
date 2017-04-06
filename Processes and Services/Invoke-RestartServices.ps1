<# 
.SYNOPSIS
    Restarts a specifiec service and logs the status along with the start time. Start time and status are written to two local files.

.PARAMETER computer
    Used to feed the script a file containing computer names or IPs. A single IP can be used as well.

.PARAMETER service
    Used to specify a service name.

.PARAMETER process
    Used to specify a process name.

.EXAMPLE
    PS C:\> .\Invoke-RestartServices.ps1 -computer c:\computers.txt -service 'splunkforwarder service' -process 'splunkd'

    Restarts the splunk service and logs the time the service and process restarted.
#>


param(
    [Parameter(Mandatory=$true)][string]$Computer,
    [Parameter(Mandatory=$true)][string]$Service,
    [Parameter(Mandatory=$true)][string]$Process
    )

$service_stat = "service_status.txt"
$start_times = "service_start_time.txt"

# Gets the start time of a process, which is tied to a service
foreach($computer in $computers)
    {
    restart-service -name $service
    get-service -name $service | restart-service
    sleep 4
    echo $computer >> $start_times
    get-process -Name $process | select Name, StartTime | ft >> $start_times
    }

# Gets the status of a service
get-service -computername $computers -name $service| Select MachineName, Name, Status  | ft -AutoSize >> $service_stat