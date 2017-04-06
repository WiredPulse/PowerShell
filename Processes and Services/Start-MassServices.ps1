<# 
.SYNOPSIS
    Starts a specifiec service and logs the status along with the start time. Start time and status are written to two local files.

.PARAMETER computer
    Used to feed the script a file containing computer names or IPs. A single IP can be used as well.

.PARAMETER service
    Used to specify a service name.

.PARAMETER process
    Used to specify a process name.

.EXAMPLE
    PS C:\> .\Start-MassServices.ps1 -computers c:\computers.txt -service 'splunkforwarder service' -process 'splunkd'

    Restarts the splunk service and logs the time the service and process restarted.
#>

param(
    [Parameter(Mandatory=$true)][string]$Computers,
    [Parameter(Mandatory=$true)][string]$Service,
    [Parameter(Mandatory=$true)][string]$Process
    )


$service_stat = "service_status.txt"
$start_times = "service_start_time.txt"

# Starts service
get-service -computername $computers -name $service | start-service

# This is an alternate method in case the above doesn't work.
#get-service -computername $computer -name $service | Set-service -Status running

# Gets the status of a service (stopped or running)
get-service -computername $computers -name $service | Select MachineName, Name, Status   | ft -AutoSize  >> $service_stat

# Gets the start time of a proces,s which is tied to a service
foreach($computer in $computers)
    {
    echo $computer >> $start_times
    get-process -Name $process | select Name, StartTime | ft >> $start_times
    }