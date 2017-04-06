<# 
.SYNOPSIS
    Starts a Splunk Forwarder. It also logs the status and start time to two local files.
#>

$computers = get-content C:\users\blue\Desktop\computers.txt
$service = "splunkforwarder"
$process_name = "splunkd"
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
    get-process -Name $process_name | select Name, StartTime | ft >> $start_times
    }