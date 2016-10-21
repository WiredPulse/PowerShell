# Retarts the Splunk Forwarder service. It also logs the status and start time to two local files.

$computers = get-content C:\users\blue\Desktop\computers.txt
$service = "splunkforwarder"
$process_name = "splunkd"
$service_stat = "service_status.txt"
$start_times = "service_start_time.txt"

# Gets the start time of a process, which is tied to a service
foreach($computer in $computers){
restart-service -name $service
get-service -name $service | restart-service
sleep 4
echo $computer >> $start_times
get-process -Name $process_name | select Name, StartTime | ft >> $start_times
}

# Gets the status of a service
get-service -computername $computers -name $service| Select MachineName, Name, Status  | ft -AutoSize >> $service_stat