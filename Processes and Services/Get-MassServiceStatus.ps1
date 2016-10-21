<# 
Checks for the status of a service and logs the status along with the start time to two local files.
 
Input the service and process name on lines 8 and 9.
#>

$computers = get-content C:\users\blue\Desktop\computers.txt
$service = " "
$process_name = " "
$service_stat = "service_status.txt"
$start_times = "service_start_time.txt"

# Gets the status of a service
get-service -computername $computers -name $service| Select MachineName, Name, Status  | ft -AutoSize >> $service_stat

# Gets the start time of a process, which is tied to a service
foreach($computer in $computers){
echo $computer >> $start_times
get-process -Name $process_name | select Name, StartTime | ft >> $start_times
}