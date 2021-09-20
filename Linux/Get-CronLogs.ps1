$logs = Get-Content "/var/log/cron"
$obj = @()
$obj = foreach($log in $logs){
    $logSplit = $log.Split(' ',6)
    if($log -like "*: (*)*" ){
        $logSplit2 = $logSplit[-1].Split(' ',2)
        [PSCustomObject]@{
            Date = $log[0..5] -join ''
            Time = $log[7..14] -join ''
            Hostname = $logSplit[3]
            Deamon = ($logSplit[4] -split '\[' -split '\]')[0]
            PID = ($logSplit[4] -split '\[' -split '\]')[1]
            User = ($logSplit2[0]).Trim('\(').Trim('\)')
            Command = $logSplit2[1]
        }
    }
    else{
        [PSCustomObject]@{
            Date = $log[0..5] -join ''
            Time = $log[7..14] -join ''
            Hostname = $logSplit[3]
            Deamon = ($logSplit[4] -split '\[' -split '\]')[0]
            PID = ($logSplit[4] -split '\[' -split '\]')[1]
            User = "N/A"
            Command = $logSplit[-1]
        }   
    }
}

$obj
