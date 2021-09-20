# Scriptblock
$logs = get-content "/var/log/messages"
$obj = @()
$obj = foreach($log in $logs){
    $logSplit = $log -Split '#012'
    $time = ($logSplit[0] -Split ' CentOS')[0]

    [PSCustomObject]@{
        Time = $time
        Command = $logSplit[1]
    }
}

$obj
