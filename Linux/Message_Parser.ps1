$logs = get-content "/var/log/secure"
$obj = @()
$obj = foreach($log in $logs){
    $log = $log -split "]: "
    $data = ($log[0] -split "\[") -split '\s+'
    [PSCustomObject]@{
        Time = ($data[0..2]) -join ' '
        Process = $data[4]
        ID = $data[-1]
        Message = $log[1]
    }
}

$obj
