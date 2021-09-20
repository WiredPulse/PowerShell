$users = get-content /etc/passwd
$obj = @()
$obj = foreach($user in $users){
    $user = $user -split ':'
    $task = crontab -u $user[0] -l 2>&1
    if($task -notlike "no*"){
        $settings = $task[0..8]
        [PSCustomObject]@{
            User = $user[0]
            Minute = $settings[0]
            Hour = $settings[2]
            DayOfMonth = $settings[4]
            Month = $settings[6]
            DayOfWeek = $settings[8]
            Command = $task[10..$task.length[-1]] -join ''
        }
    }
    else{
        [PSCustomObject]@{
            User = $user[0]
            Minute = "None"
            Hour = "None"
            DayOfMonth = "None"
            Month = "None"
            DayOfWeek = "None"
            Command = "None"
        }
    }
}
