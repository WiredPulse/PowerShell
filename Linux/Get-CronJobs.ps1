
$users = get-content /etc/passwd
$obj = @()
$obj = foreach($user in $users){
    $user = $user -split ':'
    $task = crontab -u $user[0] -l 2>&1
    if($task -notlike "no*"){
        foreach($userTask in $task){
            $settings = $usertask -split ' '
            [PSCustomObject]@{
                User = $user[0]
                Minute = $settings[0]
                Hour = $settings[1]
                DayOfMonth = $settings[2]
                Month = $settings[3]
                DayOfWeek = $settings[4]
                Command = $settings[5..$settings.length[-1]] -join ' '
            }
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

$obj
