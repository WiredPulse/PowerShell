$users = get-content /etc/passwd
foreach($user in $users){
    $user = $user -split ':'
    crontab -u $user[0] -l
}
