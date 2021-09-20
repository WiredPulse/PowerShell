$systemctl = systemctl list-units --type=service --no-legend --all #| select -skip 2 -first 4

$obj = @()
$obj = foreach($sys in $systemctl){
    $sys = $sys -split '\s+',5
    $stat = service $sys[0] status 2>&1
    $time = $path = ''
    if($sys[2] -eq 'active'){
        $active = $true
    }
    else{
        $active = $false
    }
    foreach($item in $stat){
        if($item -like "*active:*"){
            $time = ($item -split '\s+')[6..7] -join ' '
        }
        if($item -like "*main pid*"){
            $id = ($item -split '\s+')[3]
        }
        if($item -like "*$id*/*"){
            $path = ($item -split '[0-9] ')[-1]
        }
    }
    [PSCustomObject]@{
        Name = $sys[0]
        PID = $id
        Path = $path
        State = $sys[1]
        Active = $active
        Status = $sys[3]
        StartTime = $time
        Description = $sys[-1]
    }
}

$obj
