$packages = rpm -qa --last
$obj = @()
$obj = foreach($package in $packages){
    $package = $package -split '\s+'
    [PSCustomObject]@{
        Date = $package[2..4] -join ' '
        Time = $package[5..7] -join ' '
        Package = $package[0]
    }
}

$obj
