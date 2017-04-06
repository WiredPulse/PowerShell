<#
    .SYNOPSIS  
        Updates Registry Keys

#>

$regupdate = "HKLM:\System\CurrentControlSet\Control\FileSystem"
$key = "NtfsDisableLastAccessUpdate"
$val = "0"
Set-ItemProperty $regupdate -Name $key -Value $val