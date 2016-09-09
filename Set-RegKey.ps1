<#
    .SYNOPSIS  
        Alter Registry Keys


    .NOTES  
        File Name      : Set-RegKey.ps1
        Version        : v.0.1  
        Author         : CW3 Tomlinson, Fernando
        Email          : fernando.c.tomlinson2.mil@mail.mil
        Prerequisite   : PowerShell
        Created        : 10 APRIL 16

    ####################################################################################

#>

$regupdate = "HKLM:\System\CurrentControlSet\Control\FileSystem"
$key = "NtfsDisableLastAccessUpdate"
$val = "0"
Set-ItemProperty $regupdate -Name $key -Value $val