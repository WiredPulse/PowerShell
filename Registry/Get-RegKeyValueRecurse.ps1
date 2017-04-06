<#
.SYNOPSIS
    Recursively gets Sub-Keys, Values, and Value data of a specified Key.
#>

write-host "Input computer name or IP to grab Registry data from" -ForegroundColor cyan
$cpu = read-host " "

write-host "Input the registry path to grab data from." -ForegroundColor cyan
write-host " "
write-host "         Example: SYSTEM\CurrentControlSet\Services\w32time" -ForegroundColor Green
write-host "         Example: SOFTWARE\Microsoft\Windows NT\CurrentVersion" -ForegroundColor Green
write-host " "
$regpath = read-host " "

# Registry data to retrieve
$reg = $regpath.split('\') | select -last 1
$Filter = ".*"
$newline = "`r`n"

# Loops through and recursively gets Sub-Keys, Value, and Value data for a Key
function Grab-SystemKeys 
    {
    Param($regkey,$Server)
    $ServerKey = 
    [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey("LocalMachine", $Cpu)
    $SubKey = $ServerKey.OpenSubKey($regkey,$false)
    If(!($SubKey))
        {
        Return
        }
    $SubKeyValues = $SubKey.GetValueNames()
    if($SubKeyValues)
        {
        foreach($SubKeyValue in $SubKeyValues)
            {
            $subber = $subkey.name
            $vall = $_
            $Key = @{n="Key";e={$SubKey.Name -replace "HKEY_LOCAL_MACHINE\\",""}}
            $ValueName = @{n="ValueName";e={$SubKeyValue}}
            $Value = @{n="Value";e={$_}}
            $SubKey.GetValue($SubKeyValue) | ?{$_ -match $filter} | Select-Object $Key,$ValueName,$Value 
            }
        }
    $SubKeyName = $SubKey.GetSubKeyNames()
    foreach($subkey in $SubKeyName)
        {
        $SubKeyName = "$regkey\$subkey"
        Grab-SystemKeys $SubKeyName
        }
    }

foreach($path in $regpath)
    {
    Write-Host "Getting $path Keys..." -ForegroundColor Cyan
    Grab-SystemKeys $path $cpu | out-file .\$cpu'_'$reg.txt 2>$null 
    }

