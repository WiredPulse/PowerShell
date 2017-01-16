<#
SYNOPSIS:
    Recursively gets Sub-Keys, Values, and Value data of a specified Key. Resturned data is ouput to a CSV that is bes analyzed using "out-gridview" in PowerShell.

USAGE:
    Change variables in line 9 and 10.
#>

$Cpu = $env:computerName
$regpath = "SYSTEM\CurrentControlSet"

$Filter = ".*"
$newline = "`r`n"

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

Write-Host "Getting $path Keys..." -ForegroundColor Cyan
Grab-SystemKeys $path $cpu | out-file .\$cpu'_'$path.txt 2>$null 

foreach($d_data in $data)
    {
    $c_data += $system + $d_data + $newline
    $combine_data = $c_data -replace('; ','+') -replace('@{Key=','+') -replace('ValueName=','') -replace('Value=','') -replace('}+','')
    }

Clear-Variable c_data
$combine_data |out-file .\data.txt
import-csv ".\data.txt" -Delimiter '+' -Header 'System', 'Key', 'ValueName', 'Value' |export-csv .\RegData.csv


