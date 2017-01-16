<#
SYNOPSIS:
    Recursively gets Sub-Keys, Values, and Value data of a specified Key. Resturned data is ouput to a CSV that is bes analyzed using "out-gridview" in PowerShell.
#>

# Variable to change
$Cpu = $env:computerName

# Don't touch
$regpath = "BCD00000000", "HARDWARE", "SOFTWARE", "SYSTEM" 
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

# Loops through Keys (BCD*, HARDWARE, SOFTWARE, and SYSTEM) and ouputs results. Text file can be converted to CSV later. It is text now due to formatting for the next stage. 
foreach($path in $regpath)
    {
    Write-Host "Getting $path Keys..." -ForegroundColor Cyan
    Grab-SystemKeys $path $cpu | out-file .\$cpu'_'$path.txt 2>$null 
    }

