<# 
.SYNOPSIS
    Convert a Base64 string to plain text.

.PARAMETER decode
    String to Base64 decode.

.EXAMPLE
    PS c:\> .\Convert-Base64ToText.ps1 -decode aABhAG0AYgB1AHIAZwBlAHIA

    Convert a Base64 string to plain text.
#>


param(
[Parameter(Mandatory=$true)][string]$decode
)

 
[System.Text.Encoding]::UTF8.GetString(([System.Convert]::FromBase64String($decode)|?{$_}))