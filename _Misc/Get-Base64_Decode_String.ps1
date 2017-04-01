<# 
.SYNOPSIS
    Decodes a Base64 string.

.PARAMETER decode
    String to Base64 decode.

.EXAMPLE
    PS c:\> .\Get-Base64_Decode_String.ps1 -decode aABhAG0AYgB1AHIAZwBlAHIA

    Decoding a Base64 string.
#>


param(
[Parameter(Mandatory=$true)][string]$decode
)

 
[System.Text.Encoding]::UTF8.GetString(([System.Convert]::FromBase64String($decode)|?{$_}))