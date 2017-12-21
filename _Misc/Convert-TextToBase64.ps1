Function Convert-TextToBase64 {

<# 
.SYNOPSIS
    Base64 encodes inputted data.

.PARAMETER encode
    String to Base64 encode.

.EXAMPLE
    PS c:\> Convert-TextToBase64 -encode hamburger

    Base64 encoding the string "hamburger".
#>


param(
[Parameter(Mandatory=$true)][string]$encode
)


$bytes = [system.text.encoding]::unicode.getbytes($encode)
$encodedCommand = [convert]::ToBase64String($bytes) 
$encodedCommand

}