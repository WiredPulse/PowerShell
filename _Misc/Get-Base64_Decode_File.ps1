<# 
.SYNOPSIS
    Decodes a Base64 string into a file.

.PARAMETER b64_string
    Base64 string to decode.

.PARAMETER output_file
    Name of file to convert Base64 encoded string to.

.EXAMPLE
    PS c:\> .\Get-Base64_Encode_String.ps1 -b64_string 'MTcyLjE2LjE1NS4yMDANCjE3Mi4xNi4xNTUuMjAxDQoxNzIuMTYuMTU1LjIwMw==' -output_file c:\text.txt

    Decodes specified string into a file called "text.txt".
#>


param(
[Parameter(Mandatory=$true)][string]$B64_string,
[Parameter(Mandatory=$true)][string]$Output_file
)


$bytes = [Convert]::FromBase64String($b64_string)
[IO.File]::WriteAllBytes($Output_file, $bytes)