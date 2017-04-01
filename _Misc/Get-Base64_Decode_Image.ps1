<# 
.SYNOPSIS
    Decodes a Base64 string into an image.

.PARAMETER b64_string
    Base64 string to decode.

.PARAMETER output_file
    Name of image file to convert Base64 encoded string to. The script was tested with jpg and png; other formats may work.

.EXAMPLE
    PS c:\> .\Get-Base64_Decode_Image.ps1 -b64_string 'MTcyLjE2LjE1NS4yMDANCjE3Mi4xNi4xNTUuMjAxDQoxNzIuMTYuMTU1LjIwMw==' -output_file c:\my_pic.png

    Decodes specified string into an image called "my_pic.png".
#>


param(
[Parameter(Mandatory=$true)][string]$B64_string,
[Parameter(Mandatory=$true)][string]$Output_file
)


$imageBytes = [Convert]::FromBase64String($b64String)
$ms = New-Object IO.MemoryStream($imageBytes, 0, $imageBytes.Length)
$ms.Write($imageBytes, 0, $imageBytes.Length);
$image = [System.Drawing.Image]::FromStream($ms, $true)
$image.Save("$output_file")