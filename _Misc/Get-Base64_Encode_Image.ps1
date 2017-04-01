<# 
.SYNOPSIS
    Generates a Base64 encoded string from an image file.

.PARAMETER input_file
    Name of file to convert to Base64.

.EXAMPLE
    PS c:\> .\Get-Base64_Encode_Image.ps1 -input_file c:\my_pic.png

    Encodes "my_pic.png" in a Base64 string.
#>


param(
[Parameter(Mandatory=$true)][string]$Input_file
)


$image = [System.Drawing.Image]::FromFile("$Input_file")
$ms = New-Object IO.MemoryStream
$image.Save($ms, "png")
$imageBytes = $ms.ToArray()
$b64String = [Convert]::ToBase64String($imageBytes)
$b64String