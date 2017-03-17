# Takes encoded Base64 string and decodes it.

Write-host -ForegroundColor cyan "Input Base64 string to decode"
$base64string = read-host " " 
[System.Text.Encoding]::UTF8.GetString(([System.Convert]::FromBase64String($base64string)|?{$_}))