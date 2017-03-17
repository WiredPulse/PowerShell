# Base64 encodes inputted data

Write-host -ForegroundColor cyan "Input data to Base64 encode"
$command = read-host " "
$bytes = [system.text.encoding]::unicode.getbytes($command)
$encodedCommand = [convert]::ToBase64String($bytes) 
$encodedCommand