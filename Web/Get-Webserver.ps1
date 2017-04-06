<#
.SYNOPSIS
    This script will deploy a temporary webserver on the local system and will listen of the port of you choice. Once it is listening, you will be able to 
    transfer .txt and .html files from the directory in which the script is ran from (not located). The webserver will continue to run as long as the script is running.

    To execute, run the script and when prompted, input a port to listen on. To access the system and the data in the directory that the script ran from, use the below syntax.

.EXAMPLE
    Invoke-WebRequest http:/<IP_Address>:<port>/file_in_dir.txt -OutFile <downloaded file>

    Invoke-WebRequest http:/192.168.1.1:8001/passwords.txt -OutFile passwords.txt
#>

# gets IP address of the system
$ip = (gwmi Win32_NetworkAdapterConfiguration | ? { $_.IPAddress -ne $null }).ipaddress
# prompts user to input port
$port = Read-Host -Prompt  'List a port for this webserver to listen on'

$Hso = New-Object Net.HttpListener
$Hso.Prefixes.Add('http://'+$ip+':'+$port+'/')
$Hso.Start()

$url = 'http://'+$ip+':'+$port+'/'

Write-Host Listening at $url ...

While ($Hso.IsListening) {
    $HC = $Hso.GetContext()
    $HRes = $HC.Response
    # Various cont types can be found here -> https://msdn.microsoft.com/en-us/library/ms526971(v=exchg.10).aspx
    $HRes.Headers.Add("Content-Type","text/html")
    $Buf = [Text.Encoding]::UTF8.GetBytes((GC (Join-Path $Pwd ($HC.Request).RawUrl)))
    $HRes.ContentLength64 = $Buf.Length
    $HRes.OutputStream.Write($Buf,0,$Buf.Length)
    $HRes.Close()
}
$Hso.Stop()