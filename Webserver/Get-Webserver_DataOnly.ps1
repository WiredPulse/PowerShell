<#
This script will create a temporary webserver on the local system and will listen on the host IP 
and specified port. You will then be able to post some raw data that will be accessible on the network.  
When running the script you will be asked what port to listen on and what raw data you to post. This 
script does not supporting the posting of files or folders. 

The raw data can be accessed one of three ways.

Option 1: PowerShell -- Using the below syntax to view it on the screen. It will be in
the raw content section.
    Invoke-WebRequest http://<IP_Address>:<port>/default

Option 2: Powershell -- Using the below syntax to save the data to a local file
    Invoke-WebRequest http://<IP_Address>:<port>/default -OutFile downloaded_data.txt

Option 2: Internet browser -- Using the below syntaxto view it in the browser
    http://<IP Address>:<port>/default
#>

# gets IP address of the system
$ip = (gwmi Win32_NetworkAdapterConfiguration | ? { $_.IPAddress -ne $null }).ipaddress
# prompts user to input port
$port = Read-Host -Prompt  'List a port for this webserver to listen on'
# prompts user to input raw data they want to post to the webserver
$raw_data = Read-Host -Prompt 'Input the raw data that you want accessible'
$default_url = "default"

# "default" is the end of the URL (ex: http://192.168.0.2:8080/default)
$routes = @{
    "/default" = { return '<html><body>'+$raw_data+'</body></html>' }
}

$url = 'http://'+$ip+':'+$port+'/'
$listener = New-Object System.Net.HttpListener
$listener.Prefixes.Add($url)
$listener.Start()

Write-Host Listening at $url$default_url...

while ($listener.IsListening)
{
    $context = $listener.GetContext()
    $requestUrl = $context.Request.Url
    $response = $context.Response

    Write-Host ''
    Write-Host "> $requestUrl"

    $localPath = $requestUrl.LocalPath
    $route = $routes.Get_Item($requestUrl.LocalPath)

    if ($route -eq $null)
    {
        $response.StatusCode = 404
    }
    else
    {
        $content = & $route
        $buffer = [System.Text.Encoding]::UTF8.GetBytes($content)
        $response.ContentLength64 = $buffer.Length
        $response.OutputStream.Write($buffer, 0, $buffer.Length)
    }
    
    $response.Close()

    $responseStatus = $response.StatusCode
    Write-Host "< $responseStatus"
}

