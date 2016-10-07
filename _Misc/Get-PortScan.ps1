<#
    .SYNOPSIS  
        Port scanner that informs you if an IP is listening on a specified port.

    ####################################################################################

#>


$port = 135
$net = “192.168.0”
$range = 127..129

foreach ($r in $range)

{

 $ip = “{0}.{1}” -F $net,$r

 if(Test-Connection -BufferSize 32 -Count 1 -Quiet -ComputerName $ip)
   {
     $socket = new-object System.Net.Sockets.TcpClient($ip, $port)
     If($socket.Connected)
       {
        “$ip is listening on port $port”
        $socket.Close() }
         }
 }

