Function Get-PortScan {

<# 
.SYNOPSIS
    Scans a range of IPs and informs you if a specific port is listening. 

.PARAMETER port
    Port to scan.

.PARAMETER net
    Network ID. Ex: 172.16.155.

.PARAMETER start
    IP to start with... only input the last octect. Ex: .10.
    
.PARAMETER end
    IP to end with... only input the last octect. Ex: .30.

.EXAMPLE
    PS c:\> Get-PortScan
                    Input a port to scan:    135
                    Input a Network to scan (first three octects):    172.16.155
                    Input a starting range (last octect only):    10
                    Input an ending range (last octect only):    30

    Executing the script and answer the following questions with the above would scan 172.16.155.10 - 172.16.155.30 to see
    if port 135 is listening.
#>


$port = read-host "Input a port to scan"
$net =  read-host "Input a Network to scan (first three octects)"
$start = read-host "Input a starting range (last octect only)"
$end = read-host "Input an ending range (last octect only)"

$range = $start..$end

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

}