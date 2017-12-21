Function Invoke-IPScanner{

<# 
.SYNOPSIS
    Asynchronous IP range scanner (ping sweep).  

.PARAMETER net
    First three octects of the IP range.

.PARAMETER startrange
    Octect to start with.

.PARAMETER endrange
    Octect to end with.

.EXAMPLE
    PS c:\> Invoke-IPScanner -net '192.168.0' -startrange '80' -endrange '127'

    Scans 192.168.080 - 192.168.0.127".

.LINKS
    http://www.sherweb.com/blog/fun-with-powershell-the-less-than-simple-way-to-scan-an-ip-range/
#>


param(
[Parameter(Mandatory=$true)][string]$Net,
[Parameter(Mandatory=$true)][int]$StartRange,
[Parameter(Mandatory=$true)][int]$EndRange
)

 
# define the range  

#[string]$firstThree = “192.168.1”  
#[int]$startRange = 165  
#[int]$endRange = 175  

# defines how many IPs to scan at a time. Used to limit the amount of resources used by the scan.  
$groupMax = 50  
 
# start the range scan as jobs  
$count = 1  
$startRange..$endRange | %{  
        # start a test-connection job for each IP in the range, return the IP and boolean result from test-connection  
        start-job -ArgumentList “$firstThree`.$_” -scriptblock { $test = test-connection $args[0] -count 2 -quiet; return $args[0],$test } | out-null  
        # sleep for 3 seconds once groupMax is reached. This code helps prevent security filters from flagging port traffic as malicious for large IP ranges.  
        if ($count -gt $groupMax) {  
            sleep 3  
            $count = 1  
        } else {  
            $count++  
        }  
    }  
 
# wait for all the jobs to finish  
get-job | wait-job  
 
# store the jobs into an array  
$jobs = get-job  
# holds the results of the jobs  
$results = @()  
foreach ($job in $jobs) {  
    # grab the job output  
    $temp = receive-job -id $job.id -keep  
    $results += ,($temp[0],$temp[1])  
}  
 
# stop and remove all jobs  
get-job | stop-job  
get-job | remove-job  
 
# sort the results  
$results = $results | sort @{Expression={$_[0]}; Ascending=$false}  
# report the results  
foreach ($result in $results) {  
    if ($result[1]) {  
        write-host -f Green “$($result[0]) is responding”  
    } else {  
        write-host -f Red “$($result[0]) is not responding”  
    }  
} 

}