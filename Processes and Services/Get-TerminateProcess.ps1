<#
    .SYNOPSIS  
        This script will remotely terminate a process by name on a system using the IP or hostname. 

    .NOTES  
        File Name      : Terminate-Process.ps1
        Version        : v.0.1  
        Prerequisite   : PowerShell
        Created        : 23 MARCH 16

    ####################################################################################


#>

$ComputerName = Read-Host -Prompt "Input the computer name or IP"
$ProcessName = Read-Host -Prompt "Input the process name"

# Lists the specific process
$Processes = Get-WmiObject -Class Win32_Process -ComputerName $ComputerName -Filter "name='$ProcessName'"

foreach ($process in $processes) {
      echo "Found the process, I am trying to terminate it now..."
      $returnval = $process.terminate()
      echo "Almost done..."
      $processid = $process.handle
 
    if($returnval.returnvalue -eq 0) {
      write-host "The process $ProcessName `($processid`) terminated successfully!"
    }
    else {
      write-host "The process to terminate $ProcessName `($processid`) has some problems :("
    }
}