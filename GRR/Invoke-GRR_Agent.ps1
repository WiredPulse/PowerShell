<#
.SYNOPSIS
    Initiates process call on specified systems to install the GRR agent from a share. 

.USAGE
    1 - Create a share with suitable rights and put the GRR agent there
    2 - Replace the $computers variable on line 17 in this script to point to your list of computers
    3 - Input the share and executable name in line 28
    4 - Execute the script
#>

Write-Host "Input the path to the file containing system names or IPs."
$computers = read-host = " "

Write-Host "Input path to GRR agent executable."
$path = read-host = " "

$exe = $path.split('\') | select -last 1

foreach($computer in $computers)
{
# Copies script to be run on distant workstation
Copy-Item $path \\$computer\c$\. 

$proc = Invoke-WmiMethod -ComputerName $computer -Class Win32_Process -Name Create -ArgumentList "powershell /c $exe"
$my_var = Register-WmiEvent -ComputerName $computer -Query "Select * from Win32_ProcessStopTrace Where ProcessID=$($proc.ProcessId)" -MessageData $computer -Action { Write-Host "$($Event.MessageData) Process ExitCode: $($event.SourceEventArgs.NewEvent.ExitStatus)"} 
    if($proc.processid -ne $null)
        {
        # Does nothing
        }
    elseif($proc.processid -eq $null)
        {
        "$computer : Not accessible via WMI" >> .\YarPoSh_Results\_Log.txt
        }
}

