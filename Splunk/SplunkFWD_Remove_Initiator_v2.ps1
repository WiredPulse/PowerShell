# Initiator for removing the Splunk Forwarder. This script initiates copies the SplunkFWD_Remover.ps1 script to a distant machine and runs it.

# Reads in a list of computer names or IPs that you want the forwarder deleted from
$computers = Get-Content .\computers.txt

# The Splunk Forwarder to be deployed
$muscle = "SplunkFWD_Remover.ps1"

foreach($computer in $computers)
{

# Copies the SplunkForwarder_Remover_Muscle.ps1 script to the distant machine
Copy-Item .\$muscle \\$computer\c$\.

# Creates a variable for WMI process
$Action = [wmiclass] "\\$computer\ROOT\CIMv2:Win32_Process"

# Creates a process call to invoke the the uninstall Splunk muscle uninstall script
$Method = $Action.create('powershell /c c:\SplunkFWD_Remover.ps1')

# Allow time for the command to run
sleep 10

# Deletes the .msi after the uninstall is complete 
remove-item \\$computer\c$\$muscle


}