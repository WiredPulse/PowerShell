# Initiator for removing the Splunk Forwarder. 

# Reads in a list of computer names or IPs that you want the forwarder deleted from
$computers = Get-Content .\computers.txt

# The Splunk Forwarder to be deleted
#$fowarder = "splunkforwarder-6.4.3-b03109c2bad4-x64-release.msi"


foreach($computer in $computers)
{

# Copies Splunk Forwarder to the distant workstation 
#Copy-Item .\$fowarder \\$computer\c$\.

# Creates a variable for WMI process
$Action = [wmiclass] "\\$computer\ROOT\CIMv2:Win32_Process"

# Creates a process call to invoke the the uninstall of the Splunk Forwarder
# this works buts needs the file local
#$Method = $Action.create('powershell /c msiexec.exe /uninstall "c:\splunkforwarder-6.4.3-b03109c2bad4-x64-release.msi" /quiet ')

$Method = $Action.create('powershell /c msiexec.exe /uninstall "c:\splunkforwarder-6.4.3-b03109c2bad4-x64-release.msi" /quiet ')

#$Method = $Action.create('powershell /c MsiExec.exe /uninstall FB35A19C-CF31-4CDD-B629-F93028CA7A04 /quiet')

# Allow time for the command to run
sleep 10

# Deletes the .msi after the uninstall is complete 
#remove-item \\$computer\c$\$fowarder


}