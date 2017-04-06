<# 
.SYNOPSIS
    Initiator for deploying the Splunk Forwarder.

    NOTE: Be sure to change the file name on line 10 and line 11. Also be sure to change the IP for the Deployment server on line 24.
#>


# Variables to change
$computers = Get-Content .\computers.txt
$fowarder = "splunkforwarder-6.4.3-b03109c2bad4-x64-release.msi"


foreach($computer in $computers)
{

# Copies Splunk Forwarder to the distant workstation 
Copy-Item .\$fowarder \\$computer\c$\.

# Creates a variable for WMI process
$Action = [wmiclass] "\\$computer\ROOT\CIMv2:Win32_Process"

# Creates a process call to invoke the Splunk Fowarder we copied
$Method = $Action.create('powershell /c msiexec.exe /i c:\splunkforwarder-6.4.3-b03109c2bad4-x64-release.msi DEPLOYMENT_SERVER="172.16.123.141:8089" AGREETOLICENSE=Yes /quiet ')

# Allow time for the command to run
sleep 15

# Deletes the .msi after installation is complete 
remove-item \\$computer\c$\$fowarder

}