<# 
.SYNOPSIS
    Initiator for removing the Splunk Forwarder. This script requires the a Splunk forwarder .msi, which is used to delete a forwarder on a remote system.

#>

# Reads in a list of computer names or IPs that you want the forwarder deleted from
$computers = Get-Content .\computers.txt

# The Splunk Forwarder to be deleted
$fowarder = "splunkforwarder-6.4.3-b03109c2bad4-x64-release.msi"


foreach($computer in $computers)
    {

    # Copies Splunk Forwarder to the distant workstation 
    Copy-Item .\$fowarder \\$computer\c$\.

    # Creates a variable for WMI process
    $Action = [wmiclass] "\\$computer\ROOT\CIMv2:Win32_Process"
    $Method = $Action.create('powershell /c msiexec.exe /uninstall "c:\splunkforwarder-6.4.3-b03109c2bad4-x64-release.msi" /quiet ')

    # Allow time for the command to run
    sleep 15

    # Deletes the .msi after the uninstall is complete 
    remove-item \\$computer\c$\$fowarder
}