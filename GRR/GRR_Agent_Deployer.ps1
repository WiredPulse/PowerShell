<#
    .SYNOPSIS
        Initiates process call on specified systems to install the GRR agent from a share. 

    .REQUIREMENTS
        - Requires an account on the remote computer (Hopefully one with permissions and excluded from the execution policy)
        - Requires C$ or Admin Share

    .USAGE
        1 - Create a share with suitable rights and put the GRR agent there
        2 - Replace the $computers variable on line 17 in this script to point to your list of computers
        3 - Input the share and executable name in line 28
        3 - Execute the script
#>

# Reads in a list of computers that we will be installing the agent
$computers = get-content c:\user\blue\desktop\computers.txt

foreach($computer in $computers)
{
# Copies script to be run on distant workstation
Copy-Item $dir2copy\$agent \\$computer\c$\. 

# Creates variable for WMI process
$Action = [wmiclass] "\\$computer\ROOT\CIMv2:Win32_Process"

# Creates process creation to invoke the BlueSpectrum script that we copied.
$Method = $Action.create("cmd /c c:\GRR_3.1.0.2_amd64.exe")
}

# Allow time for the command to run
#sleep 40

# Deletes the script and log file on the distant machine
#remove-item \\$computer\c$\$agent