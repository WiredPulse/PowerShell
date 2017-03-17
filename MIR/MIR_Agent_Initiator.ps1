<#
    .SYNOPSIS
        Initiator used to install the MIR Agent. 

    .REQUIREMENTS
        - Requires an account on the remote computer (Hopefully one with permissions)
        - Requires C$ or Admin Share

    .USAGE
        1 - Replace the $computers and $script2run variable to represent your situation
        2 - Save your changes
        3 - Execute the script
#>


$computers = Get-Content .\computers.txt
$mir_dir = 'C:\users\blue\Desktop\MIR_Agent'

foreach($computer in $computers)
    {
    # Copies directory to distant workstation
    Copy-Item $mir_dir -recurse \\$cpu\c$\.

    # Creates variable for WMI process
    $Action = [wmiclass] "\\$cpu\ROOT\CIMv2:Win32_Process"

    # Creates process creation to invoke the agent install
    $Method = $Action.create("powershell /c msiexec /i c:\MIR_Agent\mir_agent.msi /qn ")

    # Allows time for the agent to install
    sleep 10

    # Deletes the script and log file on the distant machine
    remove-item \\$cpu\c$\MIR_Agent -Recurse
    }
