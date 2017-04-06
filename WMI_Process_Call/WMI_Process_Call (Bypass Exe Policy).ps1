<#
.SYNOPSIS
    ***  Bypasses Execution Policy  ***
    Copies and runs a script on a remote system and outputs the data to a text file. After completion, retrieves the text file of data from the distant compter and 
    saves it to the local machine. Lastly the copied script and text file of output are deleted from the distant machine.

.USAGE
    1 - Replace the $computers and $script2run variable to represent your situation
    2 - Save your changes
    3 - Execute the script
#>


$computers = Get-Content .\computers.txt
$script2run = "test.ps1"

foreach($computer in $computers)
{

# Copies script to be run on distant workstation

Copy-Item .\$script2run \\$computer\c$\.

# Creates variable for WMI process
$Action = [wmiclass] "\\$computer\ROOT\CIMv2:Win32_Process"

# Creates process creation to invoke the PowerShell script we copied and logs output to a file. It also bypasses any execution policy
$Method = $Action.create("powershell /c get-content c:\$script2run | powershell -noprofile - > c:\$computer.txt ")

# Allow time for the command to run
sleep 5

# Retrieves the log from the distant machine and saves it locally
Copy-Item \\$computer\c$\$computer.txt c:\users\blue\desktop\results\

# Deletes the script and log file on the distant machine
remove-item \\$computer\c$\$computer.txt
remove-item \\$computer\c$\$script2run

}
