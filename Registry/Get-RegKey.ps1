<#
    SYNOPSIS:
        Gets the specified Registry Hive or Key from a supplied list of systems. 

    USAGE:
        1) Change the variables in line 15 and 16
        2) Run the script (.\Get-RegKey.ps1)
        3) *.reg will be save to the location of where the script was ran from
        4) Import it into the Registry using the below syntax
                reg load < Where to import > < Location or .reg to import>
                reg load <hklm\temphive c:\users\JoeBob\desktop\192.168.1.19_Windows.reg

    REQUIREMENTS:
        An account with the applicable rights for WMI.

    NOTES:
        In my testing, some Registry Keys did not work but backing up one or two Keys above, worked well. In the end, the targeted Key 
        was retrieve, it just required getting a little more than desired.

        For example:
            When trying to get 'reg export hklm\software\microsoft\windows\currentverion\run', it error appeared but doing 'reg export 
            hklm\software\microsoft\windows' worked well. We not only got the data from the Run Key but also everything else within the 
            Windows Key and its Sub-Keys. 
#>

# Variables to Change
$computers = Get-Content .\computers.txt
$reg_name = "something.reg"

# Loops through the supplied list of computers and exports the Hive or Key
foreach($computer in $computers)
    {
    $name = $computer + '_' + $reg_name
    # Creates variable for WMI process
    $Action = [wmiclass] "\\$computer\ROOT\CIMv2:Win32_Process"

    # Creates process creation to invoke the PowerShell script we copied and logs output to a file
    $Method = $Action.create("reg export hklm\software\microsoft\windows c:\$name")

    # Allow time for the command to run
    sleep 5

    #Retrieves the Registry Hive or Key from the distant machine and saves it locally
    Copy-Item \\$computer\c$\$name .\

    # Deletes the script and log file on the distant machine
    Remove-item \\$computer\c$\$name
}
