<#
.SYNOPSIS
    Gets the specified Registry Hive or Key from a supplied list of systems. The hive can be imported into another machine for analysis, if desired.

.PARAMETER computername
    Specifies a single IP or text file containing computer names or IPs.

.PARAMETER Reg
    Specifies the Registry Hive or Key to export

.PARAMETER RegOutput
    Specifies the name of the exported Registry Hive or Key

.EXAMPLE
    PS C:\> .\Get-RegKeyExport.ps1 -computername 172.16.155.201 -Reg system\currentcontrolset\services -RegOutput Export_Services.reg
    
    Exports the 'Services' Key on 172.16.155.201 and names it 'Export_Services.reg'

.EXAMPLE
    PS C:\> .\Get-RegKeyExport.ps1 -computername c:\users\blue\desktop\computers.txt -Reg software\microsoft\windows -RegOutput Export_Windows.reg
    
    Exports the 'Windows' Key on the systems listed in computers.txt and names it 'Export_Windows.reg'


.NOTES:
    In my testing, some Registry Keys did not work but backing up one or two Keys above, worked well. In the end, the targeted Key 
    was retrieve, it just required getting a little more than desired.

    For example:
        When trying to get 'reg export hklm\software\microsoft\windows\currentverion\run', it error appeared but doing 'reg export 
        hklm\software\microsoft\windows' worked well. We not only got the data from the Run Key but also everything else within the 
        Windows Key and its Sub-Keys. 
#>


param(
    [Parameter(Mandatory=$true)][string]$ComputerName,
    [Parameter(Mandatory=$true)][string]$Reg,
    [Parameter(Mandatory=$true)][string]$RegOutput
     )


Function call
    {
    # Loops through the supplied list of computers and exports the Hive or Key
    foreach($computer in $cpu)
        {
        $name = $computer + '_' + $RegOutput
        # Creates variable for WMI process
        $Action = [wmiclass] "\\$computer\ROOT\CIMv2:Win32_Process"

        # Creates process creation to invoke the PowerShell script we copied and logs output to a file
        $Method = $Action.create("reg export hklm\$reg c:\$name")

        # Allow time for the command to run
        sleep 5

        #Retrieves the Registry Hive or Key from the distant machine and saves it locally
        Copy-Item \\$computer\c$\$name .\

        # Deletes the script and log file on the distant machine
        Remove-item \\$computer\c$\$name
    }
}

# Parameters received at the start of running the script
if($ComputerName -like '*.txt')
    {
    $exe = $path.split('\') | select -last 1
    $cpu = Get-content $computername
    Call
    }
elseif($ComputerName -notcontains '.txt')
    {
    $exe = $path.split('\') | select -last 1
    $cpu = $ComputerName
    Call
    }
else{Echo 'No IP or a file containing IPs were specified'}
