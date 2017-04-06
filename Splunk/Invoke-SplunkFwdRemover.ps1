<# 
.SYNOPSIS
    Initiator for removing the Splunk Forwarder. This script copies the SplunkRemove.ps1 script to a distant machine and runs it.
#>

# Reads in a list of computer names or IPs that you want the forwarder deleted from
$computers = Get-Content .\computers.txt

# The Splunk Forwarder to be deployed
$muscle = ".\SplunkRemove.ps1"

# Makes script 
"<# This script removes the Splunk Forwarder called 'splunkforwarder-6.4.3-b03109c2bad4-x64-release.msi' from a group of supplied workstations. If you are not removing this " >> .\SplunkRemove.ps1
"specific version, update line 52 with the applicable subject name." >> .\SplunkRemove.ps1
"" >> .\SplunkRemove.ps1
"#>" >> .\SplunkRemove.ps1
"" >> .\SplunkRemove.ps1
"Function Get-FileMetaData {" >> .\SplunkRemove.ps1
"" >> .\SplunkRemove.ps1
"[cmdletbinding()]" >> .\SplunkRemove.ps1
"param(" >> .\SplunkRemove.ps1
"    [Parameter(Mandatory = `$true," >> .\SplunkRemove.ps1
"               ValueFromPipeline = `$true," >> .\SplunkRemove.ps1
"               ValueFromPipelineByPropertyName = `$true)]" >> .\SplunkRemove.ps1
"    [Alias('FullName', 'PSPath')]" >> .\SplunkRemove.ps1
"    [string[]]`$path" >> .\SplunkRemove.ps1
"    )" >> .\SplunkRemove.ps1
"" >> .\SplunkRemove.ps1
"begin {" >> .\SplunkRemove.ps1
"    `$oshell = New-Object -ComObject Shell.Application" >> .\SplunkRemove.ps1
"    }" >> .\SplunkRemove.ps1
"" >> .\SplunkRemove.ps1
"process {" >> .\SplunkRemove.ps1
"    `$path | ForEach-Object {" >> .\SplunkRemove.ps1
"" >> .\SplunkRemove.ps1
"        if (test-path -path `$_ -pathtype leaf) {" >> .\SplunkRemove.ps1
"            `$fileitem = Get-Item -path `$_" >> .\SplunkRemove.ps1
"" >> .\SplunkRemove.ps1
"            `$ofolder = `$oshell.namespace(`$fileitem.DirectoryName)" >> .\SplunkRemove.ps1
"            `$oitem = `$ofolder.Parsename(`$fileitem.Name)" >> .\SplunkRemove.ps1
"" >> .\SplunkRemove.ps1
"            `$props = @{}" >> .\SplunkRemove.ps1
"" >> .\SplunkRemove.ps1
"            0..287 | ForEach-Object{" >> .\SplunkRemove.ps1
"                `$EXTPropName = `$ofolder.getdetailsof(`$ofolder.items, `$_)" >> .\SplunkRemove.ps1
"                `$EXTValName = `$ofolder.GetDetailsof(`$oitem, `$_)" >> .\SplunkRemove.ps1
"" >> .\SplunkRemove.ps1
"                if (-not `$props.containskey(`$extpropname) -and" >> .\SplunkRemove.ps1
"                        (`$EXTPropName -ne '')) {" >> .\SplunkRemove.ps1
"                            `$props.add(`$extpropname, `$extvalname)" >> .\SplunkRemove.ps1
"                            " >> .\SplunkRemove.ps1
"                }" >> .\SplunkRemove.ps1
"                }" >> .\SplunkRemove.ps1
"                New-object PSobject -property `$props" >> .\SplunkRemove.ps1
"                }" >> .\SplunkRemove.ps1
"                }" >> .\SplunkRemove.ps1
"                }" >> .\SplunkRemove.ps1
"                end {" >> .\SplunkRemove.ps1
"                    `$oshell = `$null" >> .\SplunkRemove.ps1
"                    }" >> .\SplunkRemove.ps1
"                    }" >> .\SplunkRemove.ps1
"" >> .\SplunkRemove.ps1
"# Retrieves a listing of where all .msi are cached on the system and looks for the Splunk one. " >> .\SplunkRemove.ps1
"`$installer_name = gci C:\windows\Installer | Get-FileMetaData | Where-Object {`$_.subject -eq 'splunk UniversalForwarder wix 1.0 installer'} | select name -ExpandProperty name" >> .\SplunkRemove.ps1
"" >> .\SplunkRemove.ps1
"# Uninstalls the Splunk Forwarder" >> .\SplunkRemove.ps1
"msiexec.exe /uninstall c:\windows\installer\`$installer_name.msi /quiet" >> .\SplunkRemove.ps1



foreach($computer in $computers)
    {

    # Copies the SplunkForwarder_Remover_Muscle.ps1 script to the distant machine
    Copy-Item .\$muscle \\$computer\c$\.

    # Creates a variable for WMI process
    $Action = [wmiclass] "\\$computer\ROOT\CIMv2:Win32_Process"

    # Creates a process call to invoke the the uninstall Splunk muscle uninstall script
    $Method = $Action.create('powershell /c c:\SplunkRemove.ps1')

    # Allow time for the command to run
    sleep 10

    # Deletes the .msi after the uninstall is complete 
    remove-item \\$computer\c$\$muscle
    }