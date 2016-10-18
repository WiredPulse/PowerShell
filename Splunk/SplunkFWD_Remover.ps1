<# This script removes the Splunk Forwarder called "splunkforwarder-6.4.3-b03109c2bad4-x64-release.msi" from a group of supplied workstations. If you are not removing this 
specific version, update line 52 with the applicable subject name.

#>
# Function to retrieve the extended file metadata
Function Get-FileMetaData {

[cmdletbinding()]
param(
    [Parameter(Mandatory = $true,
               ValueFromPipeline = $true,
               ValueFromPipelineByPropertyName = $true)]
    [Alias('FullName', 'PSPath')]
    [string[]]$path
    )

begin {
    $oshell = New-Object -ComObject Shell.Application
    }

process {
    $path | ForEach-Object {

        if (test-path -path $_ -pathtype leaf) {
            $fileitem = Get-Item -path $_

            $ofolder = $oshell.namespace($fileitem.DirectoryName)
            $oitem = $ofolder.Parsename($fileitem.Name)

            $props = @{}

            0..287 | ForEach-Object{
                $EXTPropName = $ofolder.getdetailsof($ofolder.items, $_)
                $EXTValName = $ofolder.GetDetailsof($oitem, $_)

                if (-not $props.containskey($extpropname) -and
                        ($EXTPropName -ne '')) {
                            $props.add($extpropname, $extvalname)
                            
                }
                }
                New-object PSobject -property $props
                }
                }
                }
                end {
                    $oshell = $null
                    }
                    }

# Retrieves a listing of where all .msi are cached on the system and looks for the Splunk one. 
$installer_name = gci C:\windows\Installer | Get-FileMetaData | Where-Object {$_.subject -eq "splunk UniversalForwarder wix 1.0 installer"} | select name -ExpandProperty name

# Uninstalls the Splunk Forwarder
msiexec.exe /uninstall c:\windows\installer\$installer_name.msi /quiet