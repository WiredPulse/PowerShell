<#
    .SYNOPSIS  
        Creates a formatted csv for importing data sources into McAfee ESM. Once the csv has been created, open it in Notepad or Notepad++ and save the document with UTF8 encoding.

    .DESCRIPTION  
        This script will log the actions it performs, receives the domain computer listing, checks that you are an administrator, and formulates a formatted csv for McAfee ESM. You will have to supply the ESM receiver ID, the username (domain\user) and password that will be used to authenticate to the end workstation.


    The first call is to get the folder path where you want to store all results and files in.
    The second call asks how to search.
    Three choices:
        List computers will talk to the domain and you can either pull all from the domain you are on or write your own OU to pull from
        List text file will ingest a text file and check for subnets, IP, or computer name and go through that
        Single entry can take computer name, IP, or subnets

        The list will go into a variable named $Script:Computers

    The function Get-Subnet-Range will break out subnet ranges

    .NOTES  
        File Name      : ESM_csv.ps1
        Version        : v.0.1  
        Author         : WiredPulse
        Email          : 
        Prerequisite   : PowerShell
        Created        : 01 Jun 16
     
     .CHANGELOG
        Update         : DATE 
            Changes:   : 

     .TODO
        1. 

    ####################################################################################


#>
# Set Variables
$Script:curDate = ""
$Script:curDate = $((Get-Date).ToString("yyyy_MMM_dd-HH.mm.ss-tt")) ##Sets the date and time##


# ===========================================================================================
#
# Function Name 'Get_Folder_Path' - Prompts for folder path to store files
#
# ===========================================================================================
Function Get_Folder_Path
{
    $objShell = ""
    $Script:NamedFolder = ""
    $Script:Log_File = ""
    $Script:Folder_Path = ""
    $objShell = new-object -com shell.application
    $Script:NamedFolder = $objShell.BrowseForFolder(0,"Please select a location to save the log files to:",0,"$env:USERPROFILE\Desktop")
    if ($Script:NamedFolder -eq $null) {
        Write-Host "YOU MUST SELECT A FOLDER TO STORE THE LOGS!" -Fore Red
        . Get_Folder_Path }
    Else {
        $Script:Folder_Path = $Script:NamedFolder.self.path
        write-host "All files will be written to: $Script:Folder_Path"
        New-Item -type file -force "$Script:Folder_Path\Log_File_$Script:curDate.txt" | Out-Null
        $Script:Log_File = "$Script:Folder_Path\Log_File_$Script:curDate.txt"
        # ====================================
        # Starting the Log_File
        # ====================================
        echo "Script started - "$Script:curDate | out-file $Script:Log_File -Append
        echo "--------------------------------------------------------------" | out-file $Script:Log_File -Append }
}


write-Host "Please input the ESM Device ID which can be found at Receiver Properties > Name and Description." -ForegroundColor Green
$id_response = Read-Host :
write-host "Please input the username (domain\user) that will be used to authenticate to the end workstation." -ForegroundColor Green
$user_response = Read-Host :
write-host "Please input the password that will be used to authenticate to the end workstation." -ForegroundColor Green
$pass_response = Read-Host :

Write-Host "This script needs to know where to write the results to." -ForegroundColor Green
# ========================================================================
# Function Name 'ListComputers' - Takes entered domain and lists all computers
# ========================================================================
Function ListComputers
{
    $DN = ""
    $Response = ""
    $DNSName = ""
    $DNSArray = ""
    $objSearcher = ""
    $colProplist = ""
    $objComputer = ""
    $objResults = ""
    $colResults = ""
    $Computer = ""
    $comp = ""
    New-Item -type file -force "$Script:Folder_Path\Computer_List.txt" | Out-Null
    $Script:Compute = "$Script:Folder_Path\Computer_List.txt"
    $strCategory = "(ObjectCategory=Computer)"
    
    Write-Host "Would you like to automatically pull from your domain or provide your own domain?"
    Write-Host "Auto pull uses the current domain you are on, if you need to select a different domain use manual."
    $response = Read-Host = "[1] Auto Pull, [2] Manual Selection"
    
    If($Response -eq "1") {
        $DNSName = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().Name
        If($DNSName -ne $Null) {
            $DNSArray = $DNSName.Split(".") 
            for ($x = 0; $x -lt $DNSArray.Length ; $x++) {  
                if ($x -eq ($DNSArray.Length - 1)){$Separator = ""}else{$Separator =","} 
                [string]$DN += "DC=" + $DNSArray[$x] + $Separator  } }
        $Script:Domain = $DN
        echo "Pulled computers from: "$Script:Domain | Out-File $Script:Log_File -Append
        $objSearcher = New-Object System.DirectoryServices.DirectorySearcher("LDAP://$Script:Domain")
        $objSearcher.Filter = $strCategory
        $objSearcher.PageSize = 100000
        $objSearcher.SearchScope = "SubTree"
        $colProplist = "name"
        foreach ($i in $colPropList) {
            $objSearcher.propertiesToLoad.Add($i) }
        $colResults = $objSearcher.FindAll()
        foreach ($objResult in $colResults) {
            $objComputer = $objResult.Properties
            $comp = $objComputer.name
            echo $comp | Out-File $Script:Compute -Append }
        $Script:Computers = (Get-Content $Script:Compute) | Sort-Object
    }
	elseif($Response -eq "2")
    {
        Write-Host "Would you like to automatically pull from your domain or provide your own domain?"
        Write-Host "Auto pull uses the current domain you are on, if you need to select a different domain use manual."
        $Script:Domain = Read-Host "Enter your Domain here: OU=West,DC=Company,DC=com"
        If ($Script:Domain -eq $Null) {Write-Host "You did not provide a valid response."; . ListComputers}
        
        echo "Pulled computers from: "$Script:Domain | Out-File $Script:Log_File -Append
        $objOU = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$Script:Domain")
        $objSearcher = New-Object System.DirectoryServices.DirectorySearcher
        $objSearcher.SearchRoot = $objOU
        $objSearcher.Filter = $strCategory
        $objSearcher.PageSize = 100000
        $objSearcher.SearchScope = "SubTree"
        $colProplist = "name"
        foreach ($i in $colPropList) { $objSearcher.propertiesToLoad.Add($i) }
        $colResults = $objSearcher.FindAll()
        foreach ($objResult in $colResults) {
            $objComputer = $objResult.Properties
            $comp = $objComputer.name
            echo $comp | Out-File $Script:Compute -Append }
        $Script:Computers = (Get-Content $Script:Compute) | Sort-Object
    }
    else {
        Write-Host "You did not supply a correct response, Please select a response." -foregroundColor Red
        . ListComputers }
}

# ========================================================================
# Function Name 'ListTextFile' - Enumerates Computer Names in a text file
# Create a text file and enter the names of each computer. One computer
# name per line. Supply the path to the text file when prompted.
# ========================================================================
Function ListTextFile 
{
	$file_Dialog = ""
    $file_Name = ""
    [System.Reflection.Assembly]::LoadWithPartialName("System.windows.forms") | Out-Null
    $file_Dialog = New-Object system.windows.forms.openfiledialog
    $file_Dialog.InitialDirectory = "$env:USERPROFILE\Desktop"
    $file_Dialog.MultiSelect = $false
    $file_Dialog.showdialog()
    $file_Name = $file_Dialog.filename
    $Comps = Get-Content $file_Name
    If ($Comps -eq $Null) {
        Write-Host "Your file was empty. You must select a file with at least one computer in it." -Fore Red
        . ListTextFile }
    Else
    {
        $Script:Computers = @()
        ForEach ($Comp in $Comps)
        {
            If ($Comp -match "\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}")
            {
                $Temp = $Comp.Split("/")
                $IP = $Temp[0]
                $Mask = $Temp[1]
                . Get-Subnet-Range $IP $Mask
                $Script:Computers += $Script:IPList
            }
            Else
            {
                $Script:Computers += $Comp
            }
        }

        echo " " | Out-File $Script:Log_File -Append
        echo "Computer list located: $file_Name" | Out-File $Script:Log_File -Append 
        
    }
}

Function Get-Subnet-Range {
    #.Synopsis
    # Lists all IPs in a subnet.
    #.Example
    # Get-Subnet-Range -IP 192.168.1.0 -Netmask /24
    #.Example
    # Get-Subnet-Range -IP 192.168.1.128 -Netmask 255.255.255.128        
    Param(
        [string]
        $IP,
        [string]
        $netmask
    )  
    Begin {
        $IPs = New-Object System.Collections.ArrayList

        Function Get-NetworkAddress {
            #.Synopsis
            # Get the network address of a given lan segment
            #.Example
            # Get-NetworkAddress -IP 192.168.1.36 -mask 255.255.255.0
            Param (
                [string]
                $IP,
               
                [string]
                $Mask,
               
                [switch]
                $Binary
            )
            Begin {
                $NetAdd = $null
            }
            Process {
                $BinaryIP = ConvertTo-BinaryIP $IP
                $BinaryMask = ConvertTo-BinaryIP $Mask
                0..34 | %{
                    $IPBit = $BinaryIP.Substring($_,1)
                    $MaskBit = $BinaryMask.Substring($_,1)
                    IF ($IPBit -eq '1' -and $MaskBit -eq '1') {
                        $NetAdd = $NetAdd + "1"
                    } elseif ($IPBit -eq ".") {
                        $NetAdd = $NetAdd +'.'
                    } else {
                        $NetAdd = $NetAdd + "0"
                    }
                }
                if ($Binary) {
                    return $NetAdd
                } else {
                    return ConvertFrom-BinaryIP $NetAdd
                }
            }
        }
       
        Function ConvertTo-BinaryIP {
            #.Synopsis
            # Convert an IP address to binary
            #.Example
            # ConvertTo-BinaryIP -IP 192.168.1.1
            Param (
                [string]
                $IP
            )
            Process {
                $out = @()
                Foreach ($octet in $IP.split('.')) {
                    $strout = $null
                    0..7|% {
                        IF (($octet - [math]::pow(2,(7-$_)))-ge 0) {
                            $octet = $octet - [math]::pow(2,(7-$_))
                            [string]$strout = $strout + "1"
                        } else {
                            [string]$strout = $strout + "0"
                        }  
                    }
                    $out += $strout
                }
                return [string]::join('.',$out)
            }
        }
 
 
        Function ConvertFrom-BinaryIP {
            #.Synopsis
            # Convert from Binary to an IP address
            #.Example
            # Convertfrom-BinaryIP -IP 11000000.10101000.00000001.00000001
            Param (
                [string]
                $IP
            )
            Process {
                $out = @()
                Foreach ($octet in $IP.split('.')) {
                    $strout = 0
                    0..7|% {
                        $bit = $octet.Substring(($_),1)
                        IF ($bit -eq 1) {
                            $strout = $strout + [math]::pow(2,(7-$_))
                        }
                    }
                    $out += $strout
                }
                return [string]::join('.',$out)
            }
        }

        Function ConvertTo-MaskLength {
            #.Synopsis
            # Convert from a netmask to the masklength
            #.Example
            # ConvertTo-MaskLength -Mask 255.255.255.0
            Param (
                [string]
                $mask
            )
            Process {
                $out = 0
                Foreach ($octet in $Mask.split('.')) {
                    $strout = 0
                    0..7|% {
                        IF (($octet - [math]::pow(2,(7-$_)))-ge 0) {
                            $octet = $octet - [math]::pow(2,(7-$_))
                            $out++
                        }
                    }
                }
                return $out
            }
        }
 
        Function ConvertFrom-MaskLength {
            #.Synopsis
            # Convert from masklength to a netmask
            #.Example
            # ConvertFrom-MaskLength -Mask /24
            #.Example
            # ConvertFrom-MaskLength -Mask 24
            Param (
                [int]
                $mask
            )
            Process {
                $out = @()
                [int]$wholeOctet = ($mask - ($mask % 8))/8
                if ($wholeOctet -gt 0) {
                    1..$($wholeOctet) |%{
                        $out += "255"
                    }
                }
                $subnet = ($mask - ($wholeOctet * 8))
                if ($subnet -gt 0) {
                    $octet = 0
                    0..($subnet - 1) | %{
                         $octet = $octet + [math]::pow(2,(7-$_))
                    }
                    $out += $octet
                }
                for ($i=$out.count;$i -lt 4; $I++) {
                    $out += 0
                }
                return [string]::join('.',$out)
            }
        }

        Function Get-IPRange {
            #.Synopsis
            # Given an Ip and subnet, return every IP in that lan segment
            #.Example
            # Get-IPRange -IP 192.168.1.36 -Mask 255.255.255.0
            #.Example
            # Get-IPRange -IP 192.168.5.55 -Mask /23
            Param (
                [string]
                $IP,
               
                [string]
                $netmask
            )
            Process {
                iF ($netMask.length -le 3) {
                    $masklength = $netmask.replace('/','')
                    $Subnet = ConvertFrom-MaskLength $masklength
                } else {
                    $Subnet = $netmask
                    $masklength = ConvertTo-MaskLength -Mask $netmask
                }
                $network = Get-NetworkAddress -IP $IP -Mask $Subnet
               
                [int]$FirstOctet,[int]$SecondOctet,[int]$ThirdOctet,[int]$FourthOctet = $network.split('.')
                $TotalIPs = ([math]::pow(2,(32-$masklength)) -2)
                $blocks = ($TotalIPs - ($TotalIPs % 256))/256
                if ($Blocks -gt 0) {
                    1..$blocks | %{
                        0..255 |%{
                            if ($FourthOctet -eq 255) {
                                If ($ThirdOctet -eq 255) {
                                    If ($SecondOctet -eq 255) {
                                        $FirstOctet++
                                        $secondOctet = 0
                                    } else {
                                        $SecondOctet++
                                        $ThirdOctet = 0
                                    }
                                } else {
                                    $FourthOctet = 0
                                    $ThirdOctet++
                                }  
                            } else {
                                $FourthOctet++
                            }
                            Write-Output ("{0}.{1}.{2}.{3}" -f `
                            $FirstOctet,$SecondOctet,$ThirdOctet,$FourthOctet)
                        }
                    }
                }
                $sBlock = $TotalIPs - ($blocks * 256)
                if ($sBlock -gt 0) {
                    1..$SBlock | %{
                        if ($FourthOctet -eq 255) {
                            If ($ThirdOctet -eq 255) {
                                If ($SecondOctet -eq 255) {
                                    $FirstOctet++
                                    $secondOctet = 0
                                } else {
                                    $SecondOctet++
                                    $ThirdOctet = 0
                                }
                            } else {
                                $FourthOctet = 0
                                $ThirdOctet++
                            }  
                        } else {
                            $FourthOctet++
                        }
                        Write-Output ("{0}.{1}.{2}.{3}" -f `
                        $FirstOctet,$SecondOctet,$ThirdOctet,$FourthOctet)
                    }
                }
            }
        }
    }
    Process {
        #get every ip in scope
        Get-IPRange $IP $netmask | %{
        [void]$IPs.Add($_)
        }
        $Script:IPList = $IPs
    }
}

# ========================================================================
# Function Name 'SingleEntry' - Enumerates Computer from user input
# ========================================================================
Function SingleEntry 
{
    $Comp = Read-Host "Enter Computer Name or IP (1.1.1.1) or IP Subnet (1.1.1.1/24)"
    If ($Comp -eq $Null) { . SingleEntry } 
    ElseIf ($Comp -match "\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}")
    {
        $Temp = $Comp.Split("/")
        $IP = $Temp[0]
        $Mask = $Temp[1]
        . Get-Subnet-Range $IP $Mask
        $Script:Computers = $Script:IPList
    }
    Else
    { $Script:Computers = $Comp}
}

# ========================================================================
# Function Name 'Test-Administrator' - Checks if ran as admin
# ========================================================================
function Test-Administrator  
{  
    $user = [Security.Principal.WindowsIdentity]::GetCurrent();
    (New-Object Security.Principal.WindowsPrincipal $user).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)  
}

# ==============================================================================================
# Script Body - This is where the magic happens
# ==============================================================================================
$erroractionpreference = "SilentlyContinue"
# This tests to see if the user is an administrator, if not script attempts to runas the script.
If ((Test-Administrator) -ne $True)
{
    Write-Host "You are not an administrator" -Fore Red
    $Invocation = (Get-Variable MyInvocation).Value
    $Argument = (Split-Path $Invocation.MyCommand.Path) + "\" + ($invocation.mycommand.name)
    if ($Argument -ne "") 
    {   
        $arg = "-file `"$($Argument)`"" 
        Start-Process "$psHome\powershell.exe" -Verb Runas -ArgumentList $arg -ErrorAction 'stop'  
    }
    exit # Quit this session of powershell  
}


Write-Host "This script needs to know where to write the results to." -ForegroundColor Green
Write-Host "Please select the location to store the files." -ForegroundColor Green
. Get_Folder_Path

echo "Got folder path... Next task..." | Out-File $Script:Log_File -Append
echo " " | Out-File $Script:Log_File -Append

Write-Host " "
Write-Host "How do you want to list computers?"	-ForegroundColor Green
$strResponse = Read-Host "`n[1] All Domain Computers (Must provide Domain), `n[2] Computer names from a File, `n[3] List a SingleComputer manually"
If($strResponse -eq "1"){. ListComputers | Sort-Object}
	elseif($strResponse -eq "2"){. ListTextFile}
	elseif($strResponse -eq "3"){. SingleEntry}
	else{Write-Host "You did not supply a correct response, `
	Please run script again."; pause -foregroundColor Red}				

echo "Got computer list... Next task..." | Out-File $Script:Log_File -Append
echo " " | Out-File $Script:Log_File -Append

#$receiver_id = "144116287587483648"
$Script:compute = get-content "C:\users\admin\desktop\computers.txt"
#$pass = ""
#$user = ""

Write-Output '' |out-file esm.csv
Write-Output ''|out-file esm.csv -append
foreach ($line in $computers)
{
Write-output $id_response',"'$line'","","Windows Event Log - WMI","Microsoft",0,0,,"no","F","'$line'","'$id_response'","no","no","yes","Default Policy",,"no","600","SYSTEM,APPLICATION,SECURITY",'$pass_response',"'$user_response'","0"' |out-file esm.csv -append
}

get-content .\esm.csv | foreach{ "add," + $_} | Out-File ./esm_data_source_import.csv

$esm_csv = Get-Content .\esm_data_source_import.csv
$esm_csv[0] = '"#version#","9.5.0","McAfee data source export",,,,,,'
$esm_csv[1] = 'op,rec_id,dsname,ip,model,vendor,parent_id,child_type,matching_type,elm_logging,exportNitroFile,hostname,linked_ipsid,nitro_formated_file,nitro_formated_file_xsum,parsing,policy_name,snmp_trap_id,use_rpc,wmi_interval,wmi_logs,wmi_password,wmi_username,wmi_version'
$esm_csv | Set-Content .\esm_data_source_import.csv

remove-item .\esm.csv

