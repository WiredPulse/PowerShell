<#

.SYNOPSIS
    Deletes the GRR Agent on a system.

#>


(Get-WmiObject Win32_Service -filter "name='GRR Monitor'").StopService()

(Get-WmiObject Win32_Service -filter "name='GRR Monitor'").delete()

Remove-Item HKLM:\SOFTWARE\GRR -Recurse

Remove-Item c:\windows\system32\grr -force -recurse

Remove-item c:\windows\system32\grr_installer.txt 2>1 | out-null


