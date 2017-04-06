<#
.SYNOPSIS
    Enables WMI logging (Trace) and sets the log size to 10 MB. Once enabled, logs can be found in Event Viewer >

.VIEWING LOGS
    GUI:
        1. Open Event Viewer
        2. Click View and select 'Show Analytic and Debug Logs'
        3. Expand Application and Services > Mirosoft > Windows > WMI-Activity > Trace
        4. Event ID 11 contains the good information

    Command-Line
        1. In PowerShell, type: Get-WinEvent -LogName 'Microsoft-Windows-WMI-Activity/Trace' | Out-GridView
#>

$computers = '192.168.60.202','192.168.60.201'


foreach($cpu in $computers)
    {
    wevtutil sl Microsoft-Windows-WMI-Activity/Trace /rt:true /ms:100000000 /r:$cpu
    Write-Output 'y' | wevtutil sl Microsoft-Windows-WMI-Activity/Trace /e:true /r:$cpu
    }

