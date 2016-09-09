<#
    .SYNOPSIS  
        This script will monitor creations, deletions, changes, and renames that take place within a directory. The monitoring covers any sub-directories and files as well. Any hits will be written to the screen and to a log called FileChangeLog.txt in the directory from which the script is ran from. 

    .NOTES  
        File Name      : file_monitor.ps1
        Version        : v.0.1  
        Prerequisite   : PowerShell v2 or higher
     

    .USAGE
	Change the path to the directory you wish to monitor on the second line below with the variable "$watcher.Path" and run the script. An ignorelist can be read by the script as well and will read it from the current directory. It should be named "ignorelist.txt" an there should be one entry per line.
    ####################################################################################


#>



$watcher = New-Object System.IO.FileSystemWatcher
# Path to the directory to monitor
$watcher.Path = "C:\Users\admin\desktop\170 packet"
$watcher.IncludeSubdirectories = $true
$watcher.EnableRaisingEvents = $true
$log = ".\FileChangeLog.txt"

$changed = Register-ObjectEvent $watcher "Changed" -Action {
	# Not doing anything yet. It is mostly junk like registry writes.
# Lists and directories or files to ignore
	#$ignorelist = Get-Content .\ignorelist.txt
	$ignore = $false
	#foreach ($str in $ignorelist) { 
	#	if ($($eventArgs.FullPath).contains($str)) {$ignore = $true} 
	#}
	if ($ignore -eq $false) { 
		$output =  $(get-date -f yyyy-MM-dd--hh:mm:ss)
		$output += " Changed: $($eventArgs.FullPath)"
		$output | Out-File $log -width 400 -append
		write-host $output
	}
}

$created = Register-ObjectEvent $watcher "Created" -Action {
	$log = ".\FileChangeLog.txt"
	$output =  $(get-date -f yyyy-MM-dd--hh:mm:ss)
	$output += " Created: $($eventArgs.FullPath)" 
	$output | Out-File $log -width 400 -append
	write-host $output
}
$deleted = Register-ObjectEvent $watcher "Deleted" -Action {
	$log = ".\FileChangeLog.txt"
	$output =  $(get-date -f yyyy-MM-dd--hh:mm:ss)
	$output += " Deleted: $($eventArgs.FullPath)"
	$output | Out-File $log -width 400 -append
	write-host $output
}
$renamed = Register-ObjectEvent $watcher "Renamed" -Action {
	$log = ".\FileChangeLog.txt"
	$output =  $(get-date -f yyyy-MM-dd--hh:mm:ss)
    $output += " Renamed: $($eventArgs.FullPath)"
	$output | Out-File $log -width 400 -append
	write-host $output
}

