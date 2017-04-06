<# 
.SYNOPSIS
    Returns the process name, PPID, and handle(s) from a given PID

#>
$some_pid = read-host Input the PID
get-wmiobject win32_process -Filter -computername localhost "processid = $some_pid" | select Name, ProcessID, ParentProcessID, Handle, HandleCount, CreationDate, ExecutablePath | ft -autosize