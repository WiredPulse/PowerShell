# Calls for you to input a PID and then it returns the process name, PPID, and handle(s)

$some_pid = read-host Input the PID
get-wmiobject win32_process -Filter -computername localhost "processid = $some_pid" | select Name, ProcessID, ParentProcessID, Handle, HandleCount, CreationDate, ExecutablePath | ft -autosize