# Retrieves all PIDs and with their PPIDs

get-wmiobject win32_process -computername localhost | select name, processid, parentprocessid, handle, handlecount, executablepath, creationdate | ft -autosize