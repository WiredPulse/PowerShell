<# 
.SYNOPSIS
    Enables prefetch on a Server 2012 machine. No restart is needed but it does need to be ran with elevated rights.

#>


reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" /v EnablePrefetcher /t REG_DWORD /d 3 /f
 
reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Prefetcher" /v MaxPrefetchFiles /t REG_DWORD /d 8192 /f
 
Enable-MMAgent –OperationAPI
 
net start sysmain