function Set-ServerPrefetch{

#Requires -RunAsAdministrator

<# 
.SYNOPSIS
    Enables prefetch on a Server 2008 R2 and newer server operating systems. No restart is needed but it does need to be ran with elevated rights.
#>


New-Item "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters"
New-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" -Name EnablePrefetcher -Value 3 -PropertyType dword

New-Item "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Prefetcher"
New-ItemProperty "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Prefetcher" -name MaxPrefetchFiles -Value 8192 -PropertyType dword
 
Enable-MMAgent –OperationAPI
 
Restart-Service sysmain

}