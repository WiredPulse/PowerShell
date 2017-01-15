$proc = Get-Process| where{ $_.ProcessName -eq "udaterui" -or $_.ProcessName -eq "naPrdMgr" -or $_.ProcessName -eq "mctray" -or $_.ProcessName -eq "frameworkservice" } 
$proc.modules | select size, modulename, filename, company, modulememorysize
