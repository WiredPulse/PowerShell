c:\strings.exe -accepteula 'C:\Program Files (x86)\McAfee\Common Framework\FrameworkService.exe' | out-file c:\frame.txt
c:\strings.exe 'C:\Program Files (x86)\McAfee\Common Framework\udaterui.exe' | out-file c:\99099_udate.txt
c:\strings.exe 'C:\Program Files (x86)\McAfee\Common Framework\mctray.exe' | out-file c:\99099_mctray.txt
c:\strings.exe 'C:\Program Files (x86)\McAfee\Common Framework\naPrdMgr' | out-file c:\99099_naprmgr.txt