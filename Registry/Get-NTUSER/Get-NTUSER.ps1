$ntuser_list = (gci C:\users\*\NTUSER.DAT -force -Exclude 'public', 'all users', 'default', 'default user' ).directoryname

foreach($line in $ntuser_list)
    {
    c:\RawCopy64.exe /fileNamePath:$line\ntuser.dat /OutputPath:c:\users\public\documents
    $dir_name = $line.Substring(9)

    rename-item c:\users\public\documents\ntuser.dat c:\users\public\documents\$env:COMPUTERNAME-$dir_name-NTUSER.dat
    }