foreach ($proc in get-process)
    {
    try
        {
        Get-FileHash $proc.path -Algorithm SHA1 -ErrorAction stop
        }
    catch
        {
         #error handling... log contains names of processes where there was no path listed or we lack the rights
         $proc.name | out-file c:\proc_hash_error.log -Append
        }
    }