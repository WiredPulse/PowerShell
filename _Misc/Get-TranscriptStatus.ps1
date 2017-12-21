function Get-TranscriptStatus
{

<#
.SYNOPSIS
   Returns whether the host is transcribing and if so, provides the file name and creation date. This works
   in PowerShell version 2 only. 
#>



    try
        {
        $exHost = $host.gettype().getproperty("ExternalHost",[reflection.bindingflags]"nonpublic,instance").getvalue($host, @())
        $scriptpath = $exhost.gettype().getfield("transcriptFileName", "nonpublic,instance").getvalue($externalhost)
        }
    catch
        {
        Write-Warning "The ISE doesn't support this feature."
        }

    $file = get-item $scriptpath

    try
        {
	    $stream = New-Object system.IO.StreamReader $scriptpath
	    if ($stream)
            {
            $stream.Close()
            Write-Warning "Host is not transcribing"
            }
        }
    catch
        {
        write-host "Host is transcribing..." -ForegroundColor green
        write-host "Transcript file : " -ForegroundColor green -NoNewline; write-host $file -ForegroundColor yellow
        write-host "Creation Time : " -ForegroundColor green -NoNewline; write-host $file.creationtime -ForegroundColor yellow
        }
}
