<#
.SYNOPSIS
    Reads the specified DNS debug log.

.DESCRIPTION
    Retrives all entries in the DNS debug log for further processing using powershell out-gridview or exporting to Excel.

.PARAMETER Path
    Specifies the path to the DNS debug logfile.

.PARAMETER Ignore
    Specifies which IPs to ignore.

.EXAMPLE
    PS C:\> .\Invoke-DNSLogParser -Path ".\dns.log" |group-Object "Client IP"| Sort-Object -Descending Count| Select -First 10 Name, Count | format-table

    Returns a table depicting the top ten IPs in the log and the number of times they appear.

.EXAMPLE
    PS C:\> .\Invoke-DNSLogParser -Path ".\dns.log" |group-Object "Client IP"| Sort-Object -Descending Count | format-table

    Returns a table depicting IPs in the log and the number of times they appear.

.EXAMPLE
    PS C:\> .\Invoke-DNSLogParser -Path ".\dns.log" | format-table

    Parses the log file and returns the data in a human-readable format.

.LINK
    https://gallery.technet.microsoft.com/scriptcenter/Get-DNSDebugLog-Easy-ef048bdf
#>
	


[CmdletBinding()]
	Param(
		[Parameter(Mandatory=$true)]
		[string]
		[ValidateScript({Test-Path($_)})]
		$Path,
		[Parameter(Mandatory=$False)]
		[string[]]
		$Ignore
	)


Write-Verbose "Storing DNS logfile format"
		$dnspattern = "^([0-9]{1,2}\/[0-9]{2}\/[0-9]{2,4}|[0-9]{2,4}-[0-9]{2}-[0-9]{2}) ([0-9: ]{7,8}\s?P?A?M?) ([0-9A-Z]{3,4} PACKET\s*[0-9A-Za-z]{8,16}) (UDP|TCP) (Snd|Rcv) ([0-9 .]{7,15}) ([0-9a-z]{4}) (.) (.) \[.*\] (.*) (\(.*)"
		Write-Verbose "Storing storing returning customobject format"
		$returnselect = @{label="Client IP";expression={[ipaddress] ($temp[6]).trim()}},
			@{label="DateTime";expression={[DateTime] (Get-Date("$($temp[1]) $($temp[2])"))}},
			@{label="QR";expression={switch($temp[8]){" " {'Query'};"R" {'Response'}}}},
			@{label="OpCode";expression={switch($temp[9]){'Q' {'Standard Query'};'N' {'Notify'};'U' {'Update'};'?' {'Unknown'}}}},
			@{label="Way";expression={$temp[5]}},
			@{label="QueryType";expression={($temp[10]).Trim()}},
			@{label="Query";expression={$temp[11] -replace "(`\(.*)","`$1" -replace "`\(.*?`\)","." -replace "^.",""}}


Write-Verbose "Getting the contents of $Path, and matching for correct rows."
		$rows = (Get-Content $Path) -match $dnspattern -notmatch 'ERROR offset' -notmatch 'NOTIMP'
		Write-Verbose "Found $($rows.count) in debuglog, processing 1 at a time."
		ForEach ($row in $rows)
		{
			Try
			{
				$temp = $Null
				$temp = [regex]::split($row,$dnspattern)
				if ($Ignore -notcontains ([ipaddress] ($temp[6]).trim()))
				{
					$true | Select-Object $returnselect
				}
			}
			Catch
			{
				Write-Verbose 'Failed to interpet row.'
				Write-Debug 'Failed to interpet row.'
				Write-Debug $row
		}
}


