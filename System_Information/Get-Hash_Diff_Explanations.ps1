<#

    .SYNOPSIS
        Reads in baseline hashes previously captured, gets new hashes, and compares the two based on MD5 and SHA1. The difference is output to the screen. 

    .REQUIREMENTS
        - PowerShell version 4 
        - A baseline of hashes made using the following syntax "Get-ChildItem C:\windows\system32 -Recurse | Get-FileHash -Algorithm md5 
        | export-csv .\baseline_MD5_$env:COMPUTERNAME.csv -NoTypeInformation"

#>

#Requires -Version 4.0

Get-ChildItem "C:\windows\system32" -Recurse | Get-FileHash -Algorithm md5 | export-csv .\New_MD5_$env:COMPUTERNAME.csv -NoTypeInformation
Get-ChildItem "C:\windows\system32" -Recurse | Get-FileHash -Algorithm sha1 | export-csv .\New_SHA1_$env:COMPUTERNAME.csv -NoTypeInformation

$base_md5 = import-csv ".\baseline_md5_$env:COMPUTERNAME.csv"
$base_sha1 = import-csv ".\baseline_sha1_$env:COMPUTERNAME.csv"

$new_md5 = import-csv "New_MD5_$env:COMPUTERNAME.csv"
$new_sha1 = import-csv "New_SHA1_$env:COMPUTERNAME.csv"

$compare_md5 = Compare-Object $base_md5 $new_md5 -Property Hash, Path
$compare_sha1 = Compare-Object $base_sha1 $new_sha1 -Property Hash, Path

$compare_md5 | %{
$element=$_
$ListSameElement=$compare_md5 | where { $_.Path -eq $element.Path -and $_.Hash -ne $element.Hash} | select -First 1

if ($_.SideIndicator -eq '=>')
{
    if ($ListSameElement.Count -eq 0)
    {
    $Explain="New File Created"
    $OldHash=""
    }
    else
    {
    $Explain="Hash Modified"
    $OldHash=$ListSameElement.Hash
    }

[pscustomobject]@{Hash=$element.hash;File=$element.Path;"Old HAsh"=$OldHash; Explanation=$Explain} 

}

elseif ($_.SideIndicator -eq '<=' -and $ListSameElement.Count -eq 0)
{
     [pscustomobject]@{Hash="";File=$element.Path;"Old HAsh"=$element.hash; Explanation="File Deleted"} 
}

}


$compare_sha1 | %{
$element=$_
$ListSameElement=$compare_sha1 | where { $_.Path -eq $element.Path -and $_.Hash -ne $element.Hash} | select -First 1

if ($_.SideIndicator -eq '=>')
{
    if ($ListSameElement.Count -eq 0)
    {
    $Explain="New File Created"
    $OldHash=""
    }
    else
    {
    $Explain="Hash Modified"
    $OldHash=$ListSameElement.Hash
    }

[pscustomobject]@{Hash=$element.hash;File=$element.Path;"Old HAsh"=$OldHash; Explanation=$Explain} 

}

elseif ($_.SideIndicator -eq '<=' -and $ListSameElement.Count -eq 0)
{
     [pscustomobject]@{Hash="";File=$element.Path;"Old HAsh"=$element.hash; Explanation="File Deleted"} 
}

}


