<# 
.SYNOPSIS
    Does a recursive audit of a file structure and depicts to the applied permissions. When running the script, you will be asked to input the top-level 
    directory in which you want to start from. 

.LINK
    https://jfrmilner.wordpress.com/2011/05/01/audit-ntfs-permissions-powershell-script/
#>

$some_path = read-host "Enter the path to the top-level directory to start from"

function Get-PathPermissions {
 
param ( [Parameter(Mandatory=$true)] [System.String]${Path} )
 
    begin {
    $root = Get-Item $Path
    ($root | get-acl).Access | Add-Member -MemberType NoteProperty -Name "Path" -Value $($root.fullname).ToString() -PassThru
    }
    process {
    $containers = Get-ChildItem -path $Path -recurse | ? {$_.psIscontainer -eq $true}
    if ($containers -eq $null) {break}
        foreach ($container in $containers)
        {
        (Get-ACL $container.fullname).Access | ? { $_.IsInherited -eq $false } | Add-Member -MemberType NoteProperty -Name "Path" -Value $($container.fullname).ToString() -PassThru
        }
    }
}

Get-PathPermissions $some_path | Export-Csv .\PermissionsAudit.csv –NoTypeInformation