<#
.SYNOPSIS
    This script will return the SID for a specified group.

.LINK
    
#>

param(
[Parameter(Mandatory=$true)][string]$Group
)

import-module activedirectory
Get-ADGroup -Identity $group
