<#
This script will return the sid for all Domain computer accounts.
#>

import-module activedirectory
get-adcomputer -filter * | select Name, SID