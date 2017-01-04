<#
Searches for linked files and folders
#>

Get-ChildItem c:\ -Recurse| Where-Object { $_.Attributes -match "ReparsePoint" }| select name, CreationTime, LastWriteTime, Target