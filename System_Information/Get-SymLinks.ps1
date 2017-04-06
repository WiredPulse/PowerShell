<#
Searches for linked files and folders
#>

Get-ChildItem C:\Users\blue\Desktop -Recurse| Where-Object { $_.Attributes -match "ReparsePoint" }| select name, CreationTime, LastWriteTime, Target