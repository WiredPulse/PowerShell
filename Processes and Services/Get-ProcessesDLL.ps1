# Displays all running processes and their DLLs

Foreach ( $item in ps)
{
Write-Host “PID:” $item.Id “Name:” $item.name
Get-Process -Id $item.Id| select -ExpandProperty modules| Format-Table –AutoSize
}