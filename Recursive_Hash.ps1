<# Recursively hashes a local filesystem and output to .csv
#>

dir -Recurse |Get-FileHash -Algorithm MD5 |Export-Csv -Path C:\users\admin\desktop\Output.csv