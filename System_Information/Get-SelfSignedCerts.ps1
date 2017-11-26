Get-ChildItem Cert: -recurse | where{$_.subject -ne $null} | where{$_.subject -eq $_.issuer} | select notbefore, notaftersubject, issuer | Out-GridView
