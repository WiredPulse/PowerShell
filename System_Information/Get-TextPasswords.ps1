<#
SYNOPSIS:
    Searches the filesystem for text files that contains passwords (potentially). The hits fit the criteria of at least four characters but no more than 15 
    with one being an upper, lower, number, and special character.

USAGE: 
    Call upon file from PowerShell (.\Get-TextPasswords.ps1)

REQUIREMENTS:
    At least PowerShell v2
#>


# ============================================================================== 
# Gets a listing of text files
# ============================================================================== 
$items = Get-ChildItem c:\ -Recurse -ErrorAction ignore | where {$_.extension -eq ".txt"}

# ============================================================================== 
# Important Variables
# ============================================================================== 
$current_user = [Environment]::UserName 
$newline = "`r`n"

# ============================================================================== 
# Loops through and searches for passwords
# ============================================================================== 
foreach($item in $items){
$hits = Get-Content $item.fullname -ErrorAction ignore | Select-String -Pattern '^(?=.*\d)(?=.*[a-z])(?=.*[A-Z])(?!.*\s).{4,15}$' | select-object line, linenumber
$file_hit += $item.fullname + '+' +  ($hits -replace "@{line=",'' -replace "; linenumber=",'+' -replace "}",'') + $newline
}

# ============================================================================== 
# Writes data to a file 
# ============================================================================== 
add-content -Path "c:\users\$current_user\desktop\hits.txt" -Value ($file_hit) 
  
# ============================================================================== 
# Splits data into two columns and exports it as a csv 
# ============================================================================== 
import-csv "c:\users\$current_user\desktop\hits.txt" -Delimiter '+' -Header 'Path', 'Hits', 'LineNumber' |export-csv c:\users\$current_user\desktop\hits.xml 
  
# ============================================================================== 
# Cleanup 
# ============================================================================== 
Remove-Item "c:\users\$current_user\desktop\hits.txt" 
Remove-Variable file_hit, hits, item, items

