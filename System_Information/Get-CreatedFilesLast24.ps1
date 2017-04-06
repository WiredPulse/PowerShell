<# 
.SYNOPSIS
    Gets all files created within the last 24 hours
#>

# ==============================================================================  
# Variables to change
# ==============================================================================
$computers = '127.0.0.1'

# ==============================================================================  
# Important Variables
# ==============================================================================
$newline = "`r`n" 
$current_user = [Environment]::UserName 

# ==============================================================================  
# Loops through gets directory listing and sub-directories with creation time
# ==============================================================================
foreach($cpu in $computers)
    { 
    $dir_list = Get-ChildItem -Path c:\ -recurse -force -erroraction 'silentlycontinue' | Where-Object {$_.CreationTime -gt (Get-Date).AddDays(-1) } | Select-Object FullName, CreationTime, Length | sort creationtime -Descending
        foreach($new_dir in $dir_list)
            { 
            $new_table += $cpu + '+' + ($new_dir -replace '@{FullName=','' -replace '; CreationTime=','+' -replace '; Length=','+' -replace '}','') + $newline
            }
    }

# ==============================================================================  
# Writes data to a file  
# ==============================================================================  
add-content -Path "c:\users\$current_user\desktop\Last24.txt" -Value ($new_table)  
    
# ==============================================================================  
# Splits data into three columns and exports it as a csv  
# ==============================================================================  
import-csv "c:\users\$current_user\desktop\Last24.txt" -Delimiter '+' -Header 'System', 'Path', 'Time\Date' |export-csv c:\users\$current_user\desktop\CreatedLast24.csv  
    
# ==============================================================================  
# Cleanup  
# ==============================================================================  
Remove-Item "c:\users\$current_user\desktop\Last24.txt"  
Remove-Variable dir_list, new_table, new_dir  
