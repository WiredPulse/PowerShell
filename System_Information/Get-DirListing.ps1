<# 
.SYNOPSIS
    Reads in a list of Computers and returns a directory listing of a specified directory along with the creation time\date, and whether or not it is hidden 
    within the filesystem. This script can be run remotely but it is not the fastest.
 #>

$computers = Get-Content .\computers.txt

# Signifies the root of the c:\ and all it's sub-directories
# Get-WmiObject -namespace root\cimv2 -class win32_directory -ComputerName $computers | select PSComputerName, Name, @{label='CreationTime';expression={$_.ConvertToDateTime($_.CreationDate)}}, Hidden | Export-CSV ./dir_listing.csv -NoTypeInformation
    
# Specifies everything in the c:\windows\syswow directory and all sub-directories
Get-WmiObject -namespace root\cimv2 -class win32_directory -ComputerName $computers -filter "Name LIKE 'C:\\windows\\syswow64%'" | select PSComputerName, Name, @{label='CreationTime';expression={$_.ConvertToDateTime($_.CreationDate)}}, Hidden | Export-CSV ./dir_listing.csv -NoTypeInformation
    
