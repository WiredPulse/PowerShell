<#
.SYNOPSIS
   Compares two files containing file hash information in order to
   detect new, missing or changed files in directory paths.


.DESCRIPTION
   The script compares two CSV files produced by PowerShell, or two TXT files
   produced by MD5DEEP/SHA*DEEP, which contain file hashes, and then outputs
   the paths of the files which are new, which have gone missing, or whose 
   hashes have changed.  
   
   In PowerShell, the CSV files can be produced with commands like:

      dir *.exe | get-filehash | export-csv -path baseline.csv
      dir *.exe | get-filehash | export-csv -path diff.csv
  
   Note: Get-FileHash cmdlet requires PowerShell version 4.0 or later.

   The MD5DEEP tools (https://github.com/jessek/hashdeep/releases) can 
   produce hashes on any platform, including Windows, Linux and Mac OS X. 

   Note: If you use Get-FileHash | Export-Csv, make sure to save the
   output file using a ".csv" file name extension.  Without this, you
   will get a large number of errors because this script will assume
   you made the file using one of the MD5DEEP tools instead.  If you
   use one of the MD5DEEP tools, do not save the output to *.csv.


.PARAMETER ReferenceFile
    Path to a file with path and hash data.  The baseline for comparison.
    Can be a CSV file or any TXT file that uses the *DEEP format.
    Save with a ".csv" extension when using Export-Csv.

.PARAMETER DifferenceFile
    Path to a file with path and hash data.  Probably newer data.
    Can be a CSV file or any TXT file that uses the *DEEP format.
    Save with a ".csv" extension when using Export-Csv.

.PARAMETER IncludeUnchanged
    Switch to include files in the output whose hash values have
    remained the same between the ReferenceFile and DifferenceFile.

.PARAMETER SummaryOnly
    Switch to suppress all output except one final object whose properties
    contain a summary of the findings of the comparison process.

.PARAMETER NotCaseSensitive
    By default, path comparisons are case sensitive.  This switch
    compares paths after converting them to all lowercase (slower).

.EXAMPLE
   .\Compare-FileHashesList.ps1 -ReferenceFile .\baseline.csv -DifferenceFile .\diff.csv
        -
        Status      Path           
        ------      ----          
        Changed     F:\temp\one.txt   
        New         F:\temp\two.txt       
        Missing     F:\temp\three.txt 


.EXAMPLE
   .\Compare-FileHashesList.ps1 -ReferenceFile .\baseline.csv -DifferenceFile .\diff.csv -IncludeUnchanged
        
        Output will include files whose hashes have not changed.

        Status      Path           
        ------      ----          
        Changed     F:\temp\one.txt   
        New         F:\temp\two.txt       
        Missing     F:\temp\three.txt 
        Same        F:\temp\four.txt


.EXAMPLE
   .\Compare-FileHashesList.ps1 -ReferenceFile .\baseline.csv -DifferenceFile .\diff.csv -SummaryOnly

        Output is a single object with a summary of the findings (also try -Verbose).

        StartTime        : 6/6/2015 3:21:34 PM
        FinishTime       : 6/6/2015 3:21:37 PM
        RunTimeInSeconds : 1.284
        TotalDifferences : 12
        New              : 3
        Missing          : 4
        Changed          : 5


.NOTES
  Author: Enclave Consulting LLC, Jason Fossen (http://www.sans.org/sec505)  
 Version: 3.4
 Updated: 13.Oct.2015
   LEGAL: PUBLIC DOMAIN.  SCRIPT PROVIDED "AS IS" WITH NO WARRANTIES OR GUARANTEES OF 
          ANY KIND, INCLUDING BUT NOT LIMITED TO MERCHANTABILITY AND/OR FITNESS FOR
          A PARTICULAR PURPOSE.  ALL RISKS OF DAMAGE REMAINS WITH THE USER, EVEN IF
          THE AUTHOR, SUPPLIER OR DISTRIBUTOR HAS BEEN ADVISED OF THE POSSIBILITY OF
          ANY SUCH DAMAGE.  IF YOUR STATE DOES NOT PERMIT THE COMPLETE LIMITATION OF
          LIABILITY, THEN DELETE THIS FILE SINCE YOU ARE NOW PROHIBITED TO HAVE IT.
#>


[CmdletBinding()]
Param ( $ReferenceFile, $DifferenceFile, [Switch] $IncludeUnchanged, [Switch] $SummaryOnly, [Switch] $NotCaseSensitive ) 

Set-StrictMode -Version 2.0

# Verbose messages only written when -Verbose switch is used:
if ($VerbosePreference -eq 'Continue') { [System.GC]::Collect(2) } 
$Start = Get-Date  #Used to compute total run time; excludes GC time.
Write-Verbose -Message ('Start: ' + ($Start))


# Import the files into arrays, and sort on Path to optimize Compare-Object later.
# There is a big penalty for the sorting, especially when the same command *should* be
# used to produces the files each time, but there can be up to a 50x penalty with large
# files that contain very dissimilar paths or a large difference in entry counts. 
$before = Resolve-Path -Path $ReferenceFile  -ErrorAction Stop  
$after  = Resolve-Path -Path $DifferenceFile -ErrorAction Stop  


# Function to create hashtable with pre-allocated memory:
function New-TypedDictionary([Type] $KeyType, [Type] $ValueType, [Int] $InitialSize = 1000)
{
    $GenericDict = [System.Collections.Generic.Dictionary``2]
    $GenericDict = $GenericDict.MakeGenericType( @($KeyType, $ValueType) )
    New-Object -TypeName $GenericDict -ArgumentList $InitialSize
}


# Roughly estimate number of lines in file by assuming UTF-16 encoding and MD5 hashes, then preallocate memory:
$InitialSize = (Get-Item -Path $before.Path).Length / 150
$beforehashtable =  New-TypedDictionary -KeyType 'String' -ValueType 'String' -InitialSize $InitialSize
$afterhashtable  =  New-TypedDictionary -KeyType 'String' -ValueType 'String' -InitialSize $InitialSize
$changedhashtable = New-TypedDictionary -KeyType 'String' -ValueType 'String' -InitialSize 1000


# By default, do not build a list of unchanged files, it is expensive for performance:
if ($IncludeUnchanged -and -not $SummaryOnly) 
{ 
    $samehashtable = New-TypedDictionary -KeyType 'String' -ValueType 'String' -InitialSize $InitialSize 
} 

# Process the two input files: $Before and $After
if ($before.path -like '*.csv')  #Assume CSV was created with Export-CSV
{ 
    ForEach ($line in (Get-Content -ReadCount 0 -Path $before.path))
    {
        if ($line.Length -le 31 -or $line.IndexOf('#') -eq 0){ Continue }  #Ignore headers
        $line = $line.Replace('"','')
        $firstcomma = $line.IndexOf(',') 
        $secondcomma = $line.IndexOf(',', 24) 
        $path = $line.Substring($secondcomma + 1)
        if ($NotCaseSensitive) { $path = $path.ToLower() } 
        $hash = $line.Substring(($firstcomma + 1), ($line.Length - $path.length - $firstcomma - 2)) 

        Try { $beforehashtable.Add( $path, $hash ) }
        Catch { Write-Verbose -Message ('Duplicate path in ReferenceFile: ' +  $path ) }  
    }
 
    Write-Verbose -Message ('Reference CSV Imported: ' + (Get-Date)) 
    Write-Verbose -Message ('Reference CSV Size: ' + $beforehashtable.count)

    ForEach ($line in (Get-Content -ReadCount 0 -Path $after.path))
    {
        if ($line.Length -le 31 -or $line.IndexOf('#') -eq 0){ Continue }  #Ignore headers
        $line = $line.Replace('"','')
        $firstcomma = $line.IndexOf(',') 
        $secondcomma = $line.IndexOf(',', 24) 
        $path = $line.Substring($secondcomma + 1)
        if ($NotCaseSensitive) { $path = $path.ToLower() }          
        $hash = $line.Substring(($firstcomma + 1), ($line.Length - $path.length - $firstcomma - 2)) 

        Try { $afterhashtable.Add( $path, $hash ) }
        Catch { Write-Verbose -Message ('Duplicate path in DifferenceFile: ' +  $path ) }  
    }

    Write-Verbose -Message ('Difference CSV Imported: ' + (Get-Date)) 
    Write-Verbose -Message ('Difference CSV Size: ' + $afterhashtable.count)
}
else #Assume a non-CSV file was created with one of the *DEEP tools (or anything with the same output format as MD5DEEP)
{
    $regex = New-Object -TypeName System.Text.RegularExpressions.Regex -ArgumentList @( '(^[0-9a-f]{32,})\W{2,2}(.+$)', [System.Text.RegularExpressions.RegexOptions]::Compiled )

    ForEach ($line in (Get-Content -ReadCount 0 -Path $before.path))
    {
        if ($line.Length -le 31 -or $line.IndexOf('#') -eq 0){ Continue }  #Ignore headers
        $arr = $regex.Split($line)
        Try { $beforehashtable.Add( $arr[2], $arr[1] ) }
        Catch { Write-Verbose -Message ('Duplicate path in ReferenceFile: ' +  $arr[2] ) }  
    }

    Write-Verbose -Message ('Reference Array Imported: ' + (Get-Date)) 
    Write-Verbose -Message ('Reference  Array Size: ' + $beforehashtable.count)

    ForEach ($line in (Get-Content -ReadCount 0 -Path $after.path))
    {
        if ($line.Length -le 31 -or $line.IndexOf('#') -eq 0){ Continue }  #Ignore headers
        $arr = $regex.Split($line)
        Try { $afterhashtable.Add( $arr[2], $arr[1] ) }
        Catch { Write-Verbose -Message ('Duplicate path in DifferenceFile: ' +  $arr[2] ) }  
    }

    Write-Verbose -Message ('Difference Array Imported: ' + (Get-Date)) 
    Write-Verbose -Message ('Difference Array Size: ' + $afterhashtable.count)

    $regex = $null 
}


# Sanity checks:
if ($beforehashtable.count -le 0) { throw "$ReferenceFile is empty!" ; exit } 
if ($afterhashtable.count -le 0)  { throw "$DifferenceFile is empty!" ; exit } 


# Define custom object to be outputted for each file comparison:
$file = '' | select Status,Path


# Set counters used in summary: c = changed, n = new, m = missing.
$c = $n = $m = 0          


# Look for new and changed files from the $DifferenceFile:
foreach ($key in $afterhashtable.Keys) 
{ 
    if ($beforehashtable.ContainsKey($key))
    { 
        if ($beforehashtable.Item($key) -ne $afterhashtable.Item($key)) 
        { $changedhashtable.Add( $key, ' ' ) } 
        elseif ($IncludeUnchanged -and -not $SummaryOnly)
        { $samehashtable.Add( $key, ' ' ) } 
    }
    else
    {
        if (-not $SummaryOnly)
        { 
            $file.path = $key
            $file.status = 'New'    
            $file 
        } 
        $n++ 
    }

} 

Write-Verbose -Message ('New and changed files processed: ' + (Get-Date)) 


# Look for missing and changed files from the $ReferenceFile (beware of duplicates in hashtables):
foreach ($key in $beforehashtable.Keys) 
{ 
    if ($afterhashtable.ContainsKey($key))
    { 
        if ($beforehashtable.Item($key) -ne $afterhashtable.Item($key)) 
        { 
            if (-not $changedhashtable.ContainsKey($key))
            { $changedhashtable.Add( $key, ' ' ) } 
        } 
        elseif ($IncludeUnchanged -and -not $SummaryOnly)
        { 
            if (-not $samehashtable.ContainsKey($key))
            { $samehashtable.Add( $key, ' ' ) }
        } 
    }
    else
    {
        if (-not $SummaryOnly)
        { 
           $file.path = $key
           $file.status = 'Missing'   
           $file 
        } 
        $m++ 
    }

} 

Write-Verbose -Message ('Missing and changed files processed: ' + (Get-Date)) 


# Output changed files only if necessary:
$c = $changedhashtable.count
if (-not $SummaryOnly)
{
    $file.Status = 'Changed'
    ForEach ($key in $changedhashtable.Keys) { $file.Path = $key ; $file } 
}


# Output unchanged files only if necessary:
if ($IncludeUnchanged -and -not $SummaryOnly)
{
    $file.Status = 'Same'
    ForEach ($key in $samehashtable.Keys) { $file.Path = $key ; $file } 
}


Write-Verbose -Message ('Finish: ' + (Get-Date))
Write-Verbose -Message ('Total Run Time: ' + ( [MATH]::Round( ((Get-date) - $Start).TotalSeconds, 3 )) + ' seconds')
Write-Verbose -Message ('Total Differences: ' + ($n + $m + $c))
Write-Verbose -Message "New: $n Missing: $m Changed: $c"



if ($SummaryOnly)
{
    $report = '' | select StartTime,FinishTime,RunTimeInSeconds,TotalDifferences,New,Missing,Changed
    $report.StartTime = $Start
    $report.FinishTime = Get-Date
    $report.RunTimeInSeconds = [MATH]::Round( ((Get-date) - $Start).TotalSeconds, 3 )
    $report.TotalDifferences = $n + $m + $c 
    $report.New = $n 
    $report.Missing = $m 
    $report.Changed = $c 
    $report 
}


# END-OF-SCRIPT