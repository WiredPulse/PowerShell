<#
.SYNOPSIS  
    When McAfee or Symantec quarantines a binary, it XORs it, renames the file with random characters, and changes the extension to .bup. In the end, this all makes the file unusable on
    the system. This script will reverses that process using 7-zip, the publicly known key, and then zips it with the password "malware" (no quotes). The script ultimately restores the binary 
    into it's orginal state. 

.PARAMETER -path 
    Used to specify the path to the .bup. The .bup should be in a directory by itself.

.EXAMPLE 
    PS C:\> .\Invoke-Unbup.ps1 -path "C:\Infected\7e171db0629d0.bup"

    Runs the script againt the .bup file in the C:\Infected directory. Do note that the .bup should be in a directory by itself.

.NOTES  
    Version        : v1.1  
    Prerequisite   : PowerShell v2 or newer, 7-zip
#>


Param([Parameter(Mandatory=$True)][string]$Path)

if(test-path "C:\Program Files\7-Zip\7z.exe")
    {
    Write-Host $path
    Function Un-Bup
        {
        param([string] $key="6A",[string] $iFile)
        Write-Host "Working $iFile" -fore Yellow
        $key = "0x" + $key
        $oFile = $iFile + ".out"
        #Read file in bytes
        $bytes = [System.IO.File]::ReadAllBytes("$iFile")
 
        #Where the magic happens
        for($i=0; $i -lt $bytes.count ; $i++)
            {
            $bytes[$i] = $bytes[$i] -bxor $key
            }
 
        #write file out in bytes
        [System.IO.File]::WriteAllBytes("$oFile", $bytes)
        write-host "[!] " -foregroundcolor green -nonewline; Write-host "File: " -nonewline; Write-host "$iFile " -foregroundcolor yellow -nonewline;Write-host "XOR'd with key " -nonewline;Write-host "$key. " -foregroundcolor cyan -nonewline;Write-host "Saved to " -nonewline;Write-host "$oFile" -foregroundcolor yellow -nonewline;Write-host ".";
        }

    Function Unzip-Bup
        {
        Param(
            $BupPath,
            $dirPath
        )
        Set-Location $DirPath
        & "C:\Program Files\7-Zip\7z.exe" "x" $BupPath | Out-Null
        }

    Function Make-Folder
        {
        Param(
            $file,
            $WorkingPath
        )
        $newpath = ""
        $newFilename2 = ""
        $NewPath = $WorkingPath + "\" + $file.BaseName
        New-Item -Path $WorkingPath -Name $file.BaseName -ItemType Directory -Force | Out-Null
        Move-item -path $($file.FullName) -Destination $newPath
        $newFileName2 = $NewPath + "\" + $file.Name

        Return $newFileName2
        }

    Function Remove-Files
        {
        Param(
            $curPath
        )
        Get-ChildItem -path $curPath -Exclude "*.zip" | %{ Remove-Item $_ -Force | Out-Null}
        }

    Function Zip-Files
        {
        Param(
            $NewRenamed,
            $curPath,
            $filenme
        )
        $fileNamezip = $filenme + ".zip"
        Set-Location $curPath
        & "C:\Program Files\7-Zip\7z.exe" "a" $fileNamezip "-pmalware" $NewRenamed | Out-Null
        Write-Host "Zip file was created successfully:" -NoNewline -fore Green; Write-Host "$(Test-Path ($curPath + "\" + $filenme))" -Fore Magenta
        }

    $files = Get-ChildItem -Path $Path -Recurse | where { ! $_.PSIsContainer }
    $path = $path2[0..($path2.Length)] -join('\')

    ForEach($file in $files) 
        { 
        Write-Host "#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#" -fore Red
        Write-Host "Beginning to process $($file.Name)..." -Fore Magenta
        Write-Host ""
        $newFileName  = . Make-Folder $file $Path
        $DirPath = $Path + "\" + $file.BaseName
        Write-Host "Unzipping $newFileName" -fore Yellow
        . Unzip-Bup $newFileName $dirPath
        $buppedFiles = @()
        $buppedFiles = Get-ChildItem -Path $dirPath -Recurse -Exclude "*.bup" | where { ! $_.PSIsContainer }
        $Script:RenamedFileName = ""
        ForEach($buppedfile in $buppedFiles)
            {
            $ChangePath = $buppedFile.DirectoryName
            Set-Location $ChangePath
            $WorkBupPath = $buppedFile.FullName
            Write-Host ""
            Write-Host "-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=" -fore Magenta
            Write-host "About to unbup: $WorkBupPath" -fore cyan
            . Un-Bup 6A $WorkBupPath
            $bupFilename = $buppedFile.Name
            $bupFileNamePath = $ChangePath + "\" + $bupFilename
            $fullBupName = $buppedfile.FullName + ".out"
            If($fullBupName -match "Details.out")
                {
                Write-Host "Grabbing new file name..." -fore Yellow
                $fileName = (Get-Content -Path $fullBupName) | ?{$_ -match "^OriginalName=.+"}
                $Script:RenamedFileName = $fileName.split('\')[-1]
                }
            ElseIf ($fullBupName -match "file_0.out")
                {
                Write-Host "Renaming the file to original file name..." -fore Green
                $NewRenamed = $ChangePath + "\" + $Script:RenamedFilename
                Rename-Item $fullBupName -NewName $NewRenamed -Force
            
                Write-Host "%^%^%^%^%^%^%^%^%^%^%" -fore Green
                Write-Host "Zipping up the package with known password...." -fore White
                . Zip-Files $NewRenamed $ChangePath $Script:RenamedFileName
                Write-Host "%^%^%^%^%^%^%^%^%^%^%" -fore Green
                }
            Write-Host "-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=" -fore Magenta
            }
            Write-Host "Removing unneeded files...." -fore Red
            . Remove-Files $DirPath

            Write-Host "#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#" -fore Red 
            Write-Host ""
        }

    }
else
    {
    write-host "7-zip not installed on this system at C:\Program Files\7-Zip\... install 7-zip before proceeding" -ForegroundColor red
    }