<#
.SYNOPSIS  
    Retores a .bup file into it's orginal binary. When McAfee quarantines a binary, it encrypts and XORs it. This script will reverse that process and zip it using 7zip. The password for the file is !nf3ct3d!.

.NOTES  
    Version        : v.0.1  
    Prerequisite   : PowerShell
     
.USAGE 
	Put the .bup into a folder and open PowerShell. Once open, type the following:

    Powershell.exe -noexit -file "c:\location_of\unbupandzip.ps1" -path "c:\location_of\bup"


#>


Param([Parameter(Mandatory=$True,Position=1)] [string]$Path)
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
    cd $DirPath
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
    GCI -path $curPath -Exclude "*.zip" | %{ Remove-Item $_ -Force | Out-Null}
}

Function Zip-Files
{
    Param(
        $NewRenamed,
        $curPath,
        $filenme
    )
    $fileNamezip = $filenme + ".zip"
    cd $curPath
    & "C:\Program Files\7-Zip\7z.exe" "a" $fileNamezip "-p!nf3ct3d!" $NewRenamed | Out-Null
    Write-Host "Zip file was created successfully:" -NoNewline -fore Green; Write-Host "$(Test-Path ($curPath + "\" + $filenme))" -Fore Magenta
}

$files = GCI -Path $Path -Recurse | where { ! $_.PSIsContainer }

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
    $buppedFiles = GCI -Path $dirPath -Recurse -Exclude "*.bup" | where { ! $_.PSIsContainer }
    $Script:RenamedFileName = ""
    ForEach($buppedfile in $buppedFiles)
    {
        $ChangePath = $buppedFile.DirectoryName
        cd $ChangePath
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
    #Write-Host "-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=" -fore Magenta
    }
    Write-Host "Removing unneeded files...." -fore Red
    . Remove-Files $DirPath

    Write-Host "#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#" -fore Red 
    Write-Host ""

}