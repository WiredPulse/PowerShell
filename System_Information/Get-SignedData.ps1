<# Checks to see if the files in a suppied directory are signed. 
#>

# The directory we will look for files in
$dir2search = "c:\windows"
$some_files = Get-ChildItem $dir2search | where-object {! $_.PSIsContainer} | select name | select name -ExpandProperty name


foreach($each_file in $some_files){
#(Get-AuthenticodeSignature $each_file).SignerCertificate.Subject
Get-AuthenticodeSignature $dir2search\$each_file
}

