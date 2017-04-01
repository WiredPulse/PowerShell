<#
.SYNOPSIS  
    Convert given string to rot13

.NOTES  
    File Name      : Convert-Rot13.ps1
    Version        : v.0.1  
    Created        : 06 MAY 16

.PARAMETER Rot13String
    Used to input a string to convert.

.EXAMPLE
    PS c:\> .\Convert-Rot13.ps1 -rot13string hamburger

    Converts the string 'hamburger' to Rot13. 

#>


[CmdletBinding()]
param(
    [Parameter(
        Mandatory = $true,
        ValueFromPipeline = $true
    )]
    [String]
    $rot13string
	)

    
[String] $string = $null;
$rot13string.ToCharArray() |
ForEach-Object 
    {
    Write-Verbose "$($_): $([int] $_)"
    if((([int] $_ -ge 97) -and ([int] $_ -le 109)) -or (([int] $_ -ge 65) -and ([int] $_ -le 77)))
        {
        $string += [char] ([int] $_ + 13);
        }
    elseif((([int] $_ -ge 110) -and ([int] $_ -le 122)) -or (([int] $_ -ge 78) -and ([int] $_ -le 90)))
        {
        $string += [char] ([int] $_ - 13);
        }
    else
        {
        $string += $_
        }
    }

$string
