<#
    .SYNOPSIS  
        Convert given string using rot13

    .NOTES  
        File Name      : Convert-Rot13.ps1
        Version        : v.0.1  
        Prerequisite   : PowerShell
        Created        : 06 MAY 16


    ####################################################################################

#>


function Convert-rot13
{
     [CmdletBinding()]
     param(
          [Parameter(
              Mandatory = $false,
              ValueFromPipeline = $true
          )]
          [String]
          $rot13string
     )
    
     [String] $string = $null;
     $rot13string.ToCharArray() |
     ForEach-Object {
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
}