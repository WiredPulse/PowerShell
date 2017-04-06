<#
.SYNOPSIS
    Takes a user name and a password as input and will verify if the combination is correct. The script returns a boolean based on the result.

.PARAMETER UserName
    The samaccountname of the Active Directory user account
	
.PARAMETER Password
    The password of the Active Directory user account

.EXAMPLE
    PS C:\> Test-ADCredential.ps1 -username blue -password Secret01

    Attempts to verify if the user 'blue' exists with a password of 'Secret01'

.LINKS
    https://gallery.technet.microsoft.com/scriptcenter/Verify-the-Local-User-1e365545/view/Discussions
#>


param(
[Parameter(Mandatory=$true)][string]$Username,
[Parameter(Mandatory=$true)][string]$Password
)


if (!($UserName) -or !($Password)) 
    {
    Write-Warning 'Test-ADCredential: Please specify both user name and password'
    } 
    else 
    {
    Add-Type -AssemblyName System.DirectoryServices.AccountManagement
    $DS = New-Object System.DirectoryServices.AccountManagement.PrincipalContext('domain')
    $DS.ValidateCredentials($UserName, $Password)
    }