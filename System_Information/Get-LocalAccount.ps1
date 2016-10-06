#--------------------------------------------------------------------------------- 
#The sample scripts are not supported under any Microsoft standard support 
#program or service. The sample scripts are provided AS IS without warranty  
#of any kind. Microsoft further disclaims all implied warranties including,  
#without limitation, any implied warranties of merchantability or of fitness for 
#a particular purpose. The entire risk arising out of the use or performance of  
#the sample scripts and documentation remains with you. In no event shall 
#Microsoft, its authors, or anyone else involved in the creation, production, or 
#delivery of the scripts be liable for any damages whatsoever (including, 
#without limitation, damages for loss of business profits, business interruption, 
#loss of business information, or other pecuniary loss) arising out of the use 
#of or inability to use the sample scripts or documentation, even if Microsoft 
#has been advised of the possibility of such damages 
#--------------------------------------------------------------------------------- 

#requires -Version 2.0

<#
 	.SYNOPSIS
       This script can be list all of local user account.
    .DESCRIPTION
       This script can be list all of local user account.
    .PARAMETER  <AccountName>
		Specifies the local user account you want to search.
	.PARAMETER	<ComputerName <string[]>
		Specifies the computers on which the command runs. The default is the local computer. 
	.PARAMETER  <Credential>
		Specifies a user account that has permission to perform this action. 
	.EXAMPLE
        C:\PS> C:\Script\GetLocalAccount.ps1
		
		This example shows how to list all of local users on local computer.	
	.EXAMPLE
        C:\PS> C:\Script\GetLocalAccount.ps1 | Export-Csv -Path "D:\LocalUserAccountInfo.csv" -NoTypeInformation
		
		This example will export report to csv file. If you attach the <NoTypeInformation> parameter with command, it will omit the type information 
		from the CSV file. By default, the first line of the CSV file contains "#TYPE " followed by the fully-qualified name of the object type.
    .EXAMPLE
        C:\PS> C:\Script\GetLocalAccount.ps1 -AccountName "Administrator","Guest"
		
		This example shows how to list local Administrator and Guest account information on local computer.
    .EXAMPLE
        C:\PS> $Cre=Get-Credential
		C:\PS> C:\Script\GetLocalAccount.ps1 -Credential $Cre -Computername "WINSERVER" 
		
		This example lists all of local user accounts on the WINSERVER remote computer.
#>

Param
(
	[Parameter(Position=0,Mandatory=$false)]
	[ValidateNotNullorEmpty()]
	[Alias('cn')][String[]]$ComputerName=$Env:COMPUTERNAME,
	[Parameter(Position=1,Mandatory=$false)]
	[Alias('un')][String[]]$AccountName,
	[Parameter(Position=2,Mandatory=$false)]
	[Alias('cred')][System.Management.Automation.PsCredential]$Credential
)
	
$Obj = @()

Foreach($Computer in $ComputerName)
{
	If($Credential)
	{
		$AllLocalAccounts = Get-WmiObject -Class Win32_UserAccount -Namespace "root\cimv2" `
		-Filter "LocalAccount='$True'" -ComputerName $Computer -Credential $Credential -ErrorAction Stop
	}
	else
	{
		$AllLocalAccounts = Get-WmiObject -Class Win32_UserAccount -Namespace "root\cimv2" `
		-Filter "LocalAccount='$True'" -ComputerName $Computer -ErrorAction Stop
	}
	
	Foreach($LocalAccount in $AllLocalAccounts)
	{
		$Object = New-Object -TypeName PSObject
		
		$Object|Add-Member -MemberType NoteProperty -Name "Name" -Value $LocalAccount.Name
		$Object|Add-Member -MemberType NoteProperty -Name "Full Name" -Value $LocalAccount.FullName
		$Object|Add-Member -MemberType NoteProperty -Name "Caption" -Value $LocalAccount.Caption
      	$Object|Add-Member -MemberType NoteProperty -Name "Disabled" -Value $LocalAccount.Disabled
      	$Object|Add-Member -MemberType NoteProperty -Name "Status" -Value $LocalAccount.Status
      	$Object|Add-Member -MemberType NoteProperty -Name "LockOut" -Value $LocalAccount.LockOut
		$Object|Add-Member -MemberType NoteProperty -Name "Password Changeable" -Value $LocalAccount.PasswordChangeable
		$Object|Add-Member -MemberType NoteProperty -Name "Password Expires" -Value $LocalAccount.PasswordExpires
		$Object|Add-Member -MemberType NoteProperty -Name "Password Required" -Value $LocalAccount.PasswordRequired
		$Object|Add-Member -MemberType NoteProperty -Name "SID" -Value $LocalAccount.SID
		$Object|Add-Member -MemberType NoteProperty -Name "SID Type" -Value $LocalAccount.SIDType
		$Object|Add-Member -MemberType NoteProperty -Name "Account Type" -Value $LocalAccount.AccountType
		$Object|Add-Member -MemberType NoteProperty -Name "Domain" -Value $LocalAccount.Domain
		$Object|Add-Member -MemberType NoteProperty -Name "Description" -Value $LocalAccount.Description
		
		$Obj+=$Object
	}
	
	If($AccountName)
	{
		Foreach($Account in $AccountName)
		{
			$Obj|Where-Object{$_.Name -like "$Account"}
		}
	}
	else
	{
		$Obj
	}
}