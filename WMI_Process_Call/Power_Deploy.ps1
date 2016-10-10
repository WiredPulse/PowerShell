#This script allows you to install programs, run scripts, and perform functions remotely using WMI

<#Requirements:
    - Requires an account on the remote computer (Hopefully one with permissions)
    - Requires C$ or Admin Share
#>

<#How to use:
    1: Replace each quoted text que with your information
    2: Save your changes
    3: Execute the script
#>


$ComputerList = Get-Content "ENTER COMPUTERNAME FILE LOCATION HERE"

Foreach($Computer in $ComputerList)
    {
    Copy-Item "LOCATION OF FILE/SCRIPT ON YOUR COMPUTER" \\$Computer\C$\.
    $Action = [wmiclass] "\\$Computer\ROOT\CIMv2:Win32_Process"
    $Method = $Action.create("Powershell /c Start-Process LOCATION OF THE FILE/SCRIPT YOU WANT TO USE")
    }