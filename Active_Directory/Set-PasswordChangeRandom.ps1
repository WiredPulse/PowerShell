<#
.SYNOPSIS
    Changes passwords to every account in a specified OU using a algorithm that randomly selects passwords. The newly implemented 
    password, along with the samaccountname are written to a file for you to reference and inform the applicable people of the change.
#>


write-host "Input the OU you want to search in. Example: OU=Texas,DC=sandbox,DC=local" -ForegroundColor Cyan
$searchbase = Read-host " "

import-module activedirectory

# Creates an emtpty file
[String]$path= ".\NewStuff.txt"

# Checks to see if password file already exists and if it does, deletes it.
if ($path -ne $null){Remove-Item $path -ErrorAction SilentlyContinue}

# Writes the time\date to the file so we know when it was done
$date = Get-Date
Write-Output "Generated on" $date >> NewStuff.txt

# Gets the users inside the OU specified
$users = Get-ADUser -filter * -SearchBase $searchbase

# Loops through each samaccountname
foreach($Name in $users.samaccountname)
    {
    # Generates a random password
    function RandomPassword()
        {
        $password = ""
        while($password.length -le 14)
            {
            $char = 
            "a","b","c","d","e","f","g","h","i","j","k","l","m","n","o","p","q","r","s","t","u","v","w","x","y","z","A","B","C","D","E","F","G","H","I","J","K","L","M","N","O","P","Q","R","S","T","U","V","W","X","Y","Z","0","1","2","3","4","5","6","7","8","9","!","@","#","$","%","^","&","*","(",")" | Get-random
            $password = $password + $char
            }
            return $password
        }
        $NewPassword = RandomPassword

        # Changes the password and sets the option to change password upon next logon
        Set-ADAccountPassword -Identity $Name -Reset -NewPassword (ConvertTo-SecureString -AsPlainText $NewPassword -Force)
        Get-ADUser -Identity $Name |Set-ADUser -ChangePasswordAtLogon:$true

        # Writing samaccountname and new password to file for reference
        Write-Output "UserID:$name `t Password:$NewPassword" `n`n| Format-Table -AutoSize >> NewStuff.txt
    }