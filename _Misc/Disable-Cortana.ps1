Function Disable-Cortana
{  
    $path1 = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"   
    $path2 = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"  

    if(!(Test-Path -Path $path1)) 
        { 
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows" -Name "Windows Search"
        } 
    if(!(Test-Path -Path $path2)) 
        { 
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\" -Name "Windows Search"
        }

    Set-ItemProperty -Path $path1 -Name "AllowCortana" -Value 0 
    Set-ItemProperty -Path $path2 -Name "AllowCortana" -Value 0 
    # Restart Explorer to change it immediately... it will take a minute or so your taskbar to return
    Stop-Process -name explorer
}

Disable-Cortana
