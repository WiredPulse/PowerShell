# Parse the Message property into individual properties and then filter...
Get-WinEvent -FilterHashtable @{logname='system';id='7045'} | Select-Object timecreated, @{Label="ServiceName";Expression={$_.properties.value[0]}}, 
     @{Label="ImagePath";Expression={$_.properties.value[1]}}, @{Label="ServiceType";Expression={$_.properties.value[2]}}, @{Label="StartType";Expression={$_.properties.value[3]}}, 
     @{Label="AccountName";Expression={$_.properties.value[4]}} | Where-Object{$_.servicename -eq "Bluetooth Port Driver"} 

# Return only the Service names...
Get-WinEvent -FilterHashtable @{logname='system';id='7045'} | Select-Object timecreated, @{Label="ServiceName";Expression={$_.properties.value[0]}}