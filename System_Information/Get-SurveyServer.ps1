<#
.SYNOPSIS  
    Surveys a server OS to gain a picture of the system's use and purpose.

#>


Import-module ActiveDirectory
Import-module ServerManager

$hostname = (hostname)
$ipV4 = Test-Connection -ComputerName (hostname) -Count 1 | select -ExpandProperty IPV4Address
$ipV4 = $ipV4.ipAddressToString
$outFile = $ipV4 + "_" + $hostname + ".txt"
new-item -name $outfile -itemtype file -force

echo "Survey Results for:" $hostname | out-File $outFile
echo `r | out-File $outFile -Append
echo "IP Address:" $ipV4 | out-File $outFile -Append
date | out-File $outFile -Append


echo "######################################################" | out-File $outFile -Append
echo "#                CHECKING CURRENT USER               #" | out-File $outFile -Append
echo "######################################################" | out-File $outFile -Append
echo `r | out-File $outFile -Append
quser | out-File $outFile -Append

echo `r | out-File $outFile -Append
echo "######################################################" | out-File $outFile -Append
echo "#            CHECKING OS DETAILS AND SYS INFO        #" | out-File $outFile -Append
echo "######################################################" | out-File $outFile -Append

echo `r | out-File $outFile -Append
echo "######################################################" | out-File $outFile -Append
echo "#                       SYSTEMINFO                   #" | out-File $outFile -Append
echo "######################################################" | out-File $outFile -Append
systeminfo | out-File $outFile -Append
nbtstat -n | out-File $outFile -Append

echo `r | out-File $outFile -Append
echo "######################################################" | out-File $outFile -Append
echo "#                DATE    TIME/DATE ON SYSTEM         #" | out-File $outFile -Append
echo "######################################################" | out-File $outFile -Append
date | out-File $outFile -Append

echo `r | out-File $outFile -Append
echo "######################################################" | out-File $outFile -Append
echo "#                  FSUTIL  SHOW LOCAL DRIVES         #" | out-File $outFile -Append
echo "######################################################" | out-File $outFile -Append
fsutil | out-File $outFile -Append

echo `r | out-File $outFile -Append
echo "######################################################" | out-File $outFile -Append
echo "#            TREE /A  SHOW LOCAL DIRECTORY TREE      #" | out-File $outFile -Append
echo "######################################################" | out-File $outFile -Append
tree /A | out-File $outFile -Append

echo `r | out-File $outFile -Append
echo "######################################################" | out-File $outFile -Append
echo "#    SCHTASKS /QUERY   SHOW ALL SCHEDULED TASKS      #" | out-File $outFile -Append
echo "######################################################" | out-File $outFile -Append
schtasks /query | out-File $outFile -Append

echo `r | out-File $outFile -Append
echo "######################################################" | out-File $outFile -Append
echo "#         CHECKING SERVER ROLES AND FEATURES         #" | out-File $outFile -Append
echo "######################################################" | out-File $outFile -Append
get-WindowsFeature | out-File $outFile -Append
echo `r | out-File $outFile -Append
echo "######################################################" | out-File $outFile -Append
echo "#             CHECKING INSTALLED SOFTWARE            #" | out-File $outFile -Append
echo "######################################################" | out-File $outFile -Append
Get-WmiObject -Class Win32_Product | Select-Object -Property Name | out-File $outFile -Append

echo `r | out-File $outFile -Append
echo "######################################################" | out-File $outFile -Append
echo "#                  PROCESS ANALYSIS                  #" | out-File $outFile -Append
echo "######################################################" | out-File $outFile -Append

echo `r | out-File $outFile -Append
echo "######################################################" | out-File $outFile -Append
echo "#                PROCESS LIST WITH DLLs              #" | out-File $outFile -Append
echo "######################################################" | out-File $outFile -Append
tasklist /m | out-File $outFile -Append

echo `r | out-File $outFile -Append
echo "######################################################" | out-File $outFile -Append
echo "#              PROCESS LIST WITH SERVICES            #" | out-File $outFile -Append
echo "######################################################" | out-File $outFile -Append
tasklist /svc | out-File $outFile -Append

echo `r | out-File $outFile -Append
echo "######################################################" | out-File $outFile -Append
echo "#       NET START CURRENTLY RUNNING SERVICES         #" | out-File $outFile -Append
echo "######################################################" | out-File $outFile -Append
net start | out-File $outFile -Append

echo `r | out-File $outFile -Append
echo "######################################################" | out-File $outFile -Append
echo "#             CHECKING PREFETCH DIRECTORY            #" | out-File $outFile -Append
echo "######################################################" | out-File $outFile -Append
dir $env:systemroot\prefetch | out-File $outFile -Append

echo `r | out-File $outFile -Append
echo "######################################################" | out-File $outFile -Append
echo "#                    CHECK SERVICES                  #" | out-File $outFile -Append
echo "######################################################" | out-File $outFile -Append
sc.exe query | out-File $outFile -Append

echo `r | out-File $outFile -Append
echo "######################################################" | out-File $outFile -Append
echo "#                    NETWORKING INFO                 #" | out-File $outFile -Append
echo "######################################################" | out-File $outFile -Append

echo `r | out-File $outFile -Append
echo "######################################################" | out-File $outFile -Append
echo "#        NET USE SHOW ALL NETWORK CONNECTIONS        #" | out-File $outFile -Append
echo "######################################################" | out-File $outFile -Append
net use  | out-File $outFile -Append

echo `r | out-File $outFile -Append
echo "######################################################" | out-File $outFile -Append
echo "#                 CHECKING IP CONFIG                 #" | out-File $outFile -Append
echo "######################################################" | out-File $outFile -Append
ipconfig /all | out-File $outFile -Append

echo `r | out-File $outFile -Append
echo "######################################################" | out-File $outFile -Append
echo "#       NET SHARE SHOW ALL SHARED RESOURCES          #" | out-File $outFile -Append
echo "######################################################" | out-File $outFile -Append
net share | out-File $outFile -Append

echo `r | out-File $outFile -Append
echo "######################################################" | out-File $outFile -Append
echo "#                     NETSTAT -ANO                   #" | out-File $outFile -Append
echo "######################################################" | out-File $outFile -Append
netstat -ano | out-File $outFile -Append

echo `r | out-File $outFile -Append
echo "######################################################" | out-File $outFile -Append
echo "#                      NETSTAT -R                    #" | out-File $outFile -Append
echo "######################################################" | out-File $outFile -Append
netstat -r | out-File $outFile -Append

echo `r | out-File $outFile -Append
echo "######################################################" | out-File $outFile -Append
echo "#                 ARP -A   ARP TABLE INFO            #" | out-File $outFile -Append
echo "######################################################" | out-File $outFile -Append
arp -a | out-File $outFile -Append

echo `r | out-File $outFile -Append
echo "######################################################" | out-File $outFile -Append
echo "#              LOCAL MACHINE USER INFO               #" | out-File $outFile -Append
echo "######################################################" | out-File $outFile -Append

echo `r | out-File $outFile -Append
echo "######################################################" | out-File $outFile -Append
echo "#                      NET USERS                     #" | out-File $outFile -Append
echo "######################################################" | out-File $outFile -Append
net users | out-File $outFile -Append

echo `r | out-File $outFile -Append
echo "######################################################" | out-File $outFile -Append
echo "#                   NET LOCALGROUP                   #" | out-File $outFile -Append
echo "######################################################" | out-File $outFile -Append
ipconfig /all | out-File $outFile -Append

echo `r | out-File $outFile -Append
echo "######################################################" | out-File $outFile -Append
echo "#           NET LOCALGROUP ADMINISTRATORS            #" | out-File $outFile -Append
echo "######################################################" | out-File $outFile -Append
net localgroup administrators | out-File $outFile -Append

echo `r | out-File $outFile -Append
echo "######################################################" | out-File $outFile -Append
echo "#                    NET ACCOUNTS                    #" | out-File $outFile -Append
echo "######################################################" | out-File $outFile -Append
net accounts | out-File $outFile -Append



echo `r | out-File $outFile -Append
echo "######################################################" | out-File $outFile -Append
echo "#                 FIREWALL INFORMATION              #" | out-File $outFile -Append
echo "######################################################" | out-File $outFile -Append

echo `r | out-File $outFile -Append
echo "######################################################" | out-File $outFile -Append
echo "#              NETSH FIREWALL SHOW STATE             #" | out-File $outFile -Append
echo "######################################################" | out-File $outFile -Append
netsh firewall show state | out-File $outFile -Append

echo `r | out-File $outFile -Append
echo "######################################################" | out-File $outFile -Append
echo "#                   NETSH ADVFIREWALL                #" | out-File $outFile -Append
echo "######################################################" | out-File $outFile -Append
netsh advfirewall show allprofiles | out-File $outFile -Append



echo `r | out-File $outFile -Append
echo "######################################################" | out-File $outFile -Append
echo "#          DOMAIN CONTROLLER INTERROGATION           #" | out-File $outFile -Append
echo "######################################################" | out-File $outFile -Append

echo `r | out-File $outFile -Append
echo "######################################################" | out-File $outFile -Append
echo "#            GROUP POLICY  INFORMATION               #" | out-File $outFile -Append
echo "######################################################" | out-File $outFile -Append

echo `r | out-File $outFile -Append
echo "######################################################" | out-File $outFile -Append
echo "#                     GPRESULT /Z                    #" | out-File $outFile -Append
echo "######################################################" | out-File $outFile -Append
gpresult /Z | out-File $outFile -Append

echo `r | out-File $outFile -Append
echo "######################################################" | out-File $outFile -Append
echo "#            ACTIVE DIRECTORY INFORMATION            #" | out-File $outFile -Append
echo "######################################################" | out-File $outFile -Append

echo `r | out-File $outFile -Append
echo "######################################################" | out-File $outFile -Append
echo "#                     GET-ADDOMAIN                   #" | out-File $outFile -Append
echo "######################################################" | out-File $outFile -Append
Get-ADDomain | out-File $outFile -Append

echo `r | out-File $outFile -Append
echo "######################################################" | out-File $outFile -Append
echo "#             GET-ADDUSER  ENABLED USERS             #" | out-File $outFile -Append
echo "######################################################" | out-File $outFile -Append
Get-ADUser -Filter {Enabled -eq "True"} | out-File $outFile -Append

echo `r | out-File $outFile -Append
echo "######################################################" | out-File $outFile -Append
echo "#             GET-ADDUSER  DISABLED USERS            #" | out-File $outFile -Append
echo "######################################################" | out-File $outFile -Append
Get-ADUser -Filter {Enabled -eq "False"} | out-File $outFile -Append

echo `r | out-File $outFile -Append
echo "######################################################" | out-File $outFile -Append
echo "#     GET-ADCOMPUTER  SHOWING ALL AD COMPUTERS       #" | out-File $outFile -Append
echo "######################################################" | out-File $outFile -Append
Get-ADComputer -Filter 'ObjectClass -eq "Computer"' | Select -Expand DNSHostName | out-File $outFile -Append






