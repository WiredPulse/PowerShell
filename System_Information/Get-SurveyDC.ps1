<#
    .SYNOPSIS  
        Audits a Domain Controller for specific data used to gain an understanding of the domain. This script should be run on the Domain Controller.

    .DESCRIPTION  
        When ran, data is exported as a .csv, .html, or .txt. You can view it as is and for the .csv, you can import it back into PowerShell and view it using out-gridview. To use this option, do the following:
			PS C:\Users\<User>\Desktop> Import-CSV .\<file>.csv | Out-Gridview

    .NOTES  
        File Name      : Get-DC_Survey.ps1
        Version        : v.0.1  
        Prerequisite   : PowerShell
        Created        : 09 Sep 16

    .OUTPUT
        The following folders and files will be made from running this script.

        .\Audit
            AD
                Computers.csv
                Groups.csv
                OU_Permissions.csv
                Users.csv    
            DNS
                All_Records.csv
                Blocked_Items.txt
                Directory_Services_Settings_SVR2012.txt
                Forwarders__SVR2012.txt
                Global_Name_Zone_SVR2012.txt
                Recursion_SVR2012.txt
                Roothints_SVR2012.txt
                Root_Hints.csv
                Scavenging_SVR2012.txt
                Server_Diag_SVR2012.txt
                Server_Info_SVR2012.txt
                Server_Settings_SVR2012.txt
                Stats.csv
                Stats_SVR2012.txt
                Zones.csv
                Zones_SVR2012.txt
            GPO
                GPO_Metadata_Report.csv
                GPO_Report.html
            MISC
                AD_Recycle_Bin_Check.txt
                IPv6_Status.txt
                Last_Access_Attribute.txt
                Mapped_Drives.txt
                Prefetch.txt
                Prefetch_listing.txt
                Roles_and_Features.txt
                Scheduled_Tasks.txt
                Shares.txt
		Domain_Trusts.txt
            Domain_<Domain_Name>.html
            Forest_<Forest_Name>.html

    ####################################################################################


#>

### Import needed modules
Import-Module ActiveDirectory
Import-Module GroupPolicy
Import-Module ServerManager

### Creating needed directories
new-item .\Audit -itemtype directory | out-null
new-item .\Audit\AD -itemtype directory | out-null
new-item .\Audit\GPO -itemtype directory | out-null
new-item .\Audit\DNS -itemtype directory | out-null
new-item .\Audit\MISC -itemtype directory | out-null

### Gets AD User data
Write-Host "Retrieving AD User data..."
Get-ADUser -Filter * -Properties * | Select DisplayName,SAMAccountName, DistinguishedName, LastBadPasswordAttempt, PasswordLastSet, PasswordExpired, PasswordNeverExpires, PasswordNotRequired, AccountExpirationDate, LockedOut, Enabled, CannotChangePassword, WhenCreated, WhenChanged, LastLogondate, LogonCount, BadLogonCount, ScriptPath, ProfilePath, HomeDrive, HomeDirectory | Export-CSV .\Audit\AD\Users.csv

### Gets AD Computer data
Write-Host "Retrieving AD Computer data..."
Get-ADComputer -filter * -Properties * | select Name, Created, Enabled, LogonCount, OperatingSystem, OperatingSystemServicePack, PrimaryGroup | Export-CSV .\Audit\AD\Computers.csv

### Gets AD Group data
Write-Host "Retrieving AD Group data..."
$Groups = (Get-AdGroup -filter * | Where {$_.name -like "**"} | select name -ExpandProperty name)

$Table = @()

$Record = @{
  "Group Name" = ""
  "Name" = ""
  "Username" = ""
}


Foreach ($Group in $Groups) {
  Try
  {
  $Arrayofmembers = Get-ADGroupMember -identity $Group -recursive | select name,samaccountname -ErrorAction SilentlyContinue
  }
  Catch
  {
  # Does nothing,  it is just here to hide errors from the screen.
  }

  foreach ($Member in $Arrayofmembers) {
    $Record."Group Name" = $Group
    $Record."Name" = $Member.name
    $Record."UserName" = $Member.samaccountname
    $objRecord = New-Object PSObject -property $Record
    $Table += $objrecord

  }
}
$Table | Export-CSV .\Audit\AD\Groups.csv

### OU Permissions (Delegations)
#### https://gallery.technet.microsoft.com/Active-Directory-OU-1d09f989

Write-Host "Retrieving OU permissions..."
# This array will hold the report output.
$report = @()

# Build a lookup hash table that holds all of the string names of the
# ObjectType GUIDs referenced in the security descriptors.
# See the Active Directory Technical Specifications:
#  3.1.1.2.3 Attributes
#    http://msdn.microsoft.com/en-us/library/cc223202.aspx
#  3.1.1.2.3.3 Property Set
#    http://msdn.microsoft.com/en-us/library/cc223204.aspx
#  5.1.3.2.1 Control Access Rights
#    http://msdn.microsoft.com/en-us/library/cc223512.aspx
#  Working with GUID arrays
#    http://blogs.msdn.com/b/adpowershell/archive/2009/09/22/how-to-find-extended-rights-that-apply-to-a-schema-class-object.aspx
# Hide the errors for a couple duplicate hash table keys.
$schemaIDGUID = @{}
### NEED TO RECONCILE THE CONFLICTS ###
$ErrorActionPreference = 'SilentlyContinue'
Get-ADObject -SearchBase (Get-ADRootDSE).schemaNamingContext -LDAPFilter '(schemaIDGUID=*)' -Properties name, schemaIDGUID |
 ForEach-Object {$schemaIDGUID.add([System.GUID]$_.schemaIDGUID,$_.name)}
Get-ADObject -SearchBase "CN=Extended-Rights,$((Get-ADRootDSE).configurationNamingContext)" -LDAPFilter '(objectClass=controlAccessRight)' -Properties name, rightsGUID |
 ForEach-Object {$schemaIDGUID.add([System.GUID]$_.rightsGUID,$_.name)}
$ErrorActionPreference = 'Continue'

# Get a list of all OUs.  Add in the root containers for good measure (users, computers, etc.).
$OUs  = @(Get-ADDomain | Select-Object -ExpandProperty DistinguishedName)
$OUs += Get-ADOrganizationalUnit -Filter * | Select-Object -ExpandProperty DistinguishedName
$OUs += Get-ADObject -SearchBase (Get-ADDomain).DistinguishedName -SearchScope OneLevel -LDAPFilter '(objectClass=container)' | Select-Object -ExpandProperty DistinguishedName

# Loop through each of the OUs and retrieve their permissions.
# Add report columns to contain the OU path and string names of the ObjectTypes.
ForEach ($OU in $OUs) {
    $report += Get-Acl -Path "AD:\$OU" |
     Select-Object -ExpandProperty Access | 
     Select-Object @{name='organizationalUnit';expression={$OU}}, `
                   @{name='objectTypeName';expression={if ($_.objectType.ToString() -eq '00000000-0000-0000-0000-000000000000') {'All'} Else {$schemaIDGUID.Item($_.objectType)}}}, `
                   @{name='inheritedObjectTypeName';expression={$schemaIDGUID.Item($_.inheritedObjectType)}}, `
                   *
}

# Dump the raw report out to a CSV file for analysis in Excel.
$report | Select OrganizationalUnit, IdentityReference, ObjectTypeName, InheritedObjectTypeName, ActiveDirectoryRights, InheritanceType, AccessControlType, IsInherited, InheritanceFlags, ProgationFlags, ObjectType, InheritedObjectType, ObjectFlags | Export-Csv -Path ".\Audit\AD\OU_Permissions.csv" -NoTypeInformation

### GPO Metadata Info
# https://gallery.technet.microsoft.com/Forensics-Audit-Group-f9c57a1d#content
Write-Host "Retrieving GPO metadata..."

# Gets DC information
$Server = Get-ADDomainController -Discover | Select-Object -ExpandProperty HostName

##############################################################################

Function Get-ADOrganizationalUnitOneLevel {
param($Path)
    Get-ADOrganizationalUnit -Filter * -SearchBase $Path `
        -SearchScope OneLevel -Server $Server |
        Sort-Object Name |
        ForEach-Object {
            $script:OUHash.Add($_.DistinguishedName,$script:Counter++)
            Get-ADOrganizationalUnitOneLevel -Path $_.DistinguishedName}
}

Function Get-ADOrganizationalUnitSorted {
    $DomainRoot = (Get-ADDomain -Server $Server).DistinguishedName
    $script:Counter = 1
    $script:OUHash = @{$DomainRoot=0}
    Get-ADOrganizationalUnitOneLevel -Path $DomainRoot
    $OUHash
}

$SortedOUs = Get-ADOrganizationalUnitSorted

##############################################################################

# Grab a list of all GPOs
$GPOs = Get-GPO -All -Server $Server | Select-Object ID, Path, DisplayName, GPOStatus, WMIFilter, CreationTime, ModificationTime, User, Computer

# Create a hash table for fast GPO lookups later in the report.
# Hash table key is the policy path which will match the gPLink attribute later.
# Hash table value is the GPO object with properties for reporting.
$GPOsHash = @{}
ForEach ($GPO in $GPOs) {
    $GPOsHash.Add($GPO.Path,$GPO)
}

# Empty array to hold all possible GPO link SOMs
$gPLinks = @()

# GPOs linked to the root of the domain
#  !!! Get-ADDomain does not return the gPLink attribute
$gPLinks += `
 Get-ADObject -Server $Server -Identity (Get-ADDomain).distinguishedName -Properties name, distinguishedName, gPLink, gPOptions |
 Select-Object name, distinguishedName, gPLink, gPOptions, @{name='Depth';expression={0}}

# GPOs linked to OUs
#  !!! Get-GPO does not return the gPLink attribute
# Calculate OU depth for graphical representation in final report
$gPLinks += `
 Get-ADOrganizationalUnit -Server $Server -Filter * -Properties name, distinguishedName, gPLink, gPOptions |
 Select-Object name, distinguishedName, gPLink, gPOptions, @{name='Depth';expression={($_.distinguishedName -split 'OU=').count - 1}}

# GPOs linked to sites
$gPLinks += `
 Get-ADObject -Server $Server -LDAPFilter '(objectClass=site)' -SearchBase "CN=Sites,$((Get-ADRootDSE).configurationNamingContext)" -SearchScope OneLevel -Properties name, distinguishedName, gPLink, gPOptions |
 Select-Object name, distinguishedName, gPLink, gPOptions, @{name='Depth';expression={0}}

# Empty report array
$report = @()

# Loop through all possible GPO link SOMs collected
ForEach ($SOM in $gPLinks) {
    # Filter out policy SOMs that have a policy linked
    If ($SOM.gPLink) {

        # Retrieve the replication metadata for gPLink
        #$gPLinkMetadata = Get-ADReplicationAttributeMetadata -Server $Server -Object $SOM.distinguishedName -Properties gPLink 
        <#
         AttributeName                                    : gPLink
         AttributeValue                                   : [LDAP://cn={4152322F-D1AD-4A46-8A48-CCBB585DDEDB},cn=policies,cn=system,DC=cohovineyard,DC=com;0]
         FirstOriginatingCreateTime                       : 
         IsLinkValue                                      : False
        *LastOriginatingChangeDirectoryServerIdentity     : CN=NTDS Settings,CN=CVDCR2,CN=Servers,CN=Ohio,CN=Sites,CN=Configuration,DC=CohoVineyard,DC=com
        *LastOriginatingChangeDirectoryServerInvocationId : 4eab0674-680c-4036-851a-1ba76275ca01
        *LastOriginatingChangeTime                        : 11/20/2014 12:39:58 PM
         LastOriginatingChangeUsn                         : 533407
         LastOriginatingDeleteTime                        : 
         LocalChangeUsn                                   : 533407
         Object                                           : OU=Legal,DC=CohoVineyard,DC=com
         Server                                           : CVDCR2.CohoVineyard.com
        *Version                                          : 23
        #>

        # If an OU has 'Block Inheritance' set (gPOptions=1) and no GPOs linked,
        # then the gPLink attribute is no longer null but a single space.
        # There will be no gPLinks to parse, but we need to list it with BlockInheritance.
        If ($SOM.gPLink.length -gt 1) {
            # Use @() for force an array in case only one object is returned (limitation in PS v2)
            # Example gPLink value:
            #   [LDAP://cn={7BE35F55-E3DF-4D1C-8C3A-38F81F451D86},cn=policies,cn=system,DC=wingtiptoys,DC=local;2][LDAP://cn={046584E4-F1CD-457E-8366-F48B7492FBA2},cn=policies,cn=system,DC=wingtiptoys,DC=local;0][LDAP://cn={12845926-AE1B-49C4-A33A-756FF72DCC6B},cn=policies,cn=system,DC=wingtiptoys,DC=local;1]
            # Split out the links enclosed in square brackets, then filter out
            # the null result between the closing and opening brackets ][
            $links = @($SOM.gPLink -split {$_ -eq '[' -or $_ -eq ']'} | Where-Object {$_})
            # Use a for loop with a counter so that we can calculate the precedence value
            For ( $i = $links.count - 1 ; $i -ge 0 ; $i-- ) {
                # Example gPLink individual value (note the end of the string):
                #   LDAP://cn={7BE35F55-E3DF-4D1C-8C3A-38F81F451D86},cn=policies,cn=system,DC=wingtiptoys,DC=local;2
                # Splitting on '/' and ';' gives us an array every time like this:
                #   0: LDAP:
                #   1: (null value between the two //)
                #   2: distinguishedName of policy
                #   3: numeric value representing gPLinkOptions (LinkEnabled and Enforced)
                $GPOData = $links[$i] -split {$_ -eq '/' -or $_ -eq ';'}
                # Add a new report row for each GPO link
                $report += New-Object -TypeName PSCustomObject -Property @{
                    Depth             = $SOM.Depth;
                    Name              = $SOM.Name;
                    DistinguishedName = $SOM.distinguishedName;
                    PolicyDN          = $GPOData[2];
                    Precedence        = $links.count - $i
                    GUID              = "{$($GPOsHash[$($GPOData[2])].ID)}";
                    DisplayName       = $GPOsHash[$GPOData[2]].DisplayName;
                    GPOStatus         = $GPOsHash[$GPOData[2]].GPOStatus;
                    WMIFilter         = $GPOsHash[$GPOData[2]].WMIFilter.Name;
                    GPOCreated        = $GPOsHash[$GPOData[2]].CreationTime;
                    GPOModified       = $GPOsHash[$GPOData[2]].ModificationTime;
                    UserVersionDS     = $GPOsHash[$GPOData[2]].User.DSVersion;
                    UserVersionSysvol = $GPOsHash[$GPOData[2]].User.SysvolVersion;
                    ComputerVersionDS = $GPOsHash[$GPOData[2]].Computer.DSVersion;
                    ComputerVersionSysvol = $GPOsHash[$GPOData[2]].Computer.SysvolVersion;
                    Config            = $GPOData[3];
                    LinkEnabled       = [bool](!([int]$GPOData[3] -band 1));
                    Enforced          = [bool]([int]$GPOData[3] -band 2);
                    BlockInheritance  = [bool]($SOM.gPOptions -band 1)
                    gPLinkVersion     = $gPLinkMetadata.Version
                    gPLinkLastOrigChgTime = $gPLinkMetadata.LastOriginatingChangeTime
                    gPLinkLastOrigChgDirServerId = $gPLinkMetadata.LastOriginatingChangeDirectoryServerIdentity
                    gPLinkLastOrigChgDirServerInvocId = $gPLinkMetadata.LastOriginatingChangeDirectoryServerInvocationId
                } # End Property hash table
            } # End For
        } Else {
            # BlockInheritance but no gPLink
            $report += New-Object -TypeName PSCustomObject -Property @{
                Depth             = $SOM.Depth;
                Name              = $SOM.Name;
                DistinguishedName = $SOM.distinguishedName;
                BlockInheritance  = [bool]($SOM.gPOptions -band 1)
                gPLinkVersion     = $gPLinkMetadata.Version
                gPLinkLastOrigChgTime = $gPLinkMetadata.LastOriginatingChangeTime
                gPLinkLastOrigChgDirServerId = $gPLinkMetadata.LastOriginatingChangeDirectoryServerIdentity
                gPLinkLastOrigChgDirServerInvocId = $gPLinkMetadata.LastOriginatingChangeDirectoryServerInvocationId
            }
        } # End If
    } Else {
        # No gPLink at this SOM
        $report += New-Object -TypeName PSCustomObject -Property @{
            Depth             = $SOM.Depth;
            Name              = $SOM.Name;
            DistinguishedName = $SOM.distinguishedName;
            BlockInheritance  = [bool]($SOM.gPOptions -band 1)
        }
    } # End If
} # End ForEach

# Output the results to CSV file for viewing in Excel
$report |
 Select-Object @{name='OUSort';expression={$SortedOUs[$_.DistinguishedName]}}, `
  @{name='SOM';expression={$_.name.PadLeft($_.name.length + ($_.depth * 5),'_')}}, `
  DistinguishedName, BlockInheritance, LinkEnabled, Enforced, Precedence, `
  DisplayName, GPOStatus, WMIFilter, GUID, GPOCreated, GPOModified, `
  UserVersionDS, UserVersionSysvol, ComputerVersionDS, ComputerVersionSysvol, PolicyDN, `
  gPLinkVersion, gPLinkLastOrigChgTime, gPLinkLastOrigChgDirServerId, gPLinkLastOrigChgDirServerInvocId |
 Sort-Object OUSort, Precedence, SOM |
 Export-CSV .\Audit\GPO\GPO_Metadata_Report.csv -NoTypeInformation

### GPO Dump
Write-Host "Retrieving GPO settings..."
Get-GPOReport -All -ReportType HTML > .\Audit\GPO\GPO_Report.html

### DNS info 
# All Records
Write-Host "Retrieving DNS data..."
get-wmiobject -Namespace root\MicrosoftDNS -class microsoftdns_resourcerecord | select __Class, ContainerName, DomainName, RecordData, ownername | Export-CSV .\Audit\DNS\All_Records.csv

# Gets Roothints 
get-wmiobject -Namespace root\MicrosoftDNS -class microsoftdns_resourcerecord | where{$_.domainname -eq "..roothints"} | Select recorddata | Export-CSV .\Audit\DNS\Root_Hints.csv

# Gets Zones 
Get-WmiObject -namespace "root\MicrosoftDNS" -class MicrosoftDNS_Zone | select Name | Export-CSV .\Audit\DNS\Zones.csv

# Gets DNS information
dnscmd.exe /info | out-file .\DNS_Info.txt

# Stats
get-wmiobject -Namespace root\MicrosoftDNS -class microsoftdns_statistic | select name, value | Export-CSV .\Audit\DNS\Stats.csv

# Retrieves relevant DNS data in Server 2012. The output of each is saved in a newly created DNS folder right off of where this script is ran from.

Get-DNSServerStatistics | out-file .\Audit\DNS\Stats_SVR2012.txt
Get-DnsServer | out-file .\Audit\DNS\Server_Info_SVR2012.txt
Get-DnsServerDiagnostics | out-file .\Audit\DNS\Server_Diag_SVR2012.txt
Get-DnsServerDsSetting | out-file .\Audit\DNS\Directory_Services_Settings_SVR2012.txt
Get-DnsServerForwarder | out-file .\Audit\DNS\Forwarders_SVR2012.txt
Get-DnsServerGlobalNameZone | out-file .\Audit\DNS\Global_Name_Zone_SVR2012.txt

<# The block list automatically applies to all zones for which the server is authoritative. For example, if the DNS server is authoritative for contoso.com and for europe.contoso.com, it ignores queries for wpad.contoso.com as well as for wpad.europe.contoso.com. However, the DNS Server service does not ignore queries for names in zones for which it is not authoritative. 

 Identify the items in the list. If you want to add more to the list, take note of the items currently listed and as adding more will overwrite the current ones listed. With that said, you will need to add the current ones listed with the additional ones you want to add. To add to the list, use the following syntax:
	PS C:\> dnscmd /config /globalqueryblocklist WKGA1023, wpad, isatap
#>
"## https://technet.microsoft.com/en-us/library/cc794902(v=ws.10).aspx" | out-file .\Audit\DNS\Blocked_Items.txt
" " | out-file .\Audit\DNS\Blocked_Items.txt -Append
dnscmd /info /globalqueryblocklist | out-file .\Audit\DNS\Blocked_Items.txt -Append
" " | out-file .\Audit\DNS\Blocked_Items.txt -Append
" " | out-file .\Audit\DNS\Blocked_Items.txt -Append
"## Blocklist is Enabled (1) or Disbled (0)" | out-file .\Audit\DNS\Blocked_Items.txt -Append
dnscmd /info /enableglobalqueryblocklist | out-file .\Audit\DNS\Blocked_Items.txt -Append

Get-DnsServerRecursion | out-file .\Audit\DNS\Recursion_SVR2012.txt
Get-DNSServerRootHint | out-file .\Audit\DNS\Roothints_SVR2012.txt
Get-DnsServerScavenging | out-file .\Audit\DNS\Scavenging_SVR2012.txt
Get-DnsServerSetting | out-file .\Audit\DNS\Server_Settings_SVR2012.txt
Get-DnsServerZone | out-file .\Audit\DNS\Zones_SVR2012.txt

get-wmiobject -Namespace root\MicrosoftDNS -class microsoftdns_resourcerecord | select __Class, ContainerName, DomainName, RecordData, ownername | Export-CSV .\Audit\DNS\All_Records.csv


### Roles and Features
Write-Host "Retrieving Role and Feature settings..."
Get-Windowsfeature | out-file .\Audit\misc\Roles_and_Features.txt

### IP Listing
Get-ADComputer -Filter * -Properties ipv4Address, OperatingSystem, OperatingSystemServicePack | Format-table name, ipv4*, oper* | out-file .\Audit\misc\IP_Listing.txt

### AD Recycle Bin Check (Enabled or Disabled)
"If 'EnabledScope' shows '{}', the feature is not enabled..." | out-file .\Audit\misc\AD_Recycle_Bin_Check.txt
Get-ADOptionalFeature -Filter 'name -like "Recycle Bin Feature"' | select Name, EnabledScope | out-file .\Audit\misc\AD_Recycle_Bin_Check.txt -Append

### Mapped drives
Write-Host "Retrieving mapped drives..."
Net Use | out-file .\Audit\misc\Mapped_Drives.txt

### Shares
Write-Host "Retrieving shares..."
Net Share | out-file .\Audit\misc\Shares.txt

### Domain Trusts
Get-WmiObject -Class Microsoft_DomainTrustStatus -Namespace ROOT\MicrosoftActiveDirectory | Select-Object PSComputername, TrustedDomain, TrustAttributes, TrustDirection, TrustType |fl | out-file .\Audit\misc\Domain_Trusts.txt

### Scheduled Tasks
Write-Host "Retrieving scheduled tasks..."
schtasks | out-file .\Audit\misc\Scheduled_Tasks.txt

### Prefetch check
Write-Host "Checking for prefetch..."
get-service | where{$_.name -eq "sysmain"} | out-file .\Audit\misc\Prefetch.txt | out-null

### Prefetch Directory listing
get-childitem c:\windows\prefetch | out-file .\Audit\misc\Prefetch_listing.txt | out-null

### Status of IPV6 (Enabled or Disabled)
"A Value of '4294967295' (ffffffff in hex) means IPv6 is disabled" | out-file .\Audit\misc\IPv6_Status.txt
Get-ItemProperty "HKLM:\system\currentcontrolset\services\Tcpip6\Parameters" | select DisabledComponents | out-file .\Audit\misc\IPv6_Status.txt -Append

### Check if last access attribute is enabled
Write-Host "Checking for last access attribute status..."
echo "0 means it is enabled" > .\Audit\misc\Last_Access_Attribute.txt
Get-ItemProperty hklm:system\currentcontrolset\control\filesystem ntfsdisablelastaccessupdate >> .\Audit\misc\last_access_attribute.txt

### High Level Reports
# http://www.the-little-things.net 
Write-Host "Retrieving Forest and Domain information..."

#region Custom Static Variables
# Forest level diagram reports can be enabled here. You can also just enable the source file
# generation for input into dot.exe or the graphviz gui at another workstation.
$AD_CreateDiagramSourceFiles = $ExportGraphvizDefinitionFiles
$AD_CreateDiagrams = $false
$Graphviz_Path = ''

# Added this in as it can be useful to have a list of all users with their
# AD properties sometimes (to massage for input into other scripts among other things)
$EXPORTTOCSV_ALLUSERS = $ExportAllUsers
$EXPORTTOCSV_PRIVUSERS = $ExportPrivilegedUsers

# Used if calling script from command line
$Verbosity = ($PSBoundParameters['Verbose'] -eq $true)

If ($PromptForInput)
{
    $yes = New-Object System.Management.Automation.Host.ChoiceDescription "&Yes",""
    $no = New-Object System.Management.Automation.Host.ChoiceDescription "&No",""
    $choices = [System.Management.Automation.Host.ChoiceDescription[]]($yes,$no)
    
    $result = $Host.UI.PromptForChoice("Create Diagram Source Files?","Do you want to create diagram source txt files for later processing?",$choices,1)
    $AD_CreateDiagramSourceFiles = ($result -ne $true)
    $result = $Host.UI.PromptForChoice("Create Diagrams (requires graphviz binaries)?","Do you want to create diagrams with graphviz?",$choices,1)
    $AD_CreateDiagrams = ($result -ne $true)
    if ($AD_CreateDiagrams)
    {
        $Graphviz_Path = Read-Host "Enter your graphviz binary path if needed (if already in the environment path just press enter):"
    }

    $result = $Host.UI.PromptForChoice("Export All Users?","Do you want to export a CSV of all user data?",$choices,1)
    $EXPORTTOCSV_ALLUSERS = ($result -ne $true)
    $result = $Host.UI.PromptForChoice("Export All Privileged Users?","Do you want to export a CSV of all privileged user data?",$choices,1)
    $EXPORTTOCSV_PRIVUSERS = ($result -ne $true)
    
    $result = $Host.UI.PromptForChoice("Verbose?","Do you want verbose output?",$choices,0)
    $Verbosity = ($result -ne $true)
}

# If you are color coding the domain reports this will control password age colorization
$AD_PwdAgeWarn = 60
$AD_PwdAgeAlert = 90
$AD_PwdAgeHealthy = 60

# A list of user attributes to normalize across all users.
# When an attribute doesn't exist (a non-mailbox enabled
# account for instance), it will be added with a $null value.
# These will all be exported if $EXPORTTOCSV_USERS is $true
$UserAttribs = @(
    'cn',
    'displayName',
    'givenName',
    'sn',
    'name',
    'sAMAccountName',
    'sAMAccountType',
    'whenChanged',
    'whenCreated',
    'pwdLastSet',
    'admincount',
    'accountExpires',
    'badPasswordTime',
    'badPwdCount',
    'lastLogon',
    'lastLogoff',
    'logonCount',
    'useraccountcontrol',
    'lastlogontimestamp',
    'homeMDB',
    'homeMTA',
    'mail',
    'proxyAddresses',
    'mailNickname',
    #'legacyExchangeDN',
    #'showInAddressBook',
    'msexchalobjectversion',
    #'msexchdelegatelistbl',        # Could be interesting for a seperate report
    'msexchhomeservername',
    'msexchrecipientdisplaytype',
    'msexchrecipienttypedetails',
    'msexchumdtmfmap',
    'msexchuseraccountcontrol',
    'msexchuserculture',
    'msexchversion',
    'msexchwhenmailboxcreated',
    'msnpallowdialin',
    'msRTCSIP-PrimaryHomeServer',
    'msRTCSIP-PrimaryUserAddress',
    'msRTCSIP-UserEnabled',
    'msRTCSIP-Line',
    'msRTCSIP-FederationEnabled',
    'msRTCSIP-InternetAccessEnabled'
)

# These are what we will attempt to report upon later on as 'privileged' groups
$AD_PrivilegedGroups = @(
    'Enterprise Admins',
    'Schema Admins',
    'Domain Admins',
    'Administrators',
    'Cert Publishers',
    'Account Operators',
    'Server Operators',
    'Backup Operators',
    'Print Operators'
)

$Attrib_User_MSExchangeVersion = @{
    # $null = Exchange 2003 and earlier
    '4535486012416' = '2007'
    '44220983382016' = '2010'
}

# http://msdn.microsoft.com/en-us/library/cc223546(v=prot.20).aspx
Add-Type -TypeDefinition @" 
    [System.Flags]
    public enum nTDSSiteConnectionSettingsFlags {
        IS_GENERATED                  = 0x00000001,
        TWOWAY_SYNC                   = 0x00000002,
        OVERRIDE_NOTIFY_DEFAULT       = 0x00000004,
        USE_NOTIFY                    = 0x00000008,
        DISABLE_INTERSITE_COMPRESSION = 0x00000010,
        OPT_USER_OWNED_SCHEDULE       = 0x00000020  
    }
    [System.Flags]
    public enum MSExchCurrentServerRolesFlags {
        NONE           = 0x00000001,
        MAILBOX        = 0x00000002,
        CLIENT_ACCESS  = 0x00000004,
        UM             = 0x00000010,
        HUB_TRANSPORT  = 0x00000020,
        EDGE_TRANSPORT = 0x00000040  
    }
    [System.Flags]
    public enum nTDSSiteSettingsFlags {
        IS_AUTO_TOPOLOGY_DISABLED            = 0x00000001,
        IS_TOPL_CLEANUP_DISABLED             = 0x00000002,
        IS_TOPL_MIN_HOPS_DISABLED            = 0x00000004,
        IS_TOPL_DETECT_STALE_DISABLED        = 0x00000008,
        IS_INTER_SITE_AUTO_TOPOLOGY_DISABLED = 0x00000010,
        IS_GROUP_CACHING_ENABLED             = 0x00000020,
        FORCE_KCC_WHISTLER_BEHAVIOR          = 0x00000040,
        FORCE_KCC_W2K_ELECTION               = 0x00000080,
        IS_RAND_BH_SELECTION_DISABLED        = 0x00000100,
        IS_SCHEDULE_HASHING_ENABLED          = 0x00000200,
        IS_REDUNDANT_SERVER_TOPOLOGY_ENABLED = 0x00000400
    }
    [System.Flags]
    public enum MSTrustAttributeFlags {
        NON_TRANSITIVE      = 0x00000001,
        UPLEVEL_ONLY        = 0x00000002,
        QUARANTINED_DOMAIN  = 0x00000004,
        FOREST_TRANSITIVE   = 0x00000008,
        CROSS_ORGANIZATION  = 0x00000010,
        WITHIN_FOREST       = 0x00000020,
        TREAT_AS_EXTERNAL   = 0x00000040,
        USES_RC4_ENCRYPTION = 0x00000080
    }
"@

#Schema constants
$SchemaHashExchange = 
@{
    4397='Exchange Server 2000 RTM'
    4406='Exchange Server 2000 SP3'
    6870='Exchange Server 2003 RTM'
    6936='Exchange Server 2003 SP3'
    10628='Exchange Server 2007 RTM'
    10637='Exchange Server 2007 RTM'
    11116='Exchange 2007 SP1'
    14622='Exchange 2007 SP2 or Exchange 2010 RTM'
    14625='Exchange 2007 SP3'
    14726='Exchange 2010 SP1'
    14732='Exchange 2010 SP2'
    14734='Exchange 2010 SP3'
    15137='Exchange 2013 RTM'
    15254='Exchange 2013 CU1'
    15281='Exchange 2013 CU2'
    15283='Exchange 2013 CU3'
}
$SchemaHashLync = 
@{
    1006="LCS 2005"
    1007="OCS 2007 R1"
    1008="OCS 2007 R2"
    1100="Lync Server 2010"
    1150="Lync Server 2013"
}

# AD DC capabilities list (http://www.ldapexplorer.com/en/manual/103010700-connection-rootdse.htm)
# - Primarily used to determine if a DC is RODC or not (Const LDAP_CAP_ACTIVE_DIRECTORY_PARTIAL_SECRETS_OID = "1.2.840.113556.1.4.1920")
$AD_Capabilities = @{
    '1.2.840.113556.1.4.319' = 'Paged results'
    '1.2.840.113556.1.4.417' = 'Show deleted objects'
    '1.2.840.113556.1.4.473' = 'Sort results'
    '1.2.840.113556.1.4.474' = 'Sort results response'
    '1.2.840.113556.1.4.521' = 'Cross domain move'
    '1.2.840.113556.1.4.528' = 'Server notification'
    '1.2.840.113556.1.4.529' = 'Extended DN'
    '1.2.840.113556.1.4.619' = 'Lazy commit'
    '1.2.840.113556.1.4.800' = 'Active Directory >= Windows 2000'
    '1.2.840.113556.1.4.801' = 'SD flags'
    '1.2.840.113556.1.4.805' = 'Tree delete'
    '1.2.840.113556.1.4.906' = 'Microsoft large integer'
    '1.2.840.113556.1.4.1302' = 'Microsoft OID used with DEN Attributes'
    '1.2.840.113556.1.4.1338' = 'Verify name'
    '1.2.840.113556.1.4.1339' = 'Domain scope'
    '1.2.840.113556.1.4.1340' = 'Search options'
    '1.2.840.113556.1.4.1341' = 'RODC DCPROMO'
    '1.2.840.113556.1.4.1413' = 'Permissive Modify'
    '1.2.840.113556.1.4.1670' = 'Active Directory (v5.1)>= Windows 2003'
    '1.2.840.113556.1.4.1781' = 'Microsoft LDAP fast bind extended request'
    '1.2.840.113556.1.4.1791' = 'NTLM Signing and Sealing'
    '1.2.840.113556.1.4.1851' = 'ADAM / AD LDS Supported'
    '1.2.840.113556.1.4.1852' = 'Quota Control'
    '1.2.840.113556.1.4.1880' = 'ADAM Digest'
   # '1.2.840.113556.1.4.1852' = 'Shutdown Notify'
    '1.2.840.113556.1.4.1920' = 'Partial Secrets'
    '1.2.840.113556.1.4.1935' = 'Active Directory (v6.0) >= Windows 2008'
    '1.2.840.113556.1.4.1947' = 'Force Update'
    '1.2.840.113556.1.4.1948' = 'Range Retrieval No Error'
    '1.2.840.113556.1.4.2026' = 'Input DN'
    '1.2.840.113556.1.4.2064' = 'Show Recycled'
    '1.2.840.113556.1.4.2065' = 'Show Deactivated Link'
    '1.2.840.113556.1.4.2080' = 'Active Directory (v6.1) >= Windows 2008 R2'
}

# Forest Report comments
$Comment_ForestDomainDCs = 
@'
<tr>
<th class="sectioncolumngrouping" colspan=6>Server Information</th>
<th class="sectioncolumngrouping" colspan=6>Roles</th>
</tr>
'@

# Domain Report comments
$Comment_PrivGroup_EnterpriseAdmins = 
@'
A group that exists only at the forest level of domains. The group is authorized to make forest-wide changes in Active Directory, such as adding child domains. By default, the only member of the group is the Administrator account for the forest root domain.
'@
$Comment_PrivGroup_SchemaAdmins =
@'
A group that exists only at the forest level of domains. The group is authorized to make schema changes in Active Directory. By default, the only member of the group is the Administrator account for the forest root domain. No other accounts should be in this group unless schema upgrades are being done.
'@
$Comment_PrivGroup_DomainAdmins =
@'
Members are authorized to administer the domain. By default, the Domain Admins group is a member of the Administrators group on all computers that have joined a domain, including the domain controllers. Domain Admins is the default owner of any object that is created in the domain's Active Directory by any member of the group. If members of the group create other objects, such as files, the default owner is the Administrators group.
'@
$Comment_PrivGroup_Administrators =
@'
After the initial installation of the operating system, the only member of the group is the Administrator account. When a computer joins a domain, the Domain Admins group is added to the Administrators group. When a server becomes a domain controller, the Enterprise Admins group also is added to the Administrators group. The Administrators group has built-in capabilities that give its members full control over the system. The group is the default owner of any object that is created by a member of the group.
'@
$Comment_PrivGroup_AccountOperators =
@'
Exists only on domain controllers. By default, the group has no members. By default, Account Operators have permission to create, modify, and delete accounts for users, groups, and computers in all containers and organizational units (OUs) of Active Directory except the Builtin container and the Domain Controllers OU. Account Operators do not have permission to modify the Administrators and Domain Admins groups, nor do they have permission to modify the accounts for members of those groups.
'@
$Comment_PrivGroup_ServerOperators =
@'
Exists only on domain controllers. By default, the group has no members. Server Operators can log on to a server interactively; create and delete network shares; start and stop services; back up and restore files; format the hard disk of the computer; and shut down the computer.
'@
$Comment_PrivGroup_BackupOperators =
@'
By default, the group has no members. Backup Operators can back up and restore all files on a computer, regardless of the permissions that protect those files. Backup Operators also can log on to the computer and shut it down.
'@
$Comment_PrivGroup_PrintOperators =
@'
Exists only on domain controllers. By default, the only member is the Domain Users group. Print Operators can manage printers and document queues.
'@
$Comment_PrivGroup_CertPublishers =
@'
Exists only on domain controllers. By default, the only member is the Domain Users group. Print Operators can manage printers and document queues.
'@
#endregion Custom Static Variables

#region Global Options and Variables
# Change this to allow for more or less result properties to span horizontally
#  anything equal to or above this threshold will get displayed vertically instead.
#  (NOTE: This only applies to sections set to be dynamic in html reports)
$HorizontalThreshold = 10

$currdir = ''
if ($MyInvocation.MyCommand.Path) {
    $currdir = Split-Path $MyInvocation.MyCommand.Path
} else {
    $currdir = $pwd -replace '^\S+::',''
}
#endregion Global Options and Variables

#region System Report Section Processing Definitions
$ADForestReportPreProcessing =
@'
    Get-ADForestReportInformation @VerboseDebug `
                               -ReportContainer $ReportContainer `
                               -SortedRpts $SortedReports
'@

$ADDomainReportPreProcessing =
@'
    Get-ADDomainReportInformation @VerboseDebug `
                               -ReportContainer $ReportContainer `
                               -SortedRpts $SortedReports
'@

$LyncElements_Postprocessing =
@'
    $temp = Format-HTMLTable $Table -Column 'Type' -ColumnValue 'Internal' -Attr 'class' -AttrValue 'healthy'
    $temp = Format-HTMLTable $temp -Column 'Type' -ColumnValue 'Backend' -Attr 'class' -AttrValue 'healthy'
    $temp = Format-HTMLTable $temp -Column 'Type' -ColumnValue 'Pool' -Attr 'class' -AttrValue 'warn'
            Format-HTMLTable $temp -Column 'Type' -ColumnValue 'Edge' -Attr 'class' -AttrValue 'alert'
'@

$ForestDomainDNSZones_Postprocessing =
@'
    [scriptblock]$scriptblock = {[string]$args[0] -match [string]$args[1]}
    $temp = Format-HTMLTable $Table -Scriptblock $scriptblock -Column 'Name' -ColumnValue 'CNF:' -Attr 'class' -AttrValue 'warn'
            Format-HTMLTable $temp  -Scriptblock $scriptblock -Column 'Name' -ColumnValue 'InProgress' -Attr 'class' -AttrValue 'warn'
'@
$ForestSiteConnections_Postprocessing =
@'
    $temp = Format-HTMLTable $Table -Column 'Enabled' -ColumnValue 'True' -Attr 'class' -AttrValue 'healthy'
            Format-HTMLTable $temp -Column 'Enabled' -ColumnValue 'False' -Attr 'class' -AttrValue 'alert'
'@

$ForestDomainDCs_Postprocessing =
@'
    $temp = Format-HTMLTable $Table -Column 'GC' -ColumnValue 'True' -Attr 'class' -AttrValue 'healthy'
    $temp = Format-HTMLTable $temp -Column 'GC' -ColumnValue 'False' -Attr 'class' -AttrValue 'alert'
    $temp = Format-HTMLTable $temp -Column 'Infra' -ColumnValue 'True' -Attr 'class' -AttrValue 'healthy'
    $temp = Format-HTMLTable $temp -Column 'Infra' -ColumnValue 'False' -Attr 'class' -AttrValue 'alert'
    $temp = Format-HTMLTable $temp -Column 'Naming' -ColumnValue 'True' -Attr 'class' -AttrValue 'healthy'
    $temp = Format-HTMLTable $temp -Column 'Naming' -ColumnValue 'False' -Attr 'class' -AttrValue 'alert'
    $temp = Format-HTMLTable $temp -Column 'Schema' -ColumnValue 'True' -Attr 'class' -AttrValue 'healthy'
    $temp = Format-HTMLTable $temp -Column 'Schema' -ColumnValue 'False' -Attr 'class' -AttrValue 'alert'
    $temp = Format-HTMLTable $temp -Column 'RID' -ColumnValue 'True' -Attr 'class' -AttrValue 'healthy'
    $temp = Format-HTMLTable $temp -Column 'RID' -ColumnValue 'False' -Attr 'class' -AttrValue 'alert'
    $temp = Format-HTMLTable $temp -Column 'PDC' -ColumnValue 'True' -Attr 'class' -AttrValue 'healthy'
            Format-HTMLTable $temp -Column 'PDC' -ColumnValue 'False' -Attr 'class' -AttrValue 'alert'
'@

$ADPrivUser_Postprocessing =
@'
    [scriptblock]$scriptblock = {[int]$args[0] -ge [int]$args[1]}
    [scriptblock]$scriptblockhealthy = {[int]$args[0] -lt [int]$args[1]}
    $temp = Format-HTMLTable $Table -Column 'No Pwd Expiry' -ColumnValue 'True' -Attr 'class' -AttrValue 'warn'
    $temp = Format-HTMLTable $temp -Column 'No Pwd Expiry' -ColumnValue 'False' -Attr 'class' -AttrValue 'healthy'
    $temp = Format-HTMLTable $temp -Column 'Pwd Reversable' -ColumnValue 'True' -Attr 'class' -AttrValue 'alert'
    $temp = Format-HTMLTable $temp -Column 'Pwd Reversable' -ColumnValue 'False' -Attr 'class' -AttrValue 'healthy'
    $temp = Format-HTMLTable $temp -Column 'Pwd Not Req.' -ColumnValue 'True' -Attr 'class' -AttrValue 'warn'
    $temp = Format-HTMLTable $temp -Column 'Pwd Not Req.' -ColumnValue 'False' -Attr 'class' -AttrValue 'healthy'
    $temp = Format-HTMLTable $temp -Scriptblock $scriptblockhealthy -Column 'Pwd Age (Days)' -ColumnValue $AD_PwdAgeHealthy -Attr 'class' -AttrValue 'healthy'
    $temp = Format-HTMLTable $temp -Scriptblock $scriptblock        -Column 'Pwd Age (Days)' -ColumnValue $AD_PwdAgeWarn -Attr 'class' -AttrValue 'warn'
            Format-HTMLTable $temp -Scriptblock $scriptblock        -Column 'Pwd Age (Days)' -ColumnValue $AD_PwdAgeAlert -Attr 'class' -AttrValue 'alert'
'@
#endregion Report Section Processing Definitions

#region Report Structure Definitions
<#
    Configuration
        TOC - Possibly used in the future to create a table of contents
        PreProcessing - Scriptblock to to information gathering
        SkipSectionBreaks - Allows total bypassing of sections of type 
                            'SectionBreak' in reports
        ReportTypes - List all possible report types. The first one listed
                      here will be the default used if none are specified
                      when generating the report.
        Assets - A list of assets which will be reported upon. These are keys in hashes of data
                 broken down by section. In a self contained asset report this will get
                 populated by the PreProcessing information gathering script. Usually
                 this starts out empty and gets automatically filled.
        PostProcessingEnabled - Usually this is true. Currently postprocessing for my scripts
                                rely heavily on a custom function called Format-HTMLTable which,
                                in turn, relies on at least .Net 3.5 sp2 being available for 
                                Linq assemblies. This is done to try and remove the need for
                                custom modules. If you get a bunch of errors about linq not being
                                available you can simply skip post processing by setting this to
                                be false.
#>
$ADForestReport = @{
    'Configuration' = @{
        'TOC'               = $true
        'PreProcessing'     = $ADForestReportPreProcessing
        'SkipSectionBreaks' = $false
        'ReportTypes'       = @('FullDocumentation','ExcelExport')
        'Assets'            = @()
        'PostProcessingEnabled' = $true
    }
    'Sections' = @{
        'Break_ForestInformation' = @{
            'Enabled' = $true
            'ShowSectionEvenWithNoData' = $true
            'Order' = 0
            'AllData' = @{}
            'Title' = 'Forest Information'
            'Type' = 'SectionBreak'
            'ReportTypes' = @{
                'ExcelExport' = $false
                'FullDocumentation' = @{
                    'ContainerType' = 'full'
                    'SectionOverride' = $false
                    'TableType' = 'Horizontal'
                    'Properties' = $true
                }
            }
        }
        'ForestSummary' = @{
            'Enabled' = $true
            'ShowSectionEvenWithNoData' = $true
            'Order' = 1
            'AllData' = @{}
            'Title' = 'Forest Summary'
            'Type' = 'Section'
            'Comment' = $false
            'ReportTypes' = @{
                'ExcelExport' = @{
                    'ContainerType' = 'Half'
                    'SectionOverride' = $false
                    'TableType' = 'Vertical'
                    'Properties' =
                        @{n='Name';e={$_.ForestName}},
                        @{n='Functional Level';e={$_.ForestFunctionalLevel}},
                        @{n='Domain Naming Master';e={$_.DomainNamingMaster}},
                        @{n='Schema Master';e={$_.SchemaMaster}},
                        @{n='Domain Count';e={($_.Domains).Count}},
                        @{n='DC Server Count';e={$_.DomainControllersCount}},
                        @{n='GC Server Count';e={($_.GlobalCatalogs).Count}},
                        @{n='Exchange Server Count';e={$_.ExchangeServerCount}},
                        @{n='Lync Server Count';e={$_.LyncServerCount}},
                        @{n='Lync Pool Count';e={$_.LyncPoolCount}}
                }
                'FullDocumentation' = @{
                    'ContainerType' = 'Half'
                    'SectionOverride' = $false
                    'TableType' = 'Vertical'
                    'Properties' =
                        @{n='Name';e={$_.ForestName}},
                        @{n='Functional Level';e={$_.ForestFunctionalLevel}},
                        @{n='Domain Naming Master';e={$_.DomainNamingMaster}},
                        @{n='Schema Master';e={$_.SchemaMaster}},
                        @{n='Domain Count';e={($_.Domains).Count}},
                        @{n='Site Count';e={($_.Sites).Count}},
                        @{n='DC Server Count';e={$_.DomainControllersCount}},
                        @{n='GC Server Count';e={($_.GlobalCatalogs).Count}},
                        @{n='Exchange Server Count';e={$_.ExchangeServerCount}},
                        @{n='Lync Server Count';e={$_.LyncServerCount}},
                        @{n='Lync Pool Count';e={$_.LyncPoolCount}}
                }
            }
        }
        'SiteSummary' = @{
            'Enabled' = $true
            'ShowSectionEvenWithNoData' = $true
            'Order' = 2
            'AllData' = @{}
            'Title' = 'Site Summary'
            'Type' = 'Section'
            'Comment' = $false
            'ReportTypes' = @{
                'ExcelExport' = @{
                    'ContainerType' = 'Half'
                    'SectionOverride' = $false
                    'TableType' = 'Vertical'
                    'Properties' =
                        @{n='Site Count';e={$_.SiteCount}},
                        @{n='Site Subnet Count';e={$_.SiteSubnetCount}},
                        @{n='Site Link Count';e={$_.SiteLinkCount}},
                        @{n='Site Connection Count';e={$_.SiteConnectionCount}},
                        @{n='Sites Without Site Connections';e={$_.SitesWithotuSiteConnections}},
                        @{n='Sites Without ISTG';e={$_.SitesWithoutISTG}},
                        @{n='Sites Without Subnets';e={$_.SitesWithoutSubnets}},
                        @{n='Sites Without Servers';e={$_.SitesWithoutServers}}
                }
                'FullDocumentation' = @{
                    'ContainerType' = 'Half'
                    'SectionOverride' = $false
                    'TableType' = 'Vertical'
                    'Properties' =
                        @{n='Site Count';e={$_.SiteCount}},
                        @{n='Site Subnet Count';e={$_.SiteSubnetCount}},
                        @{n='Site Link Count';e={$_.SiteLinkCount}},
                        @{n='Site Connection Count';e={$_.SiteConnectionCount}},
                        @{n='Sites Without Site Connections';e={$_.SitesWithoutSiteConnections}},
                        @{n='Sites Without ISTG';e={$_.SitesWithoutISTG}},
                        @{n='Sites Without Subnets';e={$_.SitesWithoutSubnets}},
                        @{n='Sites Without Servers';e={$_.SitesWithoutServers}}
                }
            }
        }
        'ForestFeatures' = @{
            'Enabled' = $true
            'ShowSectionEvenWithNoData' = $true
            'Order' =3
            'AllData' = @{}
            'Title' = 'Forest Features'
            'Type' = 'Section'
            'Comment' = $false
            'ReportTypes' = @{
                'ExcelExport' = @{
                    'ContainerType' = 'Half'
                    'SectionOverride' = $false
                    'TableType' = 'Vertical'
                    'Properties' =
                        @{n='Recycle Bin Enabled';e={$_.RecycleBinEnabled}},
                        @{n='Tombstone Lifetime';e={$_.TombstoneLifetime}},
                        @{n='Exchange Version';e={$_.ExchangeVersion}},
                        @{n='Lync Version';e={$_.LyncVersion}},
                       # @{n='Deleted Object Lifetime';e={$_.DeletedObjectLife}},
                       # @{n='Total Object Backup Lifetime';e={$_.TotalObjectBackupLife}},
                        @{n='Lync AD Container';e={$_.LyncADContainer}}
                }
                'FullDocumentation' = @{
                    'ContainerType' = 'Half'
                    'SectionOverride' = $false
                    'TableType' = 'Vertical'
                    'Properties' =
                        @{n='Recycle Bin Enabled';e={$_.RecycleBinEnabled}},
                        @{n='Tombstone Lifetime';e={$_.TombstoneLifetime}},
                        @{n='Exchange Version';e={$_.ExchangeVersion}},
                        @{n='Lync Version';e={$_.LyncVersion}},
                      #  @{n='Deleted Object Lifetime';e={$_.DeletedObjectLife}},
                      #  @{n='Total Object Backup Lifetime';e={$_.TotalObjectBackupLife}},
                        @{n='Lync AD Container';e={$_.LyncADContainer}}
                }
            }
        }
        'ForestLyncInfo' = @{
            'Enabled' = $true
            'ShowSectionEvenWithNoData' = $false
            'Order' = 4
            'AllData' = @{}
            'Title' = 'Lync Elements'
            'Type' = 'Section'
            'Comment' = $false
            'ReportTypes' = @{
                'ExcelExport' = @{
                    'ContainerType' = 'Half'
                    'SectionOverride' = $false
                    'TableType' = 'Horizontal'
                    'Properties' =
                        @{n='Function';e={$_.LyncElement}},
                        @{n='Type';e={$_.LyncElementType}},
                        @{n='FQDN';e={$_.LyncElementFQDN}}
                }
                'FullDocumentation' = @{
                    'ContainerType' = 'Half'
                    'SectionOverride' = $false
                    'TableType' = 'Horizontal'
                    'Properties' =
                        @{n='Function';e={$_.LyncElement}},
                        @{n='Type';e={$_.LyncElementType}},
                        @{n='FQDN';e={$_.LyncElementFQDN}}
                }
            }
            'PostProcessing' = $LyncElements_Postprocessing
        }
        'ForestExchangeInfo' = @{
            'Enabled' = $true
            'ShowSectionEvenWithNoData' = $false
            'Order' = 5
            'AllData' = @{}
            'Title' = 'Forest Exchange Servers'
            'Type' = 'Section'
            'Comment' = $false
            'ReportTypes' = @{
                'ExcelExport' = @{
                    'ContainerType' = 'Full'
                    'SectionOverride' = $false
                    'TableType' = 'Horizontal'
                    'Properties' =
                        @{n='Org';e={$_.Organization}},
                        @{n='Admin Group';e={$_.AdminGroup}},
                        @{n='Name';e={$_.Name}},
                        @{n='Roles';e={$_.Role}},
                        @{n='Site';e={$_.Site}},
                        #@{n='Created';e={$_.Created}},
                        @{n='Serial';e={$_.Serial}},
                        @{n='Product ID';e={$_.ProductID}}
                }
                'FullDocumentation' = @{
                    'ContainerType' = 'Full'
                    'SectionOverride' = $false
                    'TableType' = 'Horizontal'
                    'Properties' =
                        @{n='Org';e={$_.Organization}},
                        @{n='Admin Group';e={$_.AdminGroup}},
                        @{n='Name';e={$_.Name}},
                        @{n='Roles';e={$_.Role}},
                        @{n='Site';e={$_.Site}},
                        #@{n='Created';e={$_.Created}},
                        @{n='Serial';e={$_.Serial}},
                        @{n='Product ID';e={$_.ProductID}}
                }
            }
        }
        'ForestExchangeFederations' = @{
            'Enabled' = $true
            'ShowSectionEvenWithNoData' = $false
            'Order' = 6
            'AllData' = @{}
            'Title' = 'Forest Exchange Federations'
            'Type' = 'Section'
            'Comment' = $false
            'ReportTypes' = @{
                'ExcelExport' = @{
                    'ContainerType' = 'Full'
                    'SectionOverride' = $false
                    'TableType' = 'Horizontal'
                    'Properties' =
                        @{n='Org';e={$_.Organization}},
                        @{n='Name';e={$_.Name}},
                        @{n='Enabled';e={$_.Enabled}},
                        @{n='Domains';e={[string]$_.Domains -replace ' ', "`n`r"}},
                        @{n='Allowed Actions';e={[string]$_.AllowedActions -replace ' ', "`n`r"}},
                        @{n='App URI';e={$_.TargetAppURI}},
                        @{n='Autodiscover EPR';e={$_.TargetAutodiscoverEPR}}
                }
                'FullDocumentation' = @{
                    'ContainerType' = 'Full'
                    'SectionOverride' = $false
                    'TableType' = 'Horizontal'
                    'Properties' =
                        @{n='Org';e={$_.Organization}},
                        @{n='Name';e={$_.Name}},
                        @{n='Enabled';e={$_.Enabled}},
                        @{n='Domains';e={[string]$_.Domains -replace ' ', "<br />`n`r"}},
                        @{n='Allowed Actions';e={[string]$_.AllowedActions -replace ' ', "<br />`n`r"}}
                        #@{n='App URI';e={$_.TargetAppURI}},
                        #@{n='Autodiscover EPR';e={$_.TargetAutodiscoverEPR}}
                }
            }
        }
        'ForestDHCPServers' = @{
            'Enabled' = $true
            'ShowSectionEvenWithNoData' = $false
            'Order' = 7
            'AllData' = @{}
            'Title' = 'Registered DHCP Servers'
            'Type' = 'Section'
            'Comment' = $false
            'ReportTypes' = @{
                'ExcelExport' = @{
                    'ContainerType' = 'Half'
                    'SectionOverride' = $false
                    'TableType' = 'Horizontal'
                    'Properties' =
                        @{n='Name';e={$_.Name}},
                        @{n='Created';e={$_.WhenCreated}}
                }
                'FullDocumentation' = @{
                    'ContainerType' = 'Half'
                    'SectionOverride' = $false
                    'TableType' = 'Horizontal'
                    'Properties' =
                        @{n='Name';e={$_.Name}},
                        @{n='Created';e={$_.WhenCreated}}
                }
            }
        }
        'ForestDomainNPSServers' = @{
            'Enabled' = $true
            'ShowSectionEvenWithNoData' = $false
            'Order' = 8
            'AllData' = @{}
            'Title' = 'Registered NPS Servers'
            'Type' = 'Section'
            'Comment' = $false
            'ReportTypes' = @{
                'ExcelExport' = @{
                    'ContainerType' = 'Half'
                    'SectionOverride' = $false
                    'TableType' = 'Horizontal'
                    'Properties' =
                        @{n='Domain';e={$_.Domain}},
                        @{n='Name';e={$_.Name}},
                        @{n='Type';e={$_.Type}}
                }
                'FullDocumentation' = @{
                    'ContainerType' = 'Half'
                    'SectionOverride' = $false
                    'TableType' = 'Horizontal'
                    'Properties' =
                        @{n='Domain';e={$_.Domain}},
                        @{n='Name';e={$_.Name}},
                        @{n='Type';e={$_.Type}}
                }
            }
        }
        'Break_SiteInformation' = @{
            'Enabled' = $true
            'ShowSectionEvenWithNoData' = $true
            'Order' = 10
            'AllData' = @{}
            'Title' = 'Site Information'
            'Type' = 'SectionBreak'
            'ReportTypes' = @{
                'ExcelExport' = $false
                'FullDocumentation' = @{
                    'ContainerType' = 'full'
                    'SectionOverride' = $false
                    'TableType' = 'Horizontal'
                    'Properties' = $true
                }
            }
        }
        'ForestSiteSummary' = @{
            'Enabled' = $true
            'ShowSectionEvenWithNoData' = $false
            'Order' = 11
            'AllData' = @{}
            'Title' = 'Site Summary'
            'Type' = 'Section'
            'Comment' = $false
            'ReportTypes' = @{
                'ExcelExport' = @{
                    'ContainerType' = 'Full'
                    'SectionOverride' = $false
                    'TableType' = 'Horizontal'
                    'Properties' =
                        @{n='Name';e={$_.SiteName}},
                        @{n='Location';e={$_.Location}},
                        @{n='Domains';e={[string]$_.Domains -replace ' ', "`n`r"}},
                        @{n='DCs';e={[string]$_.Servers -replace ' ', "`n`r"}},
                        @{n='Subnets';e={[string]$_.Subnets  -replace ' ', "`n`r"}}
                }
                'FullDocumentation' = @{
                    'ContainerType' = 'Full'
                    'SectionOverride' = $false
                    'TableType' = 'Horizontal'
                    'Properties' =
                        @{n='Name';e={$_.SiteName}},
                        @{n='Location';e={$_.Location}},
                        @{n='Domains';e={[string]$_.Domains -replace ' ', "<br />`n`r"}},
                        @{n='DCs';e={[string]$_.Servers -replace ' ', "<br />`n`r"}},
                        @{n='Subnets';e={[string]$_.Subnets  -replace ' ', "<br />`n`r"}}
                }
            }
        }
        'ForestSiteDetails' = @{
            'Enabled' = $true
            'ShowSectionEvenWithNoData' = $false
            'Order' = 12
            'AllData' = @{}
            'Title' = 'Site Details'
            'Type' = 'Section'
            'Comment' = $false
            'ReportTypes' = @{
                'ExcelExport' = @{
                    'ContainerType' = 'Full'
                    'SectionOverride' = $false
                    'TableType' = 'Horizontal'
                    'Properties' =
                        @{n='Name';e={$_.SiteName}},
                        @{n='Options';e={$_.Options}},
                        @{n='ISTG';e={$_.ISTG}},
                        @{n='SiteLinks';e={[string]$_.SiteLinks -replace ' ', "`n`r"}},
                        @{n='BridgeheadServers';e={[string]$_.BridgeheadServers -replace ' ', "`n`r"}},
                        @{n='AdjacentSites';e={[string]$_.AdjacentSites -replace ' ', "`n`r"}}
                }
                'FullDocumentation' = @{
                    'ContainerType' = 'Full'
                    'SectionOverride' = $false
                    'TableType' = 'Horizontal'
                    'Properties' =
                        @{n='Name';e={$_.SiteName}},
                        @{n='Options';e={$_.Options}},
                        @{n='ISTG';e={$_.ISTG}},
                        @{n='SiteLinks';e={[string]$_.SiteLinks -replace ' ', "<br />`n`r"}},
                        @{n='BridgeheadServers';e={[string]$_.BridgeheadServers -replace ' ', "<br />`n`r"}},
                        @{n='AdjacentSites';e={[string]$_.AdjacentSites -replace ' ', "<br />`n`r"}}
                }
            }
        }
        'ForestSiteSubnets' = @{
            'Enabled' = $true
            'ShowSectionEvenWithNoData' = $false
            'Order' = 13
            'AllData' = @{}
            'Title' = 'Site Subnets'
            'Type' = 'Section'
            'Comment' = $false
            'ReportTypes' = @{
                'ExcelExport' = @{
                    'ContainerType' = 'Full'
                    'SectionOverride' = $false
                    'TableType' = 'Horizontal'
                    'Properties' =
                        @{n='Subnet';e={$_.Name}},
                        @{n='Site Name';e={$_.SiteName}},
                        @{n='Location';e={$_.Location}}
                }
                'FullDocumentation' = @{
                    'ContainerType' = 'Full'
                    'SectionOverride' = $false
                    'TableType' = 'Horizontal'
                    'Properties' =
                        @{n='Subnet';e={$_.Name}},
                        @{n='Site Name';e={$_.SiteName}},
                        @{n='Location';e={$_.Location}}
                }
            }
        }
        'ForestSiteConnections' = @{
            'Enabled' = $true
            'ShowSectionEvenWithNoData' = $false
            'Order' = 14
            'AllData' = @{}
            'Title' = 'Site Connections'
            'Type' = 'Section'
            'Comment' = $false
            'ReportTypes' = @{
                'ExcelExport' = @{
                    'ContainerType' = 'Full'
                    'SectionOverride' = $false
                    'TableType' = 'Horizontal'
                    'Properties' =
                        @{n='Enabled';e={$_.Enabled}},
                        @{n='Options';e={$_.Options}},
                        @{n='From';e={$_.FromServer}},
                        @{n='To';e={$_.Server}}
                }
                'FullDocumentation' = @{
                    'ContainerType' = 'Full'
                    'SectionOverride' = $false
                    'TableType' = 'Horizontal'
                    'Properties' =
                        @{n='Enabled';e={$_.Enabled}},
                        @{n='Options';e={$_.Options}},
                        @{n='From';e={$_.FromServer}},
                        @{n='To';e={$_.Server}}
                }
            }
            'PostProcessing' = $ForestSiteConnections_Postprocessing
        }
        'ForestSiteLinks' = @{
            'Enabled' = $true
            'ShowSectionEvenWithNoData' = $true
            'Order' = 15
            'AllData' = @{}
            'Title' = 'Site Links'
            'Type' = 'Section'
            'Comment' = $false
            'ReportTypes' = @{
                'ExcelExport' = @{
                    'ContainerType' = 'Full'
                    'SectionOverride' = $false
                    'TableType' = 'Horizontal'
                    'Properties' =
                        @{n='Name';e={$_.Name}},
                        @{n='Replication Interval';e={$_.repInterval}},
                        @{n='Sites';e={[string]$_.Sites -replace ' ', "`n`r"}},
                        @{n='Change Notification Enabled';e={$_.ChangeNotification}}
                }
                'FullDocumentation' = @{
                    'ContainerType' = 'Full'
                    'SectionOverride' = $false
                    'TableType' = 'Horizontal'
                    'Properties' =
                        @{n='Name';e={$_.Name}},
                        @{n='Replication Interval';e={$_.repInterval}},
                        @{n='Sites';e={[string]$_.Sites -replace ' ', "<br />`n`r"}},
                        @{n='Change Notification Enabled';e={$_.ChangeNotification}}
                }
            }
            'PostProcessing' = $False
        }
        'Break_DomainInformation' = @{
            'Enabled' = $true
            'ShowSectionEvenWithNoData' = $true
            'Order' = 20
            'AllData' = @{}
            'Title' = 'Domain Information'
            'Type' = 'SectionBreak'
            'ReportTypes' = @{
                'ExcelExport' = $false
                'FullDocumentation' = @{
                    'ContainerType' = 'full'
                    'SectionOverride' = $false
                    'TableType' = 'Horizontal'
                    'Properties' = $true
                }
            }
        }
        'ForestDomains' = @{
            'Enabled' = $true
            'ShowSectionEvenWithNoData' = $true
            'Order' = 21
            'AllData' = @{}
            'Title' = 'Domains'
            'Type' = 'Section'
            'Comment' = $false
            'ReportTypes' = @{
                'ExcelExport' = @{
                    'ContainerType' = 'Full'
                    'SectionOverride' = $false
                    'TableType' = 'Horizontal'
                    'Properties' =
                        @{n='Name';e={$_.Domain}},
                        @{n='NetBIOS';e={$_.NetBIOSName}},
                        @{n='Functional Level';e={$_.DomainFunctionalLevel}},
                        @{n='Forest Root';e={$_.IsForestRoot}},
                        @{n='RIDs Issued';e={$_.RIDsIssued}},
                        @{n='RIDs Remaining';e={$_.RIDsRemaining}},
                        @{n='Naming Master';e={$_.DomainNamingMaster}},
                        @{n='Schema Master';e={$_.SchemaMaster}},
                        @{n='PDC Emulator';e={$_.PDCEmulator}},
                        @{n='RID Master';e={$_.RIDMaster}},
                        @{n='Infra Master';e={$_.InfrastructureMaster}}
                }
                'FullDocumentation' = @{
                    'ContainerType' = 'Full'
                    'SectionOverride' = $false
                    'TableType' = 'Horizontal'
                    'Properties' =
                        @{n='Name';e={$_.Domain}},
                        @{n='NetBIOS';e={$_.NetBIOSName}},
                        @{n='Functional Level';e={$_.DomainFunctionalLevel}},
                        @{n='Forest Root';e={$_.IsForestRoot}},
                        @{n='RIDs Issued';e={$_.RIDsIssued}},
                        @{n='RIDs Remaining';e={$_.RIDsRemaining}}
                }
            }
        }
        'ForestDomainPasswordPolicy' = @{
            'Enabled' = $true
            'ShowSectionEvenWithNoData' = $true
            'Order' = 22
            'AllData' = @{}
            'Title' = 'Domain Password Policies'
            'Type' = 'Section'
            'Comment' = $false
            'ReportTypes' = @{
                'ExcelExport' = @{
                    'ContainerType' = 'Full'
                    'SectionOverride' = $false
                    'TableType' = 'Horizontal'
                    'Properties' =
                        @{n='Name';e={$_.Domain}},
                        @{n='NetBIOS';e={$_.NetBIOSName}},
                        @{n='Lockout Threshold';e={$_.lockoutThreshold}},
                        @{n='Password History Length';e={$_.pwdHistoryLength}},
                        @{n='Max Password Age';e={$_.maxPwdAge}},
                        @{n='Min Password Age';e={$_.minPwdAge}},
                        @{n='Min Password Length';e={$_.minPwdLength}}
                }
                'FullDocumentation' = @{
                    'ContainerType' = 'Full'
                    'SectionOverride' = $false
                    'TableType' = 'Horizontal'
                    'Properties' =
                        @{n='Name';e={$_.Domain}},
                        @{n='NetBIOS';e={$_.NetBIOSName}},
                        @{n='Lockout Threshold';e={$_.lockoutThreshold}},
                        @{n='Password History Length';e={$_.pwdHistoryLength}},
                        @{n='Max Password Age';e={$_.maxPwdAge}},
                        @{n='Min Password Age';e={$_.minPwdAge}},
                        @{n='Min Password Length';e={$_.minPwdLength}}
                }
            }
        }
        'ForestDomainDCs' = @{
            'Enabled' = $true
            'ShowSectionEvenWithNoData' = $true
            'Order' = 23
            'AllData' = @{}
            'Title' = 'Domain Controllers'
            'Type' = 'Section'
            'Comment' = $Comment_ForestDomainDCs
            'ReportTypes' = @{
                'ExcelExport' = @{
                    'ContainerType' = 'Full'
                    'SectionOverride' = $false
                    'TableType' = 'Horizontal'
                    'Properties' =
                        @{n='Domain';e={$_.Domain}},
                        @{n='Site';e={$_.Site}},
                        @{n='Name';e={$_.Name}},
                        @{n='OS';e={$_.OS}},
                        @{n='Time';e={$_.CurrentTime}},
                        @{n='IP';e={$_.IPAddress}},
                        @{n='GC';e={$_.IsGC}},
                        @{n='Infra';e={$_.IsInfraMaster}},
                        @{n='Naming';e={$_.IsNamingMaster}},
                        @{n='Schema';e={$_.IsSchemaMaster}},
                        @{n='RID';e={$_.IsRidMaster}},
                        @{n='PDC';e={$_.IsPdcMaster}}
                }
                'FullDocumentation' = @{
                    'ContainerType' = 'Full'
                    'SectionOverride' = $false
                    'TableType' = 'Horizontal'
                    'Properties' =
                        @{n='Domain';e={$_.Domain}},
                        @{n='Site';e={$_.Site}},
                        @{n='Name';e={$_.Name}},
                        @{n='OS';e={$_.OS}},
                        @{n='Time';e={$_.CurrentTime}},
                        @{n='IP';e={$_.IPAddress}},
                        @{n='GC';e={$_.IsGC}},
                        @{n='Infra';e={$_.IsInfraMaster}},
                        @{n='Naming';e={$_.IsNamingMaster}},
                        @{n='Schema';e={$_.IsSchemaMaster}},
                        @{n='RID';e={$_.IsRidMaster}},
                        @{n='PDC';e={$_.IsPdcMaster}}
                }
            }
            'PostProcessing' = $ForestDomainDCs_Postprocessing
        }
        'ForestDomainTrusts' = @{
            'Enabled' = $true
            'ShowSectionEvenWithNoData' = $false
            'Order' = 24
            'AllData' = @{}
            'Title' = 'Domain Trusts'
            'Type' = 'Section'
            'Comment' = $false
            'ReportTypes' = @{
                'ExcelExport' = @{
                    'ContainerType' = 'Full'
                    'SectionOverride' = $false
                    'TableType' = 'Horizontal'
                    'Properties' =
                        @{n='Domain';e={$_.Domain}},
                        @{n='Trusted Domain';e={$_.TrustedDomain}},
                        @{n='Direction';e={$_.Direction}},
                        @{n='Attributes';e={$_.Attributes}},
                        @{n='Trust Type';e={$_.TrustType}},
                        @{n='Created';e={$_.Created}},
                        @{n='Modified';e={$_.Modified}}
                }
                'FullDocumentation' = @{
                    'ContainerType' = 'Full'
                    'SectionOverride' = $false
                    'TableType' = 'Horizontal'
                    'Properties' =
                        @{n='Domain';e={$_.Domain}},
                        @{n='Trusted Domain';e={$_.TrustedDomain}},
                        @{n='Direction';e={$_.Direction}},
                        @{n='Attributes';e={$_.Attributes}},
                        @{n='Trust Type';e={$_.TrustType}},
                        @{n='Created';e={$_.Created}},
                        @{n='Modified';e={$_.Modified}}
                }
            }
        }
        'ForestDomainDFSShares' = @{
            'Enabled' = $true
            'ShowSectionEvenWithNoData' = $false
            'Order' = 25
            'AllData' = @{}
            'Title' = 'Domain DFS Shares'
            'Type' = 'Section'
            'Comment' = $false
            'ReportTypes' = @{
                'ExcelExport' = @{
                    'ContainerType' = 'Full'
                    'SectionOverride' = $false
                    'TableType' = 'Horizontal'
                    'Properties' =
                        @{n='Domain';e={$_.Domain}},
                        @{n='Name';e={$_.Name}},
                        @{n='DN';e={$_.DN}},
                        @{n='Remote Server';e={$_.RemoteServerName}}
                }
                'FullDocumentation' = @{
                    'ContainerType' = 'Full'
                    'SectionOverride' = $false
                    'TableType' = 'Horizontal'
                    'Properties' =
                        @{n='Domain';e={$_.Domain}},
                        @{n='Name';e={$_.Name}},
                        @{n='DN';e={$_.DN}},
                        @{n='Remote Server';e={$_.RemoteServerName}}
                }
            }
        }
        'ForestDomainDFSRShares' = @{
            'Enabled' = $true
            'ShowSectionEvenWithNoData' = $false
            'Order' = 26
            'AllData' = @{}
            'Title' = 'Domain DFSR Shares'
            'Type' = 'Section'
            'Comment' = $false
            'ReportTypes' = @{
                'ExcelExport' = @{
                    'ContainerType' = 'Full'
                    'SectionOverride' = $false
                    'TableType' = 'Horizontal'
                    'Properties' =
                        @{n='Domain';e={$_.Domain}},
                        @{n='Name';e={$_.Name}},
                        @{n='Content';e={[string]$_.Content -replace ' ', "`n`r"}},
                        @{n='Remote Servers';e={[string]$_.RemoteServerName -replace ' ', "`n`r"}}
                }
                'FullDocumentation' = @{
                    'ContainerType' = 'Full'
                    'SectionOverride' = $false
                    'TableType' = 'Horizontal'
                    'Properties' =
                        @{n='Domain';e={$_.Domain}},
                        @{n='Name';e={$_.Name}},
                        @{n='Content';e={[string]$_.Content -replace ' ', "<br />`n`r"}},
                        @{n='Remote Servers';e={[string]$_.RemoteServerName -replace ' ', "<br />`n`r"}}
                }
            }
        }
        'ForestDomainDNSZones' = @{
            'Enabled' = $true
            'ShowSectionEvenWithNoData' = $false
            'Order' = 27
            'AllData' = @{}
            'Title' = 'Domain Integrated DNS Zones'
            'Type' = 'Section'
            'Comment' = 'Active Directory integrated DNS zones. Zone names containing CNF: or InProgress may be duplicate and should be reviewed.'
            'ReportTypes' = @{
                'ExcelExport' = @{
                    'ContainerType' = 'Full'
                    'SectionOverride' = $false
                    'TableType' = 'Horizontal'
                    'Properties' =
                        @{n='Domain';e={$_.Domain}},
                        @{n='Partition';e={$_.AppPartition}},
                        @{n='Name';e={$_.Name}},
                        @{n='Record Count';e={$_.RecordCount}},
                        @{n='Created';e={$_.Created}},
                        @{n='Changed';e={$_.Changed}}
                }
                'FullDocumentation' = @{
                    'ContainerType' = 'Full'
                    'SectionOverride' = $false
                    'TableType' = 'Horizontal'
                    'Properties' =
                        @{n='Domain';e={$_.Domain}},
                        @{n='Partition';e={$_.AppPartition}},
                        @{n='Name';e={$_.Name}},
                        @{n='Record Count';e={$_.RecordCount}},
                        @{n='Created';e={$_.Created}},
                        @{n='Changed';e={$_.Changed}}
                }
            }
            'PostProcessing' = $ForestDomainDNSZones_Postprocessing
        }
        'ForestDomainGPOs' = @{
            'Enabled' = $true
            'ShowSectionEvenWithNoData' = $false
            'Order' = 28
            'AllData' = @{}
            'Title' = 'Domain GPOs'
            'Type' = 'Section'
            'Comment' = $false
            'ReportTypes' = @{
                'ExcelExport' = @{
                    'ContainerType' = 'Full'
                    'SectionOverride' = $false
                    'TableType' = 'Horizontal'
                    'Properties' =
                        @{n='Domain';e={$_.Domain}},
                        @{n='Name';e={$_.Name}},
                        @{n='Created';e={$_.Created}},
                        @{n='Changed';e={$_.Changed}}
                }
                'FullDocumentation' = @{
                    'ContainerType' = 'Full'
                    'SectionOverride' = $false
                    'TableType' = 'Horizontal'
                    'Properties' =
                        @{n='Domain';e={$_.Domain}},
                        @{n='Name';e={$_.Name}},
                        @{n='Created';e={$_.Created}},
                        @{n='Changed';e={$_.Changed}}
                }
            }
        }
        'ForestDomainPrinters' = @{
            'Enabled' = $true
            'ShowSectionEvenWithNoData' = $false
            'Order' = 30
            'AllData' = @{}
            'Title' = 'Domain Registered Printers'
            'Type' = 'Section'
            'Comment' = $false
            'ReportTypes' = @{
                'ExcelExport' = @{
                    'ContainerType' = 'Full'
                    'SectionOverride' = $false
                    'TableType' = 'Horizontal'
                    'Properties' =
                        @{n='Domain';e={$_.Domain}},
                        @{n='Name';e={$_.Name}},
                        @{n='ServerName';e={$_.serverName}},
                        @{n='ShareName';e={$_.printShareName}},
                        @{n='Location';e={$_.location}},
                        @{n='DriverName';e={$_.driverName}}
                }
                'FullDocumentation' = @{
                    'ContainerType' = 'Full'
                    'SectionOverride' = $false
                    'TableType' = 'Horizontal'
                    'Properties' =
                        @{n='Domain';e={$_.Domain}},
                        @{n='Name';e={$_.Name}},
                        @{n='ServerName';e={$_.serverName}},
                        @{n='ShareName';e={$_.printShareName}},
                        @{n='Location';e={$_.location}},
                        @{n='DriverName';e={$_.driverName}}
                }
            }
        }
        'ForestDomainSCCMServers' = @{
            'Enabled' = $true
            'ShowSectionEvenWithNoData' = $false
            'Order' = 31
            'AllData' = @{}
            'Title' = 'Registered SCCM Servers'
            'Type' = 'Section'
            'Comment' = $false
            'ReportTypes' = @{
                'ExcelExport' = @{
                    'ContainerType' = 'Full'
                    'SectionOverride' = $false
                    'TableType' = 'Horizontal'
                    'Properties' =
                        @{n='Domain';e={$_.Domain}},
                        @{n='Name';e={$_.dNSHostName}},
                        @{n='Site Code';e={$_.mSSMSSiteCode}},
                        @{n='Version';e={$_.mSSMSVersion}},
                        @{n='Default MP';e={$_.mSSMSDefaultMP}},
                        @{n='Device MP';e={$_.mSSMSDeviceManagementPoint}}
                }
                'FullDocumentation' = @{
                    'ContainerType' = 'Full'
                    'SectionOverride' = $false
                    'TableType' = 'Horizontal'
                    'Properties' =
                        @{n='Domain';e={$_.Domain}},
                        @{n='Name';e={$_.dNSHostName}},
                        @{n='Site Code';e={$_.mSSMSSiteCode}},
                        @{n='Version';e={$_.mSSMSVersion}},
                        @{n='Default MP';e={$_.mSSMSDefaultMP}},
                        @{n='Device MP';e={$_.mSSMSDeviceManagementPoint}}
                }
            }
        }
        'ForestDomainSCCMSites' = @{
            'Enabled' = $true
            'ShowSectionEvenWithNoData' = $false
            'Order' = 32
            'AllData' = @{}
            'Title' = 'Registered SCCM Sites'
            'Type' = 'Section'
            'Comment' = $false
            'ReportTypes' = @{
                'ExcelExport' = @{
                    'ContainerType' = 'Full'
                    'SectionOverride' = $false
                    'TableType' = 'Horizontal'
                    'Properties' =
                        @{n='Domain';e={$_.Domain}},
                        @{n='Name';e={$_.Name}},
                        @{n='Site Code';e={$_.mSSMSSiteCode}},
                        @{n='Roaming Boundries';e={[string]$_.mSSMSRoamingBoundaries -replace ' ', "`n`r"}}
                }
                'FullDocumentation' = @{
                    'ContainerType' = 'Full'
                    'SectionOverride' = $false
                    'TableType' = 'Horizontal'
                    'Properties' =
                        @{n='Domain';e={$_.Domain}},
                        @{n='Name';e={$_.Name}},
                        @{n='Site Code';e={$_.mSSMSSiteCode}},
                        @{n='Roaming Boundries';e={[string]$_.mSSMSRoamingBoundaries -replace ' ', "<br />`n`r"}}
                }
            }
        }
    }
} 

$ADDomainReport = @{
    'Configuration' = @{
        'TOC'                   = $true
        'PreProcessing'         = $ADDomainReportPreProcessing
        'SkipSectionBreaks'     = $false
        'ReportTypes'           = @('FullDocumentation')
        'Assets'                = @()
        'PostProcessingEnabled' = $true
    }
    'Sections' = @{
        'Break_Stats' = @{
            'Enabled' = $true
            'ShowSectionEvenWithNoData' = $true
            'Order' = 0
            'AllData' = @{}
            'Title' = 'Domain Statistics'
            'Type' = 'SectionBreak'
            'ReportTypes' = @{
                'FullDocumentation' = @{
                    'ContainerType' = 'full'
                    'SectionOverride' = $false
                    'TableType' = 'Horizontal'
                    'Properties' = $true
                }
            }
        }
        'UserAccountStats1' = @{
            'Enabled' = $true
            'ShowSectionEvenWithNoData' = $true
            'Order' = 1
            'AllData' = @{}
            'Title' = 'User Account Statistics'
            'Type' = 'Section'
            'Comment' = $false
            'ReportTypes' = @{
                'FullDocumentation' = @{
                    'ContainerType' = 'Half'
                    'SectionOverride' = $false
                    'TableType' = 'Vertical'
                    'Properties' =
                        @{n='Total User Accounts';e={$_.Total}},
                        @{n='Enabled';e={$_.Enabled}},
                        @{n='Disabled';e={$_.Disabled}},
                        @{n='Locked';e={$_.Locked}},
                        @{n='Password Does Not Expire';e={$_.PwdDoesNotExpire}},
                        @{n='Password Must Change';e={$_.PwdMustChange}}
                }
            }
        }
        'UserAccountStats2' = @{
            'Enabled' = $true
            'ShowSectionEvenWithNoData' = $true
            'Order' = 2
            'AllData' = @{}
            'Title' = 'User Account Statistics'
            'Type' = 'Section'
            'Comment' = $false
            'ReportTypes' = @{
                'FullDocumentation' = @{
                    'ContainerType' = 'Half'
                    'SectionOverride' = $false
                    'TableType' = 'Vertical'
                    'Properties' =
                        @{n='Password Not Required';e={$_.PwdNotRequired}},
                        @{n='Dial-in Enabled';e={$_.DialInEnabled}},
                        @{n='Control Access With NPS';e={$_.ControlAccessWithNPS}},
                        @{n='Unconstrained Delegation';e={$_.UnconstrainedDelegation}},
                        @{n='Not Trusted For Delegation';e={$_.NotTrustedForDelegation}},
                        @{n='No Pre-Auth Required';e={$_.NoPreAuthRequired}}
                }
            }
        }
        'GroupStats' = @{
            'Enabled' = $true
            'ShowSectionEvenWithNoData' = $true
            'Order' = 3
            'AllData' = @{}
            'Title' = 'Group Statistics'
            'Type' = 'Section'
            'Comment' = $false
            'ReportTypes' = @{
                'FullDocumentation' = @{
                    'ContainerType' = 'Half'
                    'SectionOverride' = $false
                    'TableType' = 'Vertical'
                    'Properties' =
                        @{n='Total Groups';e={$_.Total}},
                        @{n='Built-in';e={$_.Builtin}},
                        @{n='Universal Security';e={$_.UniversalSecurity}},
                        @{n='Universal Distribution';e={$_.UniversalDist}},
                        @{n='Global Security';e={$_.GlobalSecurity}},
                        @{n='Global Distribution';e={$_.GlobalDist}},
                        @{n='Domain Local Security';e={$_.DomainLocalSecurity}},
                        @{n='Domain Local Distribution';e={$_.DomainLocalDist}}
                }
            }
        }
        'PrivGroupStats' = @{
            'Enabled' = $true
            'ShowSectionEvenWithNoData' = $true
            'Order' = 10
            'AllData' = @{}
            'Title' = 'Privileged Group Statistics'
            'Type' = 'Section'
            'Comment' = $false
            'ReportTypes' = @{
                'FullDocumentation' = @{
                    'ContainerType' = 'Full'
                    'SectionOverride' = $false
                    'TableType' = 'Horizontal'
                    'Properties' =
                        @{n='Default Name';e={$_.AdminGroup}},
                        @{n='Current Name';e={$_.DisplayName}},
                        @{n='Member Count';e={$_.MemberCount}}
                }
            }
        }
        'PrivGroup_EnterpriseAdmins' = @{
            'Enabled' = $true
            'ShowSectionEvenWithNoData' = $false
            'Order' = 20
            'AllData' = @{}
            'Title' = 'Enterprise Administrators'
            'Type' = 'Section'
            'Comment' = $Comment_PrivGroup_EnterpriseAdmins
            'ReportTypes' = @{
                'FullDocumentation' = @{
                    'ContainerType' = 'Full'
                    'SectionOverride' = $false
                    'TableType' = 'Horizontal'
                    'Properties' =
                        @{n='Logon ID';e={$_.sAMAccountName}},
                        @{n='Name';e={$_.name}},
                        @{n='Pwd Age (Days)';e={$_.PasswordAge}},
                        @{n='Last Logged In';e={$_.lastlogontimestamp}},
                        @{n='No Pwd Expiry';e={$_.DONT_EXPIRE_PASSWD}},
                        @{n='Pwd Reversable';e={$_.ENCRYPTED_TEXT_PASSWORD_ALLOWED}},
                        @{n='Pwd Not Req.';e={$_.PASSWD_NOTREQD}}
                }
            }
            'PostProcessing' = $ADPrivUser_Postprocessing
        }
        'PrivGroup_SchemaAdmins' = @{
            'Enabled' = $true
            'ShowSectionEvenWithNoData' = $false
            'Order' = 21
            'AllData' = @{}
            'Title' = 'Schema Administrators'
            'Type' = 'Section'
            'Comment' = $Comment_PrivGroup_SchemaAdmins
            'ReportTypes' = @{
                'FullDocumentation' = @{
                    'ContainerType' = 'Full'
                    'SectionOverride' = $false
                    'TableType' = 'Horizontal'
                    'Properties' =
                        @{n='Logon ID';e={$_.sAMAccountName}},
                        @{n='Name';e={$_.name}},
                        @{n='Pwd Age (Days)';e={$_.PasswordAge}},
                        @{n='Last Logged In';e={$_.lastlogontimestamp}},
                        @{n='No Pwd Expiry';e={$_.DONT_EXPIRE_PASSWD}},
                        @{n='Pwd Reversable';e={$_.ENCRYPTED_TEXT_PASSWORD_ALLOWED}},
                        @{n='Pwd Not Req.';e={$_.PASSWD_NOTREQD}}
                }
            }
            'PostProcessing' = $ADPrivUser_Postprocessing
        }
        'PrivGroup_DomainAdmins' = @{
            'Enabled' = $true
            'ShowSectionEvenWithNoData' = $false
            'Order' = 22
            'AllData' = @{}
            'Title' = 'Domain Administrators'
            'Type' = 'Section'
            'Comment' = $Comment_PrivGroup_DomainAdmins
            'ReportTypes' = @{
                'FullDocumentation' = @{
                    'ContainerType' = 'Full'
                    'SectionOverride' = $false
                    'TableType' = 'Horizontal'
                    'Properties' =
                        @{n='Logon ID';e={$_.sAMAccountName}},
                        @{n='Name';e={$_.name}},
                        @{n='Pwd Age (Days)';e={$_.PasswordAge}},
                        @{n='Last Logged In';e={$_.lastlogontimestamp}},
                        @{n='No Pwd Expiry';e={$_.DONT_EXPIRE_PASSWD}},
                        @{n='Pwd Reversable';e={$_.ENCRYPTED_TEXT_PASSWORD_ALLOWED}},
                        @{n='Pwd Not Req.';e={$_.PASSWD_NOTREQD}}
                }
            }
            'PostProcessing' = $ADPrivUser_Postprocessing
        }
        'PrivGroup_Administrators' = @{
            'Enabled' = $true
            'ShowSectionEvenWithNoData' = $false
            'Order' = 23
            'AllData' = @{}
            'Title' = 'Administrators'
            'Type' = 'Section'
            'Comment' = $Comment_PrivGroup_Administrators
            'ReportTypes' = @{
                'FullDocumentation' = @{
                    'ContainerType' = 'Full'
                    'SectionOverride' = $false
                    'TableType' = 'Horizontal'
                    'Properties' =
                        @{n='Logon ID';e={$_.sAMAccountName}},
                        @{n='Name';e={$_.name}},
                        @{n='Pwd Age (Days)';e={$_.PasswordAge}},
                        @{n='Last Logged In';e={$_.lastlogontimestamp}},
                        @{n='No Pwd Expiry';e={$_.DONT_EXPIRE_PASSWD}},
                        @{n='Pwd Reversable';e={$_.ENCRYPTED_TEXT_PASSWORD_ALLOWED}},
                        @{n='Pwd Not Req.';e={$_.PASSWD_NOTREQD}}
                }
            }
            'PostProcessing' = $ADPrivUser_Postprocessing
        }
        'PrivGroup_ServerOperators' = @{
            'Enabled' = $true
            'ShowSectionEvenWithNoData' = $false
            'Order' = 24
            'AllData' = @{}
            'Title' = 'Server Operators'
            'Type' = 'Section'
            'Comment' = $Comment_PrivGroup_ServerOperators
            'ReportTypes' = @{
                'FullDocumentation' = @{
                    'ContainerType' = 'Full'
                    'SectionOverride' = $false
                    'TableType' = 'Horizontal'
                    'Properties' =
                        @{n='Logon ID';e={$_.sAMAccountName}},
                        @{n='Name';e={$_.name}},
                        @{n='Pwd Age (Days)';e={$_.PasswordAge}},
                        @{n='Last Logged In';e={$_.lastlogontimestamp}},
                        @{n='No Pwd Expiry';e={$_.DONT_EXPIRE_PASSWD}},
                        @{n='Pwd Reversable';e={$_.ENCRYPTED_TEXT_PASSWORD_ALLOWED}},
                        @{n='Pwd Not Req.';e={$_.PASSWD_NOTREQD}}
                }
            }
            'PostProcessing' = $ADPrivUser_Postprocessing
        }
        'PrivGroup_BackupOperators' = @{
            'Enabled' = $true
            'ShowSectionEvenWithNoData' = $false
            'Order' = 25
            'AllData' = @{}
            'Title' = 'Backup Operators'
            'Type' = 'Section'
            'Comment' = $Comment_PrivGroup_BackupOperators
            'ReportTypes' = @{
                'FullDocumentation' = @{
                    'ContainerType' = 'Full'
                    'SectionOverride' = $false
                    'TableType' = 'Horizontal'
                    'Properties' =
                        @{n='Logon ID';e={$_.sAMAccountName}},
                        @{n='Name';e={$_.name}},
                        @{n='Pwd Age (Days)';e={$_.PasswordAge}},
                        @{n='Last Logged In';e={$_.lastlogontimestamp}},
                        @{n='No Pwd Expiry';e={$_.DONT_EXPIRE_PASSWD}},
                        @{n='Pwd Reversable';e={$_.ENCRYPTED_TEXT_PASSWORD_ALLOWED}},
                        @{n='Pwd Not Req.';e={$_.PASSWD_NOTREQD}}
                }
            }
            'PostProcessing' = $ADPrivUser_Postprocessing
        }
        'PrivGroup_AccountOperators' = @{
            'Enabled' = $true
            'ShowSectionEvenWithNoData' = $false
            'Order' = 26
            'AllData' = @{}
            'Title' = 'Account Operators'
            'Type' = 'Section'
            'Comment' = $Comment_PrivGroup_AccountOperators
            'ReportTypes' = @{
                'FullDocumentation' = @{
                    'ContainerType' = 'Full'
                    'SectionOverride' = $false
                    'TableType' = 'Horizontal'
                    'Properties' =
                        @{n='Logon ID';e={$_.sAMAccountName}},
                        @{n='Name';e={$_.name}},
                        @{n='Pwd Age (Days)';e={$_.PasswordAge}},
                        @{n='Last Logged In';e={$_.lastlogontimestamp}},
                        @{n='No Pwd Expiry';e={$_.DONT_EXPIRE_PASSWD}},
                        @{n='Pwd Reversable';e={$_.ENCRYPTED_TEXT_PASSWORD_ALLOWED}},
                        @{n='Pwd Not Req.';e={$_.PASSWD_NOTREQD}}
                }
            }
            'PostProcessing' = $ADPrivUser_Postprocessing
        }
        'PrivGroup_CertPublishers' = @{
            'Enabled' = $true
            'ShowSectionEvenWithNoData' = $false
            'Order' = 27
            'AllData' = @{}
            'Title' = 'Certificate Publishers'
            'Type' = 'Section'
            'Comment' = $Comment_PrivGroup_CertPublishers
            'ReportTypes' = @{
                'FullDocumentation' = @{
                    'ContainerType' = 'Full'
                    'SectionOverride' = $false
                    'TableType' = 'Horizontal'
                    'Properties' =
                        @{n='Logon ID';e={$_.sAMAccountName}},
                        @{n='Name';e={$_.name}},
                        @{n='Pwd Age (Days)';e={$_.PasswordAge}},
                        @{n='Last Logged In';e={$_.lastlogontimestamp}},
                        @{n='No Pwd Expiry';e={$_.DONT_EXPIRE_PASSWD}},
                        @{n='Pwd Reversable';e={$_.ENCRYPTED_TEXT_PASSWORD_ALLOWED}},
                        @{n='Pwd Not Req.';e={$_.PASSWD_NOTREQD}}
                }
            }
            'PostProcessing' = $ADPrivUser_Postprocessing
        }
        'PrivGroup_PrintOperators' = @{
            'Enabled' = $true
            'ShowSectionEvenWithNoData' = $false
            'Order' = 28
            'AllData' = @{}
            'Title' = 'Print Operators'
            'Type' = 'Section'
            'Comment' = $Comment_PrivGroup_PrintOperators
            'ReportTypes' = @{
                'FullDocumentation' = @{
                    'ContainerType' = 'Full'
                    'SectionOverride' = $false
                    'TableType' = 'Horizontal'
                    'Properties' =
                        @{n='Logon ID';e={$_.sAMAccountName}},
                        @{n='Name';e={$_.name}},
                        @{n='Pwd Age (Days)';e={$_.PasswordAge}},
                        @{n='Last Logged In';e={$_.lastlogontimestamp}},
                        @{n='No Pwd Expiry';e={$_.DONT_EXPIRE_PASSWD}},
                        @{n='Pwd Reversable';e={$_.ENCRYPTED_TEXT_PASSWORD_ALLOWED}},
                        @{n='Pwd Not Req.';e={$_.PASSWD_NOTREQD}}
                }
            }
            'PostProcessing' = $ADPrivUser_Postprocessing
        }
    }
}
#endregion System Report Structure

#region HTML Template Variables
# This is the meat and potatoes of how the reports are spit out. Currently it is
# broken down by html component -> rendering style.
$HTMLRendering = @{
    # Markers: 
    #   <0> - Asset Name
    'Header' = @{
        'DynamicGrid' = @'
<!DOCTYPE html>
<!-- HTML5 Mobile Boilerplate -->
<!--[if IEMobile 7]><html class="no-js iem7"><![endif]-->
<!--[if (gt IEMobile 7)|!(IEMobile)]><!--><html class="no-js" lang="en"><!--<![endif]-->

<!-- HTML5 Boilerplate -->
<!--[if lt IE 7]><html class="no-js lt-ie9 lt-ie8 lt-ie7" lang="en"> <![endif]-->
<!--[if (IE 7)&!(IEMobile)]><html class="no-js lt-ie9 lt-ie8" lang="en"><![endif]-->
<!--[if (IE 8)&!(IEMobile)]><html class="no-js lt-ie9" lang="en"><![endif]-->
<!--[if gt IE 8]><!--> <html class="no-js" lang="en"><!--<![endif]-->

<head>

    <meta charset="utf-8">
    <!-- Always force latest IE rendering engine (even in intranet) & Chrome Frame -->
    <meta http-equiv="X-UA-Compatible" content="IE=edge,chrome=1">
    <title><0></title>
    <meta http-equiv="cleartype" content="on">
    <link rel="shortcut icon" href="/favicon.ico">

    <!-- Responsive and mobile friendly stuff -->
    <meta name="HandheldFriendly" content="True">
    <meta name="MobileOptimized" content="320">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">

    <!-- Stylesheets 
    <link rel="stylesheet" href="css/html5reset.css" media="all">
    <link rel="stylesheet" href="css/responsivegridsystem.css" media="all">
    <link rel="stylesheet" href="css/col.css" media="all">
    <link rel="stylesheet" href="css/2cols.css" media="all">
    <link rel="stylesheet" href="css/3cols.css" media="all">
    -->
    <!--<link rel="stylesheet" href="AllStyles.css" media="all">-->
        <!-- Responsive Stylesheets 
    <link rel="stylesheet" media="only screen and (max-width: 1024px) and (min-width: 769px)" href="/css/1024.css">
    <link rel="stylesheet" media="only screen and (max-width: 768px) and (min-width: 481px)" href="/css/768.css">
    <link rel="stylesheet" media="only screen and (max-width: 480px)" href="/css/480.css">
    -->
    <!-- All JavaScript at the bottom, except for Modernizr which enables HTML5 elements and feature detects -->
    <!-- <script src="js/modernizr-2.5.3-min.js"></script> -->

    <style type="text/css">
    <!--
        /* html5reset.css - 01/11/2011 */
        html, body, div, span, object, iframe,
        h1, h2, h3, h4, h5, h6, p, blockquote, pre,
        abbr, address, cite, code,
        del, dfn, em, img, ins, kbd, q, samp,
        small, strong, sub, sup, var,
        b, i,
        dl, dt, dd, ol, ul, li,
        fieldset, form, label, legend,
        table, caption, tbody, tfoot, thead, tr, th, td,
        article, aside, canvas, details, figcaption, figure, 
        footer, header, hgroup, menu, nav, section, summary,
        time, mark, audio, video {
            margin: 0;
            padding: 0;
            border: 0;
            outline: 0;
            font-size: 100%;
            vertical-align: baseline;
            background: transparent;
        }
        body {
            line-height: 1;
        }
        article,aside,details,figcaption,figure,
        footer,header,hgroup,menu,nav,section { 
            display: block;
        }
        nav ul {
            list-style: none;
        }
        blockquote, q {
            quotes: none;
        }
        blockquote:before, blockquote:after,
        q:before, q:after {
            content: '';
            content: none;
        }
        a {
            margin: 0;
            padding: 0;
            font-size: 100%;
            vertical-align: baseline;
            background: transparent;
        }
        /* change colours to suit your needs */
        ins {
            background-color: #ff9;
            color: #000;
            text-decoration: none;
        }
        /* change colours to suit your needs */
        mark {
            background-color: #ff9;
            color: #000; 
            font-style: italic;
            font-weight: bold;
        }
        del {
            text-decoration:  line-through;
        }
        abbr[title], dfn[title] {
            border-bottom: 1px dotted;
            cursor: help;
        }
        table {
            border-collapse: collapse;
            border-spacing: 0;
        }
        /* change border colour to suit your needs */
        hr {
            display: block;
            height: 1px;
            border: 0;   
            border-top: 1px solid #cccccc;
            margin: 1em 0;
            padding: 0;
        }
        input, select {
            vertical-align: middle;
        }
        /* RESPONSIVE GRID SYSTEM =============================================================================  */
        /* BASIC PAGE SETUP ============================================================================= */
        body { 
        margin : 0 auto;
        padding : 0;
        font : 100%/1.4 'lucida sans unicode', 'lucida grande', 'Trebuchet MS', verdana, arial, helvetica, helve, sans-serif;     
        color : #000; 
        text-align: center;
        background: #fff url(/images/bodyback.png) left top;
        }
        button, 
        input, 
        select, 
        textarea { 
        font-family : MuseoSlab100, lucida sans unicode, 'lucida grande', 'Trebuchet MS', verdana, arial, helvetica, helve, sans-serif; 
        color : #333; }
        /*  HEADINGS  ============================================================================= */
        h1, h2, h3, h4, h5, h6 {
        font-family:  MuseoSlab300, 'lucida sans unicode', 'lucida grande', 'Trebuchet MS', verdana, arial, helvetica, helve, sans-serif;
        font-weight : normal;
        margin-top: 0px;
        letter-spacing: -1px;
        }
        h1 { 
        font-family:  LeagueGothicRegular, 'lucida sans unicode', 'lucida grande', 'Trebuchet MS', verdana, arial, helvetica, helve, sans-serif;
        color: #000;
        margin-bottom : 0.0em;
        font-size : 4em; /* 40 / 16 */
        line-height : 1.0;
        }
        h2 { 
        color: #222;
        margin-bottom : .5em;
        margin-top : .5em;
        font-size : 2.75em; /* 40 / 16 */
        line-height : 1.2;
        }
        h3 { 
        color: #333;
        margin-bottom : 0.3em;
        letter-spacing: -1px;
        font-size : 1.75em; /* 28 / 16 */
        line-height : 1.3; }
        h4 { 
        color: #444;
        margin-bottom : 0.5em;
        font-size : 1.5em; /* 24 / 16  */
        line-height : 1.25; }
            footer h4 { 
                color: #ccc;
            }
        h5 { 
        color: #555;
        margin-bottom : 1.25em;
        font-size : 1em; /* 20 / 16 */ }
        h6 { 
        color: #666;
        font-size : 1em; /* 16 / 16  */ }
        /*  TYPOGRAPHY  ============================================================================= */
        p, ol, ul, dl, address { 
        margin-bottom : 1.5em; 
        font-size : 1em; /* 16 / 16 = 1 */ }
        p {
        hyphens : auto;  }
        p.introtext {
        font-family:  MuseoSlab100, 'lucida sans unicode', 'lucida grande', 'Trebuchet MS', verdana, arial, helvetica, helve, sans-serif;
        font-size : 2.5em; /* 40 / 16 */
        color: #333;
        line-height: 1.4em;
        letter-spacing: -1px;
        margin-bottom: 0.5em;
        }
        p.handwritten {
        font-family:  HandSean, 'lucida sans unicode', 'lucida grande', 'Trebuchet MS', verdana, arial, helvetica, helve, sans-serif; 
        font-size: 1.375em; /* 24 / 16 */
        line-height: 1.8em;
        margin-bottom: 0.3em;
        color: #666;
        }
        p.center {
        text-align: center;
        }
        .and {
        font-family: GoudyBookletter1911Regular, Georgia, Times New Roman, sans-serif;
        font-size: 1.5em; /* 24 / 16 */
        }
        .heart {
        font-family: Pictos;
        font-size: 1.5em; /* 24 / 16 */
        }
        ul, 
        ol { 
        margin : 0 0 1.5em 0; 
        padding : 0 0 0 24px; }
        li ul, 
        li ol { 
        margin : 0;
        font-size : 1em; /* 16 / 16 = 1 */ }
        dl, 
        dd { 
        margin-bottom : 1.5em; }
        dt { 
        font-weight : normal; }
        b, strong { 
        font-weight : bold; }
        hr { 
        display : block; 
        margin : 1em 0; 
        padding : 0;
        height : 1px; 
        border : 0; 
        border-top : 1px solid #ccc;
        }
        small { 
        font-size : 1em; /* 16 / 16 = 1 */ }
        sub, sup { 
        font-size : 75%; 
        line-height : 0; 
        position : relative; 
        vertical-align : baseline; }
        sup { 
        top : -.5em; }
        sub { 
        bottom : -.25em; }
        .subtext {
            color: #666;
            }
        /* LINKS =============================================================================  */
        a { 
        color : #cc1122;
        -webkit-transition: all 0.3s ease;
        -moz-transition: all 0.3s ease;
        -o-transition: all 0.3s ease;
        transition: all 0.3s ease;
        text-decoration: none;
        }
        a:visited { 
        color : #ee3344; }
        a:focus { 
        outline : thin dotted; 
        color : rgb(0,0,0); }
        a:hover, 
        a:active { 
        outline : 0;
        color : #dd2233;
        }
        footer a { 
        color : #ffffff;
        -webkit-transition: all 0.3s ease;
        -moz-transition: all 0.3s ease;
        -o-transition: all 0.3s ease;
        transition: all 0.3s ease;
        }
        footer a:visited { 
        color : #fff; }
        footer a:focus { 
        outline : thin dotted; 
        color : rgb(0,0,0); }
        footer a:hover, 
        footer a:active { 
        outline : 0;
        color : #fff;
        }
        /* IMAGES ============================================================================= */
        img {
        border : 0;
        max-width: 100%;}
        img.floatleft { float: left; margin: 0 10px 0 0; }
        img.floatright { float: right; margin: 0 0 0 10px; }
        /* TABLES ============================================================================= */
        table { 
        border-collapse : collapse;
        border-spacing : 0;
        margin-bottom : 0em; 
        width : 100%; }
        th, td, caption { 
        padding : .25em 10px .25em 5px; }
        tfoot { 
        font-style : italic; }
        caption { 
        background-color : transparent; }
        /*  MAIN LAYOUT    ============================================================================= */
        #skiptomain { display: none; }
        #wrapper {
            width: 100%;
            position: relative;
            text-align: left;
        }
            #headcontainer {
                width: 100%;
            }
                header {
                    clear: both;
                    width: 100%; /* 1000px / 1250px */
                    font-size: 0.6125em; /* 13 / 16 */
                    max-width: 92.3em; /* 1200px / 13 */
                    margin: 0 auto;
                    padding: 5px 0px 0px 0px;
                    position: relative;
                    color: #000;
                    text-align: center ;
                }
            #maincontentcontainer {
                width: 100%;
            }
                .standardcontainer {
                }
                .darkcontainer {
                    background: rgba(102, 102, 102, 0.05);
                }
                .lightcontainer {
                    background: rgba(255, 255, 255, 0.25);
                }
                    #maincontent{
                        clear: both;
                        width: 80%; /* 1000px / 1250px */
                        font-size: 0.8125em; /* 13 / 16 */
                        max-width: 92.3em; /* 1200px / 13 */
                        margin: 0 auto;
                        padding: 1em 0px;
                        color: #333;
                        line-height: 1.5em;
                        position: relative;
                    }
                    .maincontent{
                        clear: both;
                        width: 80%; /* 1000px / 1250px */
                        font-size: 0.8125em; /* 13 / 16 */
                        max-width: 92.3em; /* 1200px / 13 */
                        margin: 0 auto;
                        padding: 1em 0px;
                        color: #333;
                        line-height: 1.5em;
                        position: relative;
                    }
            #footercontainer {
                width: 100%;    
                border-top: 1px solid #000;
                background: #222 url(/images/footerback.png) left top;
            }
                footer {
                    clear: both;
                    width: 80%; /* 1000px / 1250px */
                    font-size: 0.8125em; /* 13 / 16 */
                    max-width: 92.3em; /* 1200px / 13 */
                    margin: 0 auto;
                    padding: 20px 0px 10px 0px;
                    color: #999;
                }
                footer strong {
                    font-size: 1.077em; /* 14 / 13 */
                    color: #aaa;
                }
                footer a:link, footer a:visited { color: #999; text-decoration: underline; }
                footer a:hover { color: #fff; text-decoration: underline; }
                ul.pagefooterlist, ul.pagefooterlistimages {
                    display: block;
                    float: left;
                    margin: 0px;
                    padding: 0px;
                    list-style: none;
                }
                ul.pagefooterlist li, ul.pagefooterlistimages li {
                    clear: left;
                    margin: 0px;
                    padding: 0px 0px 3px 0px;
                    display: block;
                    line-height: 1.5em;
                    font-weight: normal;
                    background: none;
                }
                ul.pagefooterlistimages li {
                    height: 34px;
                }
                ul.pagefooterlistimages li img {
                    padding: 5px 5px 5px 0px;
                    vertical-align: middle;
                    opacity: 0.75;
                    -ms-filter: "progid:DXImageTransform.Microsoft.Alpha(Opacity=75)";
                    filter: alpha( opacity  = 75);
                    -webkit-transition: all 0.3s ease;
                    -moz-transition: all 0.3s ease;
                    -o-transition: all 0.3s ease;
                    transition: all 0.3s ease;
                }
                ul.pagefooterlistimages li a
                {
                    text-decoration: none;
                }
                ul.pagefooterlistimages li a:hover img {
                    opacity: 1.0;
                    -ms-filter: "progid:DXImageTransform.Microsoft.Alpha(Opacity=100)";
                    filter: alpha( opacity  = 100);
                }
                    #smallprint {
                        margin-top: 20px;
                        line-height: 1.4em;
                        text-align: center;
                        color: #999;
                        font-size: 0.923em; /* 12 / 13 */
                    }
                    #smallprint p{
                        vertical-align: middle;
                    }
                    #smallprint .twitter-follow-button{
                        margin-left: 1em;
                        vertical-align: middle;
                    }
                    #smallprint img {
                        margin: 0px 10px 15px 0px;
                        vertical-align: middle;
                        opacity: 0.5;
                        -ms-filter: "progid:DXImageTransform.Microsoft.Alpha(Opacity=50)";
                        filter: alpha( opacity  = 50);
                        -webkit-transition: all 0.3s ease;
                        -moz-transition: all 0.3s ease;
                        -o-transition: all 0.3s ease;
                        transition: all 0.3s ease;
                    }
                    #smallprint a:hover img {
                        opacity: 1.0;
                        -ms-filter: "progid:DXImageTransform.Microsoft.Alpha(Opacity=100)";
                        filter: alpha( opacity  = 100);
                    }
                    #smallprint a:link, #smallprint a:visited { color: #999; text-decoration: none; }
                    #smallprint a:hover { color: #999; text-decoration: underline; }
        /*  SECTIONS  ============================================================================= */
        .section {
            clear: both;
            padding: 0px;
            margin: 0px;
        }
        /*  CODE  ============================================================================= */
        pre.code {
            padding: 0;
            margin: 0;
            font-family: monospace;
            white-space: pre-wrap;
            font-size: 1.1em;
        }
        strong.code {
            font-weight: normal;
            font-family: monospace;
            font-size: 1.2em;
        }
        /*  EXAMPLE  ============================================================================= */
        #example .col {
            background: #ccc;
            background: rgba(204, 204, 204, 0.85);
        }
        /*  NOTES  ============================================================================= */
        .note {
            position:relative;
            padding:1em 1.5em;
            margin: 0 0 1em 0;
            background: #fff;
            background: rgba(255, 255, 255, 0.5);
            overflow:hidden;
        }
        .note:before {
            content:"";
            position:absolute;
            top:0;
            right:0;
            border-width:0 16px 16px 0;
            border-style:solid;
            border-color:transparent transparent #cccccc #cccccc;
            background:#cccccc;
            -webkit-box-shadow:0 1px 1px rgba(0,0,0,0.3), -1px 1px 1px rgba(0,0,0,0.2);
            -moz-box-shadow:0 1px 1px rgba(0,0,0,0.3), -1px 1px 1px rgba(0,0,0,0.2);
            box-shadow:0 1px 1px rgba(0,0,0,0.3), -1px 1px 1px rgba(0,0,0,0.2);
            display:block; width:0; /* Firefox 3.0 damage limitation */
        }
        .note.rounded {
            -webkit-border-radius:5px 0 5px 5px;
            -moz-border-radius:5px 0 5px 5px;
            border-radius:5px 0 5px 5px;
        }
        .note.rounded:before {
            border-width:8px;
            border-color:#ff #ff transparent transparent;
            background: url(/images/bodyback.png);
            -webkit-border-bottom-left-radius:5px;
            -moz-border-radius:0 0 0 5px;
            border-radius:0 0 0 5px;
        }
        /*  SCREENS  ============================================================================= */
        .siteimage {
            max-width: 90%;
            padding: 5%;
            margin: 0 0 1em 0;
            background: transparent url(/images/stripe-bg.png);
            -webkit-transition: background 0.3s ease;
            -moz-transition: background 0.3s ease;
            -o-transition: background 0.3s ease;
            transition: background 0.3s ease;
        }
        .siteimage:hover {
            background: #bbb url(/images/stripe-bg.png);
            position: relative;
            top: -2px;
            
        }
        /*  COLUMNS  ============================================================================= */
        .twocolumns{
            -moz-column-count: 2;
            -moz-column-gap: 2em;
            -webkit-column-count: 2;
            -webkit-column-gap: 2em;
            column-count: 2;
            column-gap: 2em;
          }
        /*  GLOBAL OBJECTS ============================================================================= */
        .breaker { clear: both; }
        .group:before,
        .group:after {
            content:"";
            display:table;
        }
        .group:after {
            clear:both;
        }
        .group {
            zoom:1; /* For IE 6/7 (trigger hasLayout) */
        }
        .floatleft {
            float: left;
        }
        .floatright {
            float: right;
        }
        /* VENDOR-SPECIFIC ============================================================================= */
        html { 
        -webkit-overflow-scrolling : touch; 
        -webkit-tap-highlight-color : rgb(52,158,219); 
        -webkit-text-size-adjust : 100%; 
        -ms-text-size-adjust : 100%; }
        .clearfix { 
        zoom : 1; }
        ::-webkit-selection { 
        background : rgb(23,119,175); 
        color : rgb(250,250,250); 
        text-shadow : none; }
        ::-moz-selection { 
        background : rgb(23,119,175); 
        color : rgb(250,250,250); 
        text-shadow : none; }
        ::selection { 
        background : rgb(23,119,175); 
        color : rgb(250,250,250); 
        text-shadow : none; }
        button, 
        input[type="button"], 
        input[type="reset"], 
        input[type="submit"] { 
        -webkit-appearance : button; }
        ::-webkit-input-placeholder {
        font-size : .875em; 
        line-height : 1.4; }
        input:-moz-placeholder { 
        font-size : .875em; 
        line-height : 1.4; }
        .ie7 img,
        .iem7 img { 
        -ms-interpolation-mode : bicubic; }
        input[type="checkbox"], 
        input[type="radio"] { 
        box-sizing : border-box; }
        input[type="search"] { 
        -webkit-box-sizing : content-box;
        -moz-box-sizing : content-box; }
        button::-moz-focus-inner, 
        input::-moz-focus-inner { 
        padding : 0;
        border : 0; }
        p {
        /* http://www.w3.org/TR/css3-text/#hyphenation */
        -webkit-hyphens : auto;
        -webkit-hyphenate-character : "\2010";
        -webkit-hyphenate-limit-after : 1;
        -webkit-hyphenate-limit-before : 3;
        -moz-hyphens : auto; }
        /*  SECTIONS  ============================================================================= */
        .section {
            clear: both;
            padding: 0px;
            margin: 0px;
        }
        /*  GROUPING  ============================================================================= */
        .group:before,
        .group:after {
            content:"";
            display:table;
        }
        .group:after {
            clear:both;
        }
        .group {
            zoom:1; /* For IE 6/7 (trigger hasLayout) */
        }
        /*  GRID COLUMN SETUP   ==================================================================== */
        .col {
            display: block;
            float:left;
            margin: 1% 0 1% 1.6%;
        }
        .col:first-child { margin-left: 0; } /* all browsers except IE6 and lower */
        /*  REMOVE MARGINS AS ALL GO FULL WIDTH AT 480 PIXELS */
        @media only screen and (max-width: 480px) {
            .col { 
                margin: 1% 0 1% 0%;
            }
        }
        /*  GRID OF TWO   ============================================================================= */
        .span_2_of_2 {
            width: 100%;
        }
        .span_1_of_2 {
            width: 49.2%;
        }
        /*  GO FULL WIDTH AT LESS THAN 480 PIXELS */
        @media only screen and (max-width: 480px) {
            .span_2_of_2 {
                width: 100%; 
            }
            .span_1_of_2 {
                width: 100%; 
            }
        }
        /*  GRID OF THREE   ============================================================================= */
        .span_3_of_3 {
            width: 100%; 
        }
        .span_2_of_3 {
            width: 66.1%; 
        }
        .span_1_of_3 {
            width: 32.2%; 
        }
        /*  GO FULL WIDTH AT LESS THAN 480 PIXELS */
        @media only screen and (max-width: 480px) {
            .span_3_of_3 {
                width: 100%; 
            }
            .span_2_of_3 {
                width: 100%; 
            }
            .span_1_of_3 {
                width: 100%;
            }
        }
        /*  GRID OF FOUR   ============================================================================= */
        .span_4_of_4 {
            width: 100%; 
        }
        .span_3_of_4 {
            width: 74.6%; 
        }
        .span_2_of_4 {
            width: 49.2%; 
        }
        .span_1_of_4 {
            width: 23.8%; 
        }
        /*  GO FULL WIDTH AT LESS THAN 480 PIXELS */
        @media only screen and (max-width: 480px) {
            .span_4_of_4 {
                width: 100%; 
            }
            .span_3_of_4 {
                width: 100%; 
            }
            .span_2_of_4 {
                width: 100%; 
            }
            .span_1_of_4 {
                width: 100%; 
            }
        }
        
        body {
            font-family: Verdana, Geneva, Arial, Helvetica, sans-serif;
        }
        
        table{
            border-collapse: collapse;
            border: none;
            font: 10pt Verdana, Geneva, Arial, Helvetica, sans-serif;
            color: black;
            margin-bottom: 0px;
        }
        table td{
            font-size: 10px;
            padding-left: 0px;
            padding-right: 20px;
            text-align: left;
        }
        table td:last-child{
            padding-right: 5px;
        }
        table th {
            font-size: 12px;
            font-weight: bold;
            padding-left: 0px;
            padding-right: 20px;
            text-align: left;
            border-bottom: 1px  grey solid;
        }
        h2{ 
            clear: both;
            font-size: 200%; 
            margin-left: 20px;
            font-weight: bold;
        }
        h3{
            clear: both;
            font-size: 115%;
            margin-left: 20px;
            margin-top: 30px;
        }
        p{ 
            margin-left: 20px; font-size: 12px;
        }
        table.list{
            float: left;
        }
        table.list td:nth-child(1){
            font-weight: bold;
            border-right: 1px grey solid;
            text-align: right;
        }
        table.list td:nth-child(2){
            padding-left: 7px;
        }
        table tr:nth-child(even) td:nth-child(even){ background: #CCCCCC; }
        table tr:nth-child(odd) td:nth-child(odd){ background: #F2F2F2; }
        table tr:nth-child(even) td:nth-child(odd){ background: #DDDDDD; }
        table tr:nth-child(odd) td:nth-child(even){ background: #E5E5E5; }
        
        /*  Error and warning highlighting - Row*/
        table tr.warn:nth-child(even) td:nth-child(even){ background: #FFFF88; }
        table tr.warn:nth-child(odd) td:nth-child(odd){ background: #FFFFBB; }
        table tr.warn:nth-child(even) td:nth-child(odd){ background: #FFFFAA; }
        table tr.warn:nth-child(odd) td:nth-child(even){ background: #FFFF99; }
        
        table tr.alert:nth-child(even) td:nth-child(even){ background: #FF8888; }
        table tr.alert:nth-child(odd) td:nth-child(odd){ background: #FFBBBB; }
        table tr.alert:nth-child(even) td:nth-child(odd){ background: #FFAAAA; }
        table tr.alert:nth-child(odd) td:nth-child(even){ background: #FF9999; }
        
        table tr.healthy:nth-child(even) td:nth-child(even){ background: #88FF88; }
        table tr.healthy:nth-child(odd) td:nth-child(odd){ background: #BBFFBB; }
        table tr.healthy:nth-child(even) td:nth-child(odd){ background: #AAFFAA; }
        table tr.healthy:nth-child(odd) td:nth-child(even){ background: #99FF99; }
        
        /*  Error and warning highlighting - Cell*/
        table tr:nth-child(even) td.warn:nth-child(even){ background: #FFFF88; }
        table tr:nth-child(odd) td.warn:nth-child(odd){ background: #FFFFBB; }
        table tr:nth-child(even) td.warn:nth-child(odd){ background: #FFFFAA; }
        table tr:nth-child(odd) td.warn:nth-child(even){ background: #FFFF99; }
        
        table tr:nth-child(even) td.alert:nth-child(even){ background: #FF8888; }
        table tr:nth-child(odd) td.alert:nth-child(odd){ background: #FFBBBB; }
        table tr:nth-child(even) td.alert:nth-child(odd){ background: #FFAAAA; }
        table tr:nth-child(odd) td.alert:nth-child(even){ background: #FF9999; }
        
        table tr:nth-child(even) td.healthy:nth-child(even){ background: #88FF88; }
        table tr:nth-child(odd) td.healthy:nth-child(odd){ background: #BBFFBB; }
        table tr:nth-child(even) td.healthy:nth-child(odd){ background: #AAFFAA; }
        table tr:nth-child(odd) td.healthy:nth-child(even){ background: #99FF99; }
        
        /* security highlighting */
        table tr.security:nth-child(even) td:nth-child(even){ 
            border-color: #FF1111; 
            border: 1px #FF1111 solid;
        }
        table tr.security:nth-child(odd) td:nth-child(odd){ 
            border-color: #FF1111; 
            border: 1px #FF1111 solid;
        }
        table tr.security:nth-child(even) td:nth-child(odd){
            border-color: #FF1111; 
            border: 1px #FF1111 solid;
        }
        table tr.security:nth-child(odd) td:nth-child(even){
            border-color: #FF1111; 
            border: 1px #FF1111 solid;
        }
        table th.title{ 
            text-align: center;
            background: #848482;
            border-bottom: 1px  black solid;
            font-weight: bold;
            color: white;
        }
        table th.sectioncomment{ 
            text-align: left;
            background: #848482;
            font-style : italic;
            color: white;
            font-weight: normal;
            
            padding: 0px;
        }
        table th.sectioncolumngrouping{ 
            text-align: center;
            background: #AAAAAA;
            color: black;
            font-weight: bold;
            border:1px solid white;
        }
        table th.sectionbreak{ 
            text-align: center;
            background: #848482;
            border: 2px black solid;
            font-weight: bold;
            color: white;
            font-size: 130%;
        }
        table th.reporttitle{ 
            text-align: center;
            background: #848482;
            border: 2px black solid;
            font-weight: bold;
            color: white;
            font-size: 150%;
        }
        table tr.divide{
            border-bottom: 1px  grey solid;
        }
    -->
    </style></head>

<body>
<div id="wrapper">
'@
        'EmailFriendly' = @'
<!DOCTYPE HTML PUBLIC '-//W3C//DTD HTML 4.01 Frameset//EN' 'http://www.w3.org/TR/html4/frameset.dtd'>
<html><head><title><0></title>
<style type='text/css'>
<!--
body {
    font-family: Verdana, Geneva, Arial, Helvetica, sans-serif;
}
table{
   border-collapse: collapse;
   border: none;
   font: 10pt Verdana, Geneva, Arial, Helvetica, sans-serif;
   color: black;
   margin-bottom: 10px;
   margin-left: 20px;
}
table td{
   font-size: 12px;
   padding-left: 0px;
   padding-right: 20px;
   text-align: left;
   border:1px solid black;
}
table th {
   font-size: 12px;
   font-weight: bold;
   padding-left: 0px;
   padding-right: 20px;
   text-align: left;
}

h1{ clear: both;
    font-size: 150%; 
    text-align: center;
  }
h2{ clear: both; font-size: 130%; }

h3{
   clear: both;
   font-size: 115%;
   margin-left: 20px;
   margin-top: 30px;
}

p{ margin-left: 20px; font-size: 12px; }

table.list{ float: left; }
   table.list td:nth-child(1){
   font-weight: bold;
   border: 1px grey solid;
   text-align: right;
}

table th.title{ 
    text-align: center;
    background: #848482;
    border: 2px  grey solid;
    font-weight: bold;
    color: white;
}
table tr.divide{
    border-bottom: 5px  grey solid;
}
.odd { background-color:#ffffff; }
.even { background-color:#dddddd; }
.warn { background-color:yellow; }
.alert { background-color:red; }
-->
</style>
</head>
<body>
'@
    }
    'Footer' = @{
        'DynamicGrid' = @'
</div>
</body>
</html>        
'@
        'EmailFriendly' = @'
</div>
</body>
</html>       
'@
    }

    # Markers: 
    #   <0> - Server Name
    'ServerBegin' = @{
        'DynamicGrid' = @'
    
    <hr noshade size="3" width='100%'>
    <div id="headcontainer">
        <table>        
            <tr>
                <th class="reporttitle"><0></th>
            </tr>
        </table>
    </div>
    <div id="maincontentcontainer">
        <div id="maincontent">
            <div class="section group">
                <hr noshade size="3" width='100%'>
            </div>
            <div>

       
'@
        'EmailFriendly' = @'
    <div id='report'>
    <hr noshade size=3 width='100%'>
    <h1><0></h1>

    <div id="maincontentcontainer">
    <div id="maincontent">
      <div class="section group">
        <hr noshade="noshade" size="3" width="100%" style=
        "display:block;height:1px;border:0;border-top:1px solid #ccc;margin:1em 0;padding:0;" />
      </div>
      <div>

'@    
    }
    'ServerEnd' = @{
        'DynamicGrid' = @'

            </div>
        </div>
    </div>
</div>

'@
        'EmailFriendly' = @'

            </div>
        </div>
    </div>
</div>

'@
    }
    
    # Markers: 
    #   <0> - columns to span title
    #   <1> - Table header title
    'TableTitle' = @{
        'DynamicGrid' = @'
        
            <tr>
                <th class="title" colspan=<0>><1></th>
            </tr>
'@
        'EmailFriendly' = @'
            
            <tr>
              <th class="title" colspan="<0>"><1></th>
            </tr>
              
'@
    }
    
    'TableComment' = @{
        'DynamicGrid' = @'
        
            <tr>
                <th class="sectioncomment" colspan=<0>><1></th>
            </tr>
'@
        'EmailFriendly' = @'
            
            <tr>
              <th class="sectioncomment" colspan="<0>"><1></th>
            </tr>
              
'@
    }    

    'SectionContainers' = @{
        'DynamicGrid'  = @{
            'Half' = @{
                'Head' = @'
        
        <div class="col span_2_of_4">
'@
                'Tail' = @'
        </div>
'@
            }
            'Full' = @{
                'Head' = @'
        
        <div class="col span_4_of_4">
'@
                'Tail' = @'
        </div>
'@
            }
            'Third' = @{
                'Head' = @'
        
        <div class="col span_1_of_3">
'@
                'Tail' = @'
        </div>
'@
            }
            'TwoThirds' = @{
                'Head' = @'
        
        <div class="col span_2_of_3">
'@
                'Tail' = @'
                
        </div>
'@
            }
            'Fourth'        = @{
                'Head' = @'
        
        <div class="col span_1_of_4">
'@
                'Tail' = @'
                
        </div>
'@
            }
            'ThreeFourths'  = @{
                'Head' = @'
               
        <div class="col span_3_of_4">
'@
                'Tail'          = @'
        
        </div>
'@
            }
        }
        'EmailFriendly'  = @{
            'Half' = @{
                'Head' = @'
        
        <div class="col span_2_of_4">
        <table><tr WIDTH="50%">
'@
                'Tail' = @'
        </tr></table>       
        </div>
'@
            }
            'Full' = @{
                'Head' = @'
        
        <div class="col span_4_of_4">
'@
                'Tail' = @'
                
        </div>
'@
            }
            'Third' = @{
                'Head' = @'
        
        <div class="col span_1_of_3">
'@
                'Tail' = @'
                
        </div>
'@
            }
            'TwoThirds' = @{
                'Head' = @'
        
        <div class="col span_2_of_3">
'@
                'Tail' = @'
                
        </div>
'@
            }
            'Fourth'        = @{
                'Head' = @'
        
        <div class="col span_1_of_4">
'@
                'Tail' = @'
                
        </div>
'@
            }
            'ThreeFourths'  = @{
                'Head' = @'
               
        <div class="col span_3_of_4">
'@
                'Tail'          = @'
        
        </div>
'@
            }
        }
    }
    
    'SectionContainerGroup' = @{
        'DynamicGrid' = @{ 
            'Head' = @'
        
        <div class="section group">
'@
            'Tail' = @'
        </div>
'@
        }
        'EmailFriendly' = @{
            'Head' = @'
    
        <div class="section group">
'@
            'Tail' = @'
        </div>
'@
        }
    }
    
    'CustomSections' = @{
        # Markers: 
        #   <0> - Header
        'SectionBreak' = @'
    
    <div class="section group">        
        <div class="col span_4_of_4"><table>        
            <tr>
                <th class="sectionbreak"><0></th>
            </tr>
        </table>
        </div>
    </div>
'@
    }
}
#endregion HTML Template Variables
#endregion Globals

#region Functions - Serial or Utility
Function ConvertTo-PropertyValue 
{
    <#
    .SYNOPSIS
    Convert an object with various properties into an array of property, value pairs 
    
    .DESCRIPTION
    Convert an object with various properties into an array of property, value pairs

    If you output reports or other formats where a table with one long row is poorly formatted, this is a quick way to create a table of property value pairs.

    There are other ways you could do this.  For example, I could list all noteproperties from Get-Member results and return them.
    This function will keep properties in the same order they are provided, which can often be helpful for readability of results.

    .PARAMETER inputObject
    A single object to convert to an array of property value pairs.

    .PARAMETER leftheader
    Header for the left column.  Default:  Property

    .PARAMETER rightHeader
    Header for the right column.  Default:  Value

    .PARAMETER memberType
    Return only object members of this membertype.  Default:  Property, NoteProperty, ScriptProperty

    .EXAMPLE
    get-process powershell_ise | convertto-propertyvalue

    I want details on the powershell_ise process.
        With this command, if I output this to a table, a csv, etc. I will get a nice vertical listing of properties and their values
        Without this command, I get a long row with the same info

    .EXAMPLE
    #This example requires and demonstrates using the New-HTMLHead, New-HTMLTable, Add-HTMLTableColor, ConvertTo-PropertyValue and Close-HTML functions.
    
    #get processes to work with
        $processes = Get-Process
    
    #Build HTML header
        $HTML = New-HTMLHead -title "Process details"

    #Add CPU time section with top 10 PrivateMemorySize processes.  This example does not highlight any particular cells
        $HTML += "<h3>Process Private Memory Size</h3>"
        $HTML += New-HTMLTable -inputObject $($processes | sort PrivateMemorySize -Descending | select name, PrivateMemorySize -first 10)

    #Add Handles section with top 10 Handle usage.
    $handleHTML = New-HTMLTable -inputObject $($processes | sort handles -descending | select Name, Handles -first 10)

        #Add highlighted colors for Handle count
            
            #build hash table with parameters for Add-HTMLTableColor.  Argument and AttrValue will be modified each time we run this.
            $params = @{
                Column = "Handles" #I'm looking for cells in the Handles column
                ScriptBlock = {[double]$args[0] -gt [double]$args[1]} #I want to highlight if the cell (args 0) is greater than the argument parameter (arg 1)
                Attr = "Style" #This is the default, don't need to actually specify it here
            }

            #Add yellow, orange and red shading
            $handleHTML = Add-HTMLTableColor -HTML $handleHTML -Argument 1500 -attrValue "background-color:#FFFF99;" @params
            $handleHTML = Add-HTMLTableColor -HTML $handleHTML -Argument 2000 -attrValue "background-color:#FFCC66;" @params
            $handleHTML = Add-HTMLTableColor -HTML $handleHTML -Argument 3000 -attrValue "background-color:#FFCC99;" @params
      
        #Add title and table
        $HTML += "<h3>Process Handles</h3>"
        $HTML += $handleHTML

    #Add process list containing first 10 processes listed by get-process.  This example does not highlight any particular cells
        $HTML += New-HTMLTable -inputObject $($processes | select name -first 10 ) -listTableHead "Random Process Names"

    #Add property value table showing details for PowerShell ISE
        $HTML += "<h3>PowerShell Process Details PropertyValue table</h3>"
        $processDetails = Get-process powershell_ise | select name, id, cpu, handles, workingset, PrivateMemorySize, Path -first 1
        $HTML += New-HTMLTable -inputObject $(ConvertTo-PropertyValue -inputObject $processDetails)

    #Add same PowerShell ISE details but not in property value form.  Close the HTML
        $HTML += "<h3>PowerShell Process Details object</h3>"
        $HTML += New-HTMLTable -inputObject $processDetails | Close-HTML

    #write the HTML to a file and open it up for viewing
        set-content C:\test.htm $HTML
        & 'C:\Program Files\Internet Explorer\iexplore.exe' C:\test.htm

    .FUNCTIONALITY
    General Command
    #> 
    [cmdletbinding()]
    param(
        [Parameter(Mandatory=$true,
            ValueFromPipeline=$true)]
        [PSObject]$InputObject,
        
        [validateset("AliasProperty", "CodeProperty", "Property", "NoteProperty", "ScriptProperty",
            "Properties", "PropertySet", "Method", "CodeMethod", "ScriptMethod", "Methods",
            "ParameterizedProperty", "MemberSet", "Event", "Dynamic", "All")]
        [string[]]$memberType = @( "NoteProperty", "Property", "ScriptProperty" ),
            
        [string]$leftHeader = "Property",
            
        [string]$rightHeader = "Value"
    )

    begin{
        #init array to dump all objects into
        $allObjects = @()

    }
    process{
        #if we're taking from pipeline and get more than one object, this will build up an array
        $allObjects += $inputObject
    }

    end{
        #use only the first object provided
        $allObjects = $allObjects[0]

        #Get properties.  Filter by memberType.
        $properties = $allObjects.psobject.properties | ?{$memberType -contains $_.memberType} | select -ExpandProperty Name

        #loop through properties and display property value pairs
        foreach($property in $properties){

            #Create object with property and value
            $temp = "" | select $leftHeader, $rightHeader
            $temp.$leftHeader = $property.replace('"',"")
            $temp.$rightHeader = try { $allObjects | select -ExpandProperty $temp.$leftHeader -erroraction SilentlyContinue } catch { $null }
            $temp
        }
    }
}

Function ConvertTo-HashArray
{
    <#
    .SYNOPSIS
    Convert an array of objects to a hash table based on a single property of the array. 
    
    .DESCRIPTION
    Convert an array of objects to a hash table based on a single property of the array.
    
    .PARAMETER InputObject
    An array of objects to convert to a hash table array.

    .PARAMETER PivotProperty
    The property to use as the key value in the resulting hash.
    
    .PARAMETER LookupValue
    Property in the psobject to be the value that the hash key points to in the returned result. If not specified, all properties in the psobject are used.

    .EXAMPLE
    $DellServerHealth = @(Get-DellServerhealth @_dellhardwaresplat)
    $DellServerHealth = ConvertTo-HashArray $DellServerHealth 'PSComputerName'

    Description
    -----------
    Calls a function which returns a psobject then converts that result to a hash array based on the PSComputerName
    
    .NOTES
    Author:
    Zachary Loeber
    
    Version Info:
    1.1 - 11/17/2013
        - Added LookupValue Parameter to allow for creation of one to one hashs
        - Added more error validation
        - Dolled up the paramerters
        
    .LINK 
    http://www.the-little-things.net 
    #> 
    [cmdletbinding()]
    param(
        [Parameter(Mandatory=$true,
                   ValueFromPipeline=$true,
                   HelpMessage='A single or array of PSObjects',
                   Position=0)]
        [AllowEmptyCollection()]
        [PSObject[]]
        $InputObject,
        
        [Parameter(Mandatory=$true,
                   HelpMessage='Property in the psobject to be the future key in a returned hash.',
                   Position=1)]
        [string]$PivotProperty,
        
        [Parameter(HelpMessage='Property in the psobject to be the value that the hash key points to. If not specified, all properties in the psobject are used.',
                   Position=2)]
        [string]$LookupValue = ''
    )

    BEGIN
    {
        #init array to dump all objects into
        $allObjects = @()
        $Results = @{}
    }
    PROCESS
    {
        #if we're taking from pipeline and get more than one object, this will build up an array
        $allObjects += $inputObject
    }

    END
    {
        ForEach ($object in $allObjects)
        {
            if ($object -ne $null)
            {
                try
                {
                    if ($object.PSObject.Properties.Match($PivotProperty).Count) 
                    {
                        if ($LookupValue -eq '')
                        {
                            $Results[$object.$PivotProperty] = $object
                        }
                        else
                        {
                            if ($object.PSObject.Properties.Match($LookupValue).Count)
                            {
                                $Results[$object.$PivotProperty] = $object.$LookupValue
                            }
                            else
                            {
                                Write-Warning -Message ('ConvertTo-HashArray: LookupValue Not Found - {0}' -f $_.Exception.Message)
                            }
                        }
                    }
                    else
                    {
                        Write-Warning -Message ('ConvertTo-HashArray: LookupValue Not Found - {0}' -f $_.Exception.Message)
                    }
                }
                catch
                {
                    Write-Warning -Message ('ConvertTo-HashArray: Something weird happened! - {0}' -f $_.Exception.Message)
                }
            }
        }
        $Results
    }
}

Function ConvertTo-PSObject
{
    <# 
     Take an array of like psobject and convert it to a singular psobject based on two shared
     properties across all psobjects in the array.
     Example Input object: 
    $obj = @()
    $a = @{ 
        'PropName' = 'Property 1'
        'Val1' = 'Value 1'
        }
    $b = @{ 
        'PropName' = 'Property 2'
        'Val1' = 'Value 2'
        }
    $obj += new-object psobject -property $a
    $obj += new-object psobject -property $b

    $c = $obj | ConvertTo-PSObject -propname 'PropName' -valname 'Val1'
    $c.'Property 1'
    Value 1
    #>
    [cmdletbinding()]
    PARAM(
        [Parameter(Mandatory=$true,
            ValueFromPipeline=$true)]
        [PSObject[]]$InputObject,
        [string]$propname,
        [string]$valname
    )

    BEGIN
    {
        #init array to dump all objects into
        $allObjects = @()
    }
    PROCESS
    {
        #if we're taking from pipeline and get more than one object, this will build up an array
        $allObjects += $inputObject
    }
    END
    {
        $returnobject = New-Object psobject
        foreach ($obj in $allObjects)
        {
            if ($obj.$propname -ne $null)
            {
                $returnobject | Add-Member -MemberType NoteProperty -Name $obj.$propname -Value $obj.$valname
            }
        }
        $returnobject
    }
}

Function ConvertTo-MultiArray 
{
 <#
 .Notes
 NAME: ConvertTo-MultiArray
 AUTHOR: Tome Tanasovski
 Website: http://powertoe.wordpress.com
 Twitter: http://twitter.com/toenuff
 Version: 1.0
 CREATED: 11/5/2010
 LASTEDIT:
 11/5/2010 1.0
 Initial Release
 11/5/2010 1.1
 Removed array parameter and passes a reference to the multi-dimensional array as output to the cmdlet
 11/5/2010 1.2
 Modified all rows to ensure they are entered as string values including $null values as a blank ("") string.

 .Synopsis
 Converts a collection of PowerShell objects into a multi-dimensional array

 .Description
 Converts a collection of PowerShell objects into a multi-dimensional array.  The first row of the array contains the property names.  Each additional row contains the values for each object.

 This cmdlet was created to act as an intermediary to importing PowerShell objects into a range of cells in Exchange.  By using a multi-dimensional array you can greatly speed up the process of adding data to Excel through the Excel COM objects.

 .Parameter InputObject
 Specifies the objects to export into the multi dimensional array.  Enter a variable that contains the objects or type a command or expression that gets the objects. You can also pipe objects to ConvertTo-MultiArray.

 .Inputs
 System.Management.Automation.PSObject
        You can pipe any .NET Framework object to ConvertTo-MultiArray

 .Outputs
 [ref]
        The cmdlet will return a reference to the multi-dimensional array.  To access the array itself you will need to use the Value property of the reference

 .Example
 $arrayref = get-process |Convertto-MultiArray

 .Example
 $dir = Get-ChildItem c:\
 $arrayref = Convertto-MultiArray -InputObject $dir

 .Example
 $range.value2 = (ConvertTo-MultiArray (get-process)).value

 .LINK

http://powertoe.wordpress.com

#>
    param(
        [Parameter(Mandatory=$true, Position=1, ValueFromPipeline=$true)]
        [PSObject[]]$InputObject
    )
    BEGIN {
        $objects = @()
        [ref]$array = [ref]$null
    }
    Process {
        $objects += $InputObject
    }
    END {
        $properties = $objects[0].psobject.properties |%{$_.name}
        $array.Value = New-Object 'object[,]' ($objects.Count+1),$properties.count
        # i = row and j = column
        $j = 0
        $properties |%{
            $array.Value[0,$j] = $_.tostring()
            $j++
        }
        $i = 1
        $objects |% {
            $item = $_
            $j = 0
            $properties | % {
                if ($item.($_) -eq $null) {
                    $array.value[$i,$j] = ""
                }
                else {
                    $array.value[$i,$j] = $item.($_).tostring()
                }
                $j++
            }
            $i++
        }
        $array
    }
}

Function Format-HTMLTable 
{
    <# 
    .SYNOPSIS 
        Format-HTMLTable - Selectively color elements of of an html table based on column value or even/odd rows.
     
    .DESCRIPTION 
        Create an html table and colorize individual cells or rows of an array of objects 
        based on row header and value. Optionally, you can also modify an existing html 
        document or change only the styles of even or odd rows.
     
    .PARAMETER InputObject 
        An array of objects (ie. (Get-process | select Name,Company) 
     
    .PARAMETER  Column 
        The column you want to modify. (Note: If the parameter ColorizeMethod is not set to ByValue the 
        Column parameter is ignored)

    .PARAMETER ScriptBlock
        Used to perform custom cell evaluations such as -gt -lt or anything else you need to check for in a
        table cell element. The scriptblock must return either $true or $false and is, by default, just
        a basic -eq comparisson. You must use the variables as they are used in the following example.
        (Note: If the parameter ColorizeMethod is not set to ByValue the ScriptBlock parameter is ignored)

        [scriptblock]$scriptblock = {[int]$args[0] -gt [int]$args[1]}

        $args[0] will be the cell value in the table
        $args[1] will be the value to compare it to

        Strong typesetting is encouraged for accuracy.

    .PARAMETER  ColumnValue 
        The column value you will modify if ScriptBlock returns a true result. (Note: If the parameter 
        ColorizeMethod is not set to ByValue the ColumnValue parameter is ignored).
     
    .PARAMETER  Attr 
        The attribute to change should ColumnValue be found in the Column specified. 
        - A good example is using "style" 

    .PARAMETER  AttrValue 
        The attribute value to set when the ColumnValue is found in the Column specified 
        - A good example is using "background: red;" 
    
    .PARAMETER DontUseLinq
        Use inline C# Linq calls for html table manipulation by default. This is extremely fast but requires .NET 3.5 or above.
        Use this switch to force using non-Linq method (xml) first.
        
    .PARAMETER Fragment
        Return only the HTML table instead of a full document.
    
    .EXAMPLE 
        This will highlight the process name of Dropbox with a red background. 

        $TableStyle = @'
        <title>Process Report</title> 
            <style>             
            BODY{font-family: Arial; font-size: 8pt;} 
            H1{font-size: 16px;} 
            H2{font-size: 14px;} 
            H3{font-size: 12px;} 
            TABLE{border: 1px solid black; border-collapse: collapse; font-size: 8pt;} 
            TH{border: 1px solid black; background: #dddddd; padding: 5px; color: #000000;} 
            TD{border: 1px solid black; padding: 5px;} 
            </style>
        '@

        $tabletocolorize = Get-Process | Select Name,CPU,Handles | ConvertTo-Html -Head $TableStyle
        $colorizedtable = Format-HTMLTable $tabletocolorize -Column "Name" -ColumnValue "Dropbox" -Attr "style" -AttrValue "background: red;" -HTMLHead $TableStyle
        $colorizedtable = Format-HTMLTable $colorizedtable -Attr "style" -AttrValue "background: grey;" -ColorizeMethod 'ByOddRows' -WholeRow:$true
        $colorizedtable = Format-HTMLTable $colorizedtable -Attr "style" -AttrValue "background: yellow;" -ColorizeMethod 'ByEvenRows' -WholeRow:$true
        $colorizedtable | Out-File "$pwd/testreport.html" 
        ii "$pwd/testreport.html"

    .EXAMPLE 
        Using the same $TableStyle variable above this will create a table of top 5 processes by memory usage,
        color the background of a whole row yellow for any process using over 150Mb and red if over 400Mb.

        $tabletocolorize = $(get-process | select -Property ProcessName,Company,@{Name="Memory";Expression={[math]::truncate($_.WS/ 1Mb)}} | Sort-Object Memory -Descending | Select -First 5 ) 

        [scriptblock]$scriptblock = {[int]$args[0] -gt [int]$args[1]}
        $testreport = Format-HTMLTable $tabletocolorize -Column "Memory" -ColumnValue 150 -Attr "style" -AttrValue "background:yellow;" -ScriptBlock $ScriptBlock -HTMLHead $TableStyle -WholeRow $true
        $testreport = Format-HTMLTable $testreport -Column "Memory" -ColumnValue 400 -Attr "style" -AttrValue "background:red;" -ScriptBlock $ScriptBlock -WholeRow $true
        $testreport | Out-File "$pwd/testreport.html" 
        ii "$pwd/testreport.html"

    .NOTES 
        If you are going to convert something to html with convertto-html in powershell v2 there is 
        a bug where the header will show up as an asterick if you only are converting one object property. 

        This script is a modification of something I found by some rockstar named Jaykul at this site
        http://stackoverflow.com/questions/4559233/technique-for-selectively-formatting-data-in-a-powershell-pipeline-and-output-as

        .Net 3.5 or above is a requirement for using the Linq libraries.

    Version Info:
    1.2 - 01/12/2014
        - Changed bool parameters to switch
        - Added DontUseLinq parameter
        - Changed function name to be less goofy sounding
        - Updated the add-type custom namespace from Huddled to CustomLinq
        - Added help messages to fuction parameters.
        - Added xml method for function to use if the linq assemblies couldn't be loaded (slower but still works)
    1.1 - 11/13/2013
        - Removed the explicit definition of Csharp3 in the add-type definition to allow windows 2012 compatibility.
        - Fixed up parameters to remove assumed values
        - Added try/catch around add-type to detect and prevent errors when processing on systems which do not support
          the linq assemblies.
    .LINK 
        http://www.the-little-things.net 
    #> 
    [CmdletBinding( DefaultParameterSetName = "StringSet")] 
    param ( 
        [Parameter( Position=0,
                    Mandatory=$true, 
                    ValueFromPipeline=$true, 
                    ParameterSetName="ObjectSet",
                    HelpMessage="Array of psobjects to convert to an html table and modify.")]
        [Object[]]
        $InputObject,
        
        [Parameter( Position=0, 
                    Mandatory=$true, 
                    ValueFromPipeline=$true, 
                    ParameterSetName="StringSet",
                    HelpMessage="HTML table to modify.")] 
        [string]
        $InputString='',
        
        [Parameter( HelpMessage="Column name to compare values against when updating the table by value.")]
        [string]
        $Column="Name",
        
        [Parameter( HelpMessage="Value to compare when updating the table by value.")]
        $ColumnValue=0,
        
        [Parameter( HelpMessage="Custom script block for table conditions to search for when updating the table by value.")]
        [scriptblock]
        $ScriptBlock = {[string]$args[0] -eq [string]$args[1]}, 
        
        [Parameter( Mandatory=$true,
                    HelpMessage="Attribute to append to table element.")] 
        [string]
        $Attr,
        
        [Parameter( Mandatory=$true,
                    HelpMessage="Value to assign to attribute.")] 
        [string]
        $AttrValue,
        
        [Parameter( HelpMessage="By default the td element (individual table cell) is modified. This switch causes the attributes for the entire row (tr) to update instead.")] 
        [switch]
        $WholeRow,
        
        [Parameter( HelpMessage="If an array of object is converted to html prior to modification this is the head data which will get prepended to it.")]
        [string]
        $HTMLHead='<title>HTML Table</title>',
        
        [Parameter( HelpMessage="Method for table modification. ByValue uses column name lookups. ByEvenRows/ByOddRows are exactly as they sound.")]
        [ValidateSet('ByValue','ByEvenRows','ByOddRows')]
        [string]
        $ColorizeMethod='ByValue',
        
        [Parameter( HelpMessage="Use inline C# Linq calls for html table manipulation by default. Extremely fast but requires .NET 3.5 or above to work. Use this switch to force using non-Linq method (xml) first.")] 
        [switch]
        $DontUseLinq,
        
        [Parameter( HelpMessage="Return only the html table element.")] 
        [switch]
        $Fragment
        )
    
    BEGIN 
    {
        $LinqAssemblyLoaded = $false
        if (-not $DontUseLinq)
        {
            # A little note on Add-Type, this adds in the assemblies for linq with some custom code. The first time this 
            # is run in your powershell session it is compiled and loaded into your session. If you run it again in the same
            # session and the code was not changed at all, powershell skips the command (otherwise recompiling code each time
            # the function is called in a session would be pretty ineffective so this is by design). If you make any changes
            # to the code, even changing one space or tab, it is detected as new code and will try to reload the same namespace
            # which is not allowed and will cause an error. So if you are debugging this or changing it up, either change the
            # namespace as well or exit and restart your powershell session.
            #
            # And some notes on the actual code. It is my first jump into linq (or C# for that matter) so if it looks not so 
            # elegant or there is a better way to do this I'm all ears. I define four methods which names are self-explanitory:
            # - GetElementByIndex
            # - GetElementByValue
            # - GetOddElements
            # - GetEvenElements
            $LinqCode = @"
            public static System.Collections.Generic.IEnumerable<System.Xml.Linq.XElement> GetElementByIndex(System.Xml.Linq.XContainer doc, System.Xml.Linq.XName element, int index)
            {
                return doc.Descendants(element)
                        .Where  (e => e.NodesBeforeSelf().Count() == index)
                        .Select (e => e);
            }
            public static System.Collections.Generic.IEnumerable<System.Xml.Linq.XElement> GetElementByValue(System.Xml.Linq.XContainer doc, System.Xml.Linq.XName element, string value)
            {
                return  doc.Descendants(element) 
                        .Where  (e => e.Value == value)
                        .Select (e => e);
            }
            public static System.Collections.Generic.IEnumerable<System.Xml.Linq.XElement> GetOddElements(System.Xml.Linq.XContainer doc, System.Xml.Linq.XName element)
            {
                return doc.Descendants(element)
                        .Where  ((e,i) => i % 2 != 0)
                        .Select (e => e);
            }
            public static System.Collections.Generic.IEnumerable<System.Xml.Linq.XElement> GetEvenElements(System.Xml.Linq.XContainer doc, System.Xml.Linq.XName element)
            {
                return doc.Descendants(element)
                        .Where  ((e,i) => i % 2 == 0)
                        .Select (e => e);
            }
"@
            try
            {
                Add-Type -ErrorAction SilentlyContinue `
                -ReferencedAssemblies System.Xml, System.Xml.Linq `
                -UsingNamespace System.Linq `
                -Name XUtilities `
                -Namespace CustomLinq `
                -MemberDefinition $LinqCode
                
                $LinqAssemblyLoaded = $true
            }
            catch
            {
                $LinqAssemblyLoaded = $false
            }
        }
        $tablepattern = [regex]'(?s)(<table.*?>.*?</table>)'
        $headerpattern = [regex]'(?s)(^.*?)(?=<table)'
        $footerpattern = [regex]'(?s)(?<=</table>)(.*?$)'
        $header = ''
        $footer = ''
    }
    PROCESS 
    { }
    END 
    { 
        if ($psCmdlet.ParameterSetName -eq 'ObjectSet')
        {
            # If we sent an array of objects convert it to html first
            $InputString = ($InputObject | ConvertTo-Html -Head $HTMLHead)
        }

        # Convert our data to x(ht)ml 
        if ($LinqAssemblyLoaded)
        {
            $xml = [System.Xml.Linq.XDocument]::Parse("$InputString")
        }
        else
        {
            # old school xml is kinda dumb so we strip out only the table to work with then 
            # add the header and footer back on later.
            $firsttable = [Regex]::Match([string]$InputString, $tablepattern).Value
            $header = [Regex]::Match([string]$InputString, $headerpattern).Value
            $footer = [Regex]::Match([string]$InputString, $footerpattern).Value
            [xml]$xml = [string]$firsttable
        }
        switch ($ColorizeMethod) {
            "ByEvenRows" {
                if ($LinqAssemblyLoaded)
                {
                    $evenrows = [CustomLinq.XUtilities]::GetEvenElements($xml, "{http://www.w3.org/1999/xhtml}tr")    
                    foreach ($row in $evenrows)
                    {
                        $row.SetAttributeValue($Attr, $AttrValue)
                    }
                }
                else
                {
                    $rows = $xml.GetElementsByTagName('tr')
                    for($i=0;$i -lt $rows.count; $i++)
                    {
                        if (($i % 2) -eq 0 ) {
                           $newattrib=$xml.CreateAttribute($Attr)
                           $newattrib.Value=$AttrValue
                           [void]$rows.Item($i).Attributes.Append($newattrib)
                        }
                    }
                }
            }
            "ByOddRows" {
                if ($LinqAssemblyLoaded)
                {
                    $oddrows = [CustomLinq.XUtilities]::GetOddElements($xml, "{http://www.w3.org/1999/xhtml}tr")    
                    foreach ($row in $oddrows)
                    {
                        $row.SetAttributeValue($Attr, $AttrValue)
                    }
                }
                else
                {
                    $rows = $xml.GetElementsByTagName('tr')
                    for($i=0;$i -lt $rows.count; $i++)
                    {
                        if (($i % 2) -ne 0 ) {
                           $newattrib=$xml.CreateAttribute($Attr)
                           $newattrib.Value=$AttrValue
                           [void]$rows.Item($i).Attributes.Append($newattrib)
                        }
                    }
                }
            }
            "ByValue" {
                if ($LinqAssemblyLoaded)
                {
                    # Find the index of the column you want to format 
                    $ColumnLoc = [CustomLinq.XUtilities]::GetElementByValue($xml, "{http://www.w3.org/1999/xhtml}th",$Column) 
                    $ColumnIndex = $ColumnLoc | Foreach-Object{($_.NodesBeforeSelf() | Measure-Object).Count} 
            
                    # Process each xml element based on the index for the column we are highlighting 
                    switch([CustomLinq.XUtilities]::GetElementByIndex($xml, "{http://www.w3.org/1999/xhtml}td", $ColumnIndex)) 
                    { 
                        {$(Invoke-Command $ScriptBlock -ArgumentList @($_.Value, $ColumnValue))} {
                            if ($WholeRow)
                            {
                                $_.Parent.SetAttributeValue($Attr, $AttrValue)
                            }
                            else
                            {
                                $_.SetAttributeValue($Attr, $AttrValue)
                            }
                        }
                    }
                }
                else
                {
                    $colvalindex = 0
                    $headerindex = 0
                    $xml.GetElementsByTagName('th') | Foreach {
                        if ($_.'#text' -eq $Column) 
                        {
                            $colvalindex=$headerindex
                        }
                        $headerindex++
                    }
                    $rows = $xml.GetElementsByTagName('tr')
                    $cols = $xml.GetElementsByTagName('td')
                    $colvalindexstep = ($cols.count /($rows.count - 1))
                    for($i=0;$i -lt $rows.count; $i++)
                    {
                        $index = ($i * $colvalindexstep) + $colvalindex
                        $colval = $cols.Item($index).'#text'
                        if ($(Invoke-Command $ScriptBlock -ArgumentList @($colval, $ColumnValue))) {
                            $newattrib=$xml.CreateAttribute($Attr)
                            $newattrib.Value=$AttrValue
                            try 
                            {
                                if ($WholeRow)
                                {
                                    [void]$rows.Item($i).Attributes.Append($newattrib)
                                }
                                else
                                {
                                    [void]$cols.Item($index).Attributes.Append($newattrib)
                                }
                            }
                            catch
                            {
                                Write-Warning -Message ('Format-HTMLTable: Something weird happened! - {0}' -f $_.Exception.Message)
                            }
                        }
                    }
                }
            }
        }
        if ($LinqAssemblyLoaded)
        {
            if ($Fragment)
            {
                [string]$htmlresult = $xml.Document.ToString()
                if ([string]$htmlresult -match $tablepattern)
                {
                    [string]$matches[0]
                }
            }
            else
            {
                [string]$xml.Document.ToString()
            }
        }
        else
        {
            if ($Fragment)
            {
                [string]($xml.OuterXml | Out-String)
            }
            else
            {
                [string]$htmlresult = $header + ($xml.OuterXml | Out-String) + $footer
                return $htmlresult
            }
        }
    }
}

Function Add-Zip
{
    param([string]$zipfilename)

    if(-not (test-path($zipfilename)))
    {
        set-content $zipfilename ("PK" + [char]5 + [char]6 + ("$([char]0)" * 18))
        (dir $zipfilename).IsReadOnly = $false  
    }

    $shellApplication = new-object -com shell.application
    $zipPackage = $shellApplication.NameSpace($zipfilename)

    foreach($file in $input) 
    { 
            $zipPackage.CopyHere($file.FullName)
            Start-sleep -milliseconds 500
    }
}

Function New-ZipFile
{
    #.Synopsis
    #  Expand a zip file, ensuring it's contents go to a single folder ...
    [CmdletBinding()]
    param(
        [Parameter(Position=0, Mandatory=$true)]
        $ZipFilePath,

        [Parameter(Position=1, Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
        [Alias("PSPath","Item")]
        [string[]]
        $InputObject = $Pwd,

        [switch]
        $Append,

        # The compression level (defaults to Optimal):
        #   Optimal - The compression operation should be optimally compressed, even if the operation takes a longer time to complete.
        #   Fastest - The compression operation should complete as quickly as possible, even if the resulting file is not optimally compressed.
        #   NoCompression - No compression should be performed on the file.
        [System.IO.Compression.CompressionLevel]$Compression = "Optimal"
    )
    BEGIN
    {
        # Make sure the folder already exists
        [string]$File = Split-Path $ZipFilePath -Leaf
        [string]$Folder = $(if($Folder = Split-Path $ZipFilePath) { Resolve-Path $Folder } else { $Pwd })
        $ZipFilePath = Join-Path $Folder $File
        # If they don't want to append, make sure the zip file doesn't already exist.
        if(!$Append) 
        {
            if(Test-Path $ZipFilePath) 
            { 
                Remove-Item $ZipFilePath 
            }
        }
        $Archive = [System.IO.Compression.ZipFile]::Open( $ZipFilePath, "Update" )
    }
    PROCESS
    {
        foreach($path in $InputObject) 
        {
            foreach($item in Resolve-Path $path) 
            {
                # Push-Location so we can use Resolve-Path -Relative 
                Push-Location (Split-Path $item)
                # This will get the file, or all the files in the folder (recursively)
                foreach($file in Get-ChildItem $item -Recurse -File -Force | % FullName) 
                {
                    # Calculate the relative file path
                    $relative = (Resolve-Path $file -Relative).TrimStart(".\")
                    # Add the file to the zip
                    $null = [System.IO.Compression.ZipFileExtensions]::CreateEntryFromFile($Archive, $file, $relative, $Compression)
                }
                Pop-Location
            }
        }
    }
    END
    {
        $Archive.Dispose()
        Get-Item $ZipFilePath
    }
}
#endregion Functions - Serial or Utility

#region Functions - AD
Function Search-AD
{
# Original Author (largely unmodified btw): 
#  http://becomelotr.wordpress.com/2012/11/02/quick-active-directory-search-with-pure-powershell/
    param (
        [string[]]$Filter,
        [string[]]$Properties = @('Name','ADSPath'),
        [string]$SearchRoot,
        [switch]$DontJoinAttributeValues
    )
    if ($SearchRoot) 
    { 
        $Root = [ADSI]$SearchRoot
    }
    else 
    {
        $Root = [ADSI]''
    }
    if ($Filter)
    {
        $LDAP = "(&({0}))" -f ($Filter -join ')(')
    }
    else
    {
        $LDAP = "(name=*)"
    }
    try
    {
        (New-Object ADSISearcher -ArgumentList @(
            $Root,
            $LDAP,
            $Properties
        ) -Property @{
            PageSize = 1000
        }).FindAll() | ForEach-Object {
            $ObjectProps = @{}
            $_.Properties.GetEnumerator() |
                Foreach-Object {
                    $Val = @($_.Value)
                    if ($_.Name -ne $null)
                    {
                        if ($DontJoinAttributeValues -and ($Val.Count -gt 1))
                        {
                            $ObjectProps.Add(
                                $_.Name,
                                ($_.Value)
                            )
                        }
                        else
                        {
                            $ObjectProps.Add(
                                $_.Name,
                                (-join $_.Value)
                            )
                        }
                    }
                }
            if ($ObjectProps.psbase.keys.count -ge 1)
            {
                New-Object PSObject -Property $ObjectProps |
                    select $Properties
            }
        }
    }
    catch
    {
        Write-Warning -Message ('Search-AD: Filter - {0}: Root - {1}: Error - {2}' -f $LDAP,$Root.Path,$_.Exception.Message)
    }
}

Function Append-ADUserAccountControl 
{
    <#
        author: Zachary Loeber
        http://support.microsoft.com/kb/305144
        http://msdn.microsoft.com/en-us/library/cc245514.aspx
    #>
    [cmdletbinding()]
    param
    (
        [Parameter(HelpMessage='User or users to process.',
                   Mandatory=$true,
                   ValueFromPipeline=$true)]
        [psobject[]]$User
    )

    BEGIN
    {
        Add-Type -TypeDefinition @" 
        [System.Flags]
        public enum userAccountControlFlags {
            SCRIPT                                  = 0x0000001,
            ACCOUNTDISABLE                          = 0x0000002,
            NOT_USED                                = 0x0000004,
            HOMEDIR_REQUIRED                        = 0x0000008,
            LOCKOUT                                 = 0x0000010,
            PASSWD_NOTREQD                          = 0x0000020,
            PASSWD_CANT_CHANGE                      = 0x0000040,
            ENCRYPTED_TEXT_PASSWORD_ALLOWED         = 0x0000080,
            TEMP_DUPLICATE_ACCOUNT                  = 0x0000100,
            NORMAL_ACCOUNT                          = 0x0000200,
            INTERDOMAIN_TRUST_ACCOUNT               = 0x0000800,
            WORKSTATION_TRUST_ACCOUNT               = 0x0001000,
            SERVER_TRUST_ACCOUNT                    = 0x0002000,
            DONT_EXPIRE_PASSWD                      = 0x0010000,
            MNS_LOGON_ACCOUNT                       = 0x0020000,
            SMARTCARD_REQUIRED                      = 0x0040000,
            TRUSTED_FOR_DELEGATION                  = 0x0080000,
            NOT_DELEGATED                           = 0x0100000,
            USE_DES_KEY_ONLY                        = 0x0200000,
            DONT_REQUIRE_PREAUTH                    = 0x0400000,
            PASSWORD_EXPIRED                        = 0x0800000,
            TRUSTED_TO_AUTH_FOR_DELEGATION          = 0x1000000
        }
"@
        $Users = @()
        $UACAttribs = @(
            'SCRIPT',
            'ACCOUNTDISABLE',
            'NOT_USED',
            'HOMEDIR_REQUIRED',
            'LOCKOUT',
            'PASSWD_NOTREQD',
            'PASSWD_CANT_CHANGE',
            'ENCRYPTED_TEXT_PASSWORD_ALLOWED',
            'TEMP_DUPLICATE_ACCOUNT',
            'NORMAL_ACCOUNT',
            'INTERDOMAIN_TRUST_ACCOUNT',
            'WORKSTATION_TRUST_ACCOUNT',
            'SERVER_TRUST_ACCOUNT',
            'DONT_EXPIRE_PASSWD',
            'MNS_LOGON_ACCOUNT',
            'SMARTCARD_REQUIRED',
            'TRUSTED_FOR_DELEGATION',
            'NOT_DELEGATED',
            'USE_DES_KEY_ONLY',
            'DONT_REQUIRE_PREAUTH',
            'PASSWORD_EXPIRED',
            'TRUSTED_TO_AUTH_FOR_DELEGATION',
            'PARTIAL_SECRETS_ACCOUNT'
        )
    }
    PROCESS
    {
        $Users += $User
    }
    END
    {
        Foreach ($usr in $Users)
        {
            if ($usr.PSObject.Properties.Match('useraccountcontrol').Count) 
            {
                try 
                {
                    $UAC = [Enum]::Parse('userAccountControlFlags', $usr.useraccountcontrol)
                    $UACAttribs | Foreach {
                        Add-Member -InputObject $usr -MemberType NoteProperty `
                        -Name $_ -Value ($UAC -match $_) -Force
                    }
                }
                catch
                {
                    Write-Warning -Message ('Append-ADUserAccountControl: {0}' -f $_.Exception.Message)
                }
            }
            $usr
        }
    }
}

Function Normalize-ADUsers
{
    [cmdletbinding()]
    param
    (
        [Parameter(HelpMessage='User or users to process.',
                   Mandatory=$true,
                   ValueFromPipeline=$true)]
        [psobject[]]$User,
        
        [Parameter(HelpMessage='AD attributes to process.',
                   Mandatory=$true)]
        [string[]]$Attribs
    )

    BEGIN
    {
        $Users = @()
        $LyncPools = Get-LyncPoolAssociationHash | 
                      ConvertTo-HashArray -PivotProperty 'ServiceName' -LookupValue 'PoolName'
    }
    PROCESS
    {
        if ($User -ne $null)
        {
            $Users += $User
        }
    }
    END
    {
        Foreach ($usr in $Users)
        {
            $UserProps = @{}
            Foreach ($Attrib in $Attribs)
            {
                if ($usr.PSObject.Properties.Match($Attrib).Count) 
                {
                    switch ($Attrib) 
                    {
                        'pwdlastset' {                            
                            $AttribVal = [datetime]::FromFileTime([int64]($usr.$Attrib))
                            $PasswordAge=((get-date) - $AttribVal).days
                            $UserProps.Add(
                                'PasswordAge',
                                $PasswordAge
                            )
                            break
                        }
                        'lastlogontimestamp' {
                            $AttribVal = [datetime]::FromFileTime([int64]($usr.$Attrib))
                            if ($AttribVal -match '12/31/1600')
                            {
                                $LogonAge = 'Never'
                                $AttribVal = 'Never'
                            }
                            else
                            {
                                $LogonAge=((get-date) - $AttribVal).days
                            }
                            $UserProps.Add(
                                'DaysSinceLastLogon',
                                $LogonAge
                            )
                            break
                        }
                        { @('badPasswordTime', 'lastlogon') -contains $_ } {
                            $AttribVal = [datetime]::FromFileTime([int64]($usr.$Attrib))
                            break
                        }
                        'accountExpires'{
                            if (($usr.$Attrib -eq 0) -or ($usr.$Attrib -eq '9223372036854775807') -or ($usr.$Attrib -eq '9223372032559808511'))
                            {
                                $AttribVal = 'Never'
                            }
                            else
                            {
                                $AttribVal = [datetime]::FromFileTime([int64]($usr.$Attrib))
                            }
                            break
                        }
                        'msRTCSIP-PrimaryHomeServer' {
                            if ($usr.$Attrib -ne $null)
                            {
                                $AttribVal = $LyncPools[$usr.$Attrib]
                            }
                            else
                            {
                                $AttribVal = $null
                            }
                            $UserProps.Add(
                                'LyncPool',
                                $AttribVal
                            )
                        }
                        default {
                            $AttribVal = $usr.$Attrib
                            break
                        }
                     }

                    $UserProps.Add(
                            $Attrib,
                            $AttribVal
                    )
                } 
                else 
                { 
                    $UserProps.Add(
                            $Attrib,
                            $null
                    )
                }
            }
            New-Object psobject -Property $UserProps
        }
    }
}

Function Get-ADPrivilegedGroups
{
    [CmdletBinding()]
    param
    (
        [Parameter(HelpMessage="Domain to gather privileged group information about. If not specified, all domains in the current forest will be enumerated.",
                   Mandatory=$false,
                   ValueFromPipeline=$true)]
        $Domain
    )
    BEGIN
    {
        $Domains = @()
    }
    PROCESS
    {
        if ($Domain -ne $null)
        {
            $Domains += $Domain
        }
    }
    END
    {
        if ($Domains.Count -eq 0)
        {
            $Forest = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()
            $Domains = @($Forest.Domains | %{[string]$_.Name})
        }
        Foreach ($Dom in $Domains)
        {
            # Domain SID
            $DomainDN = 'dc=' + $Dom.Replace('.', ',dc=')
            $DomGCobject = [adsi]"GC://$domainDN"
            $DomSid = New-Object System.Security.Principal.SecurityIdentifier($DomGCobject.objectSid[0], 0)
            $DomSid = $DomSid.toString()
            
            $StaticPrivGroupDesc = @{
                'S-1-5-32-544' = "Administrators"
                'S-1-5-32-548' = "Account Operators"
                'S-1-5-32-549' = "Server Operators"
                'S-1-5-32-550' = "Print Operators"
                'S-1-5-32-551' = "Backup Operators"
                "$DomSid-517" = "Cert Publishers"
                "$DomSid-518"  = "Schema Admins"
                "$DomSid-519"  = "Enterprise Admins"
               # "$DomSid-520"  = "Group Policy Creator Owners"
                "$DomSid-512"  = "Domain Admins"
            }
            $ADProp_Grp = @('Name',
                            'cn',
                            'distinguishedname')
            
            Foreach ($GrpSid in $StaticPrivGroupDesc.Keys)
            {
                $Grp = @(Search-AD -Filter "(objectSID=$GrpSid)" `
                                   -SearchRoot "LDAP://$DomainDN" `
                                   -Properties $ADProp_Grp)
                if ($Grp.Count -gt 0)
                {
                    $GrpProps = @{
                        'Domain' = $dom
                        'Group' = $StaticPrivGroupDesc[$GrpSid]
                        'GroupDN' = $Grp[0].distinguishedname
                        'GroupCN' = $Grp[0].cn
                        'GroupName' = $Grp[0].Name
                #        'Admincount' = $Grp[0].admincount
                        'Sid' = $GrpSid
                    }
                    New-Object PSObject -Property $GrpProps
                }
            }
        }
    }
}

Function Get-ADDomainPrivAccounts
{
    [CmdletBinding()]
    param
    (
        [Parameter(HelpMessage="Domain to gather privileged accounts. If not specified, all domains in the current forest will be enumerated.",
                   ValueFromPipeline=$true)]
        [string[]]$Domain,
        [Parameter(HelpMessage='User attributes to include in results.')]
        $UserAttribs = @( 'cn',
                          'displayName',
                          'givenName',
                          'sn',
                          'name',
                          'sAMAccountName',
                          'whenChanged',
                          'whenCreated',
                          'pwdLastSet',
                          'badPasswordTime',
                          'badPwdCount',
                          'lastLogon',
                          'logonCount',
                          'useraccountcontrol',
                          'lastlogontimestamp'
                        )
    )
    BEGIN
    {
        $RootDSC = [adsi]"LDAP://RootDSE"
        $DomNamingContext = $RootDSC.RootDomainNamingContext
        $ConfigNamingContext = $RootDSC.configurationNamingContext
        $Domains = @()
    }
    PROCESS
    {
        if ($Domain -ne $null)
        {
            $Domains += $Domain
        }
    }
    END
    {
        if ($Domains.Count -eq 0)
        {
            $Forest = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()
            $Domains = @($Forest.Domains | %{[string]$_.Name})
        }
        $DomPrivGroups = @()
        ForEach ($Dom in $Domains) 
        { 
            $CurDomainContext = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext("Domain", $Dom)
            $CurDomain = [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($CurDomainContext)
            $CurDomainDetails = [ADSI]"LDAP://$($CurDomain)"
            $DomainDN = 'dc=' + $Dom.Replace('.', ',dc=')
            $NetBIOSName = Get-NETBiosName $DomainDN $ConfigNamingContext
            
            $DomPrivGroups = @(Get-ADPrivilegedGroups -Domain $Dom)
            Foreach ($PrivGroup in $DomPrivGroups)
            {
                $PrivGroupDN = $PrivGroup.GroupDN
                Write-Verbose $PrivGroupDN
                # Only works on 2003 SP2 and above
                $Filter = "(samAccountType=805306368)(!(userAccountControl:1.2.840.113556.1.4.803:=2))(memberOf:1.2.840.113556.1.4.1941:=$PrivGroupDN)"
                $PrivUsers = @(Search-AD -Filter $Filter `
                                         -SearchRoot "LDAP://$DomainDN" `
                                         -Properties $UserAttribs)
                Write-Verbose -Message ('Privileged Users: Group {0}' -f $PrivGroup.GroupDN)
                $PrivUsers = $PrivUsers | 
                             Normalize-ADUsers -Attribs $UserAttribs |
                             Append-ADUserAccountControl
                Foreach ($PrivUser in $PrivUsers)
                {
                    if ($PrivUser -ne $null)
                    {
                        $PrivMemberProp = @{
                            Domain = $Dom
                            DomainNetBIOS = $NetBIOSName
                            PrivGroup = $PrivGroup.Group
                        }
                        $PrivUser.psobject.properties | 
                        Where {$_.Name -ne $null} | ForEach {
                            $PrivMemberProp[$_.Name] = $_.Value 
                        }
                        New-Object psobject -Property $PrivMemberProp
                    }
                }
            }
        }
    }
}

Function Get-TreeFromLDAPPath
{
    # $Output = [System.Web.HttpUtility]::HtmlDecode(($a | ConvertTo-Html))
    [CmdletBinding()]
    Param
    (
        [Parameter(HelpMessage="LDAP path.")]
        [string]
        $LDAPPath,
        
        [Parameter(HelpMessage="Determines the depth a tree node is indented")]
        [int]
        $IndentDepth=1,
        
        [Parameter(HelpMessage="Optional character to use for each newly indented node.")]
        [char]
        $IndentChar = 3,
        
        [Parameter(HelpMessage="Don't remove the ldap node type (ie. DC=)")]
        [Switch]
        $KeepNodeType
     )
    $regex = [regex]'(?<LDAPType>^.+)\=(?<LDAPName>.+$)'
    $ldaparr = Get-ADPathName $LDAPPath -split
    $ADPartCount = $ldaparr.count
    $spacer = ''
    $output = ''
    for ($index = ($ADPartCount); $index -gt 0; $index--) 
    {
        $node = $ldaparr[($index-1)]
        if (-not $KeepNodeType)
        {
            if ($node -match $regex)
            {
                $node = $matches['LDAPName']
            }
        }
        if ($index -eq ($ADPartCount))
        {
            $line = ''
        }
        else
        {
            $line = $IndentChar
            $spacer = $spacer + (' ' * $IndentDepth)
            # This fixes an offset issue
            if ($index -lt ($ADPartCount - 1))
            {
                $spacer = $spacer + ' '
            }
        }
        $line = $spacer + $line + $node + "`n"
        $output = $Output+$line
    }
    [string]$output
}

Function Get-ObjectFromLDAPPath
{
    [CmdletBinding()]
    Param
    (
        [Parameter(HelpMessage="LDAP path.")]
        [string]
        $LDAPPath,
        
        [Parameter(HelpMessage="Translate the ldap type.")]
        [switch]
        $TranslateNamingAttribute
    )
    $output = @()
    $ldaparr = Get-ADPathName $LDAPPath -split
    $regex = [regex]'(?<LDAPType>^.+)\=(?<LDAPName>.+$)'
    $position = 0
    $ldaparr | %{
        if ($_ -match $regex)
        {
            if ($TranslateNamingAttribute)
            {
                switch ($matches['LDAPType']) 
                {
                      'CN' {$_ldaptype = "Common Name"}
                      'OU' {$_ldaptype = "Organizational Unit"}
                      'DC' {$_ldaptype = "Domain Component"}
                   default {$_ldaptype = $matches['LDAPType']}
                }
            }
            else
            {
                $_ldaptype = $matches['LDAPType']
            }
            $objprop = @{
                LDAPType = $_ldaptype
                LDAPName = $matches['LDAPName']
                Position = $position
            }
            $output += New-Object psobject -Property $objprop
            $position++
        }
    }
    Write-Output -InputObject $output
}

Function Get-LyncPoolAssociationHash 
{
    BEGIN
    {
        $Lync_Elements = @()
        $AD_PoolProperties = @('cn',
                               'distinguishedName',
                               'dnshostname',
                               'msrtcsip-pooldisplayname'
                              )
    }
    PROCESS
    {}
    END
    {
        $RootDSC = [adsi]"LDAP://RootDSE"
        $DomNamingContext = $RootDSC.RootDomainNamingContext
        $ConfigNamingContext = $RootDSC.configurationNamingContext
        $OCSADContainer = ''

        # Find Lync AD config partition 
        $LyncPathSearch = @(Search-AD -Filter '(objectclass=msRTCSIP-Service)' -SearchRoot "LDAP://$([string]$DomNamingContext)")
        if ($LyncPathSearch.count -ge 1)
        {
            $OCSADContainer = ($LyncPathSearch[0]).adspath
        }
        else
        {
            $LyncPathSearch = @(Search-AD -Filter '(objectclass=msRTCSIP-Service)' -SearchRoot "LDAP://$ConfigNamingContext")
            if ($LyncPathSearch.count -ge 1)
            {
                $OCSADContainer = ($LyncPathSearch[0]).adspath
            }
        }
        if ($OCSADContainer -ne '')
        {
            $LyncPoolLookupTable = @{}
            # All Lync pools
            $Lync_Pools = @(Search-AD -Filter '(&(objectClass=msRTCSIP-Pool))' `
                                      -Properties $AD_PoolProperties `
                                      -SearchRoot $OCSADContainer)
            $LyncPoolCount = $Lync_Pools.Count
            $Lync_Pools | %{
                $LyncElementProps = @{
                    CN = $_.cn
                    distinguishedName = $_.distinguishedName
                    ServiceName = "CN=Lc Services,CN=Microsoft,$($_.distinguishedName)"
                    PoolName = $_.'msrtcsip-pooldisplayname'
                    PoolFQDN = $_.dnshostname
                }
                $Lync_Elements += New-Object PSObject -Property $LyncElementProps
            }
            $Lync_Elements
        }
    }
}

Function Get-NETBiosName ( $dn, $ConfigurationNC ) 
{ 
    try 
    { 
        $Searcher = New-Object System.DirectoryServices.DirectorySearcher  
        $Searcher.SearchScope = "subtree"  
        $Searcher.PropertiesToLoad.Add("nETBIOSName")| Out-Null 
        $Searcher.SearchRoot = "LDAP://cn=Partitions,$ConfigurationNC" 
        $Searcher.Filter = "(nCName=$dn)" 
        $NetBIOSName = ($Searcher.FindOne()).Properties.Item("nETBIOSName") 
        Return $NetBIOSName 
    } 
    catch 
    { 
        Return $null 
    } 
}

Function Get-ADPathName
{
    # Get-ADPathname
    # Written by Bill Stewart (bstewart@iname.com)
    # PowerShell wrapper script for the Pathname COM object.

    #requires -version 2

    <#
    .SYNOPSIS
    Outputs Active Directory path names in various formats.

    .DESCRIPTION
    Outputs Active Directory (AD) path names in various formats using the Pathname COM object. The Pathname COM object implements the ADSI IADSPathname interface (see RELATED LINKS). This is a more robust means of handling AD path names than string parsing because it supports escaping of special characters.

    .PARAMETER Path
    Specifies the AD path. For example: "CN=Ken Dyer,DC=fabrikam,DC=com". If using the Full type (see -Full parameter), include the server and/or provider; for example: "LDAP://CN=Ken Dyer,DC=fabrikam,DC=com" or "LDAP://server/CN=Key Dyer,DC=fabrikam,DC=com".

    .PARAMETER Type
    Specifies the type of the AD path. This parameter must be one of the following values: "DN" or "Full". If you specify "Full", include the provider and/or server. The default value for this parameter is "DN".

    .PARAMETER Format
    Specifies the format in which to output the AD path. This parameter must be one of the following values: "Windows", "WindowsNoServer", "WindowsDN", "WindowsParent", "X500", "X500NoServer", "X500DN", "X500Parent", "Server", "Provider", or "Leaf". The default value for this parameter is "X500DN" (i.e., the distinguished name of the user, without provider or server names). This parameter's values correspond to the ADS_FORMAT_ENUM enumeration's values (see RELATED LINKS for more information and examples).

    .PARAMETER Retrieve
    Outputs the AD path using the format specified by the -Format parameter. This parameter is optional.

    .PARAMETER AddLeafElement
    Adds the specified leaf element(s) to the AD path and outputs the new AD path(s) using the format specified by the -Format parameter.

    .PARAMETER RemoveLeafElement
    Removes the final leaf element from the AD path and outputs the new AD path(s) using the format specified by the -Format parameter.

    .PARAMETER GetElement
    Outputs the specified element from the AD path. The left-most element is numbered 0 (zero), the second is numbered 1 (one), and so forth.

    .PARAMETER GetNumElements
    Outputs the number of elements in the AD path.

    .PARAMETER Split
    Outputs a list of the elements in the AD path.

    .PARAMETER GetEscapedElement
    Outputs one or more AD name element(s) with escape ("\") characters inserted in the correct places.

    .PARAMETER EscapedMode
    Specifies how escape characters are displayed in the AD path. This parameter must be one of the following values: "Default", "On", "Off", or "OffEx". The default value for this parameter is "Default".

    .PARAMETER ValuesOnly
    Specifies how elements in a path are output. If this parameter is absent, path elements are output using both attributes and values (e.g., "CN=Ken Dyer"). If this parameter is present, path elements are output with values only (e.g., "Ken Dyer").

    .INPUTS
    Inputs are AD path strings.

    .OUTPUTS
    Outputs are AD path strings.

    .EXAMPLE
    PS C:\> Get-ADPathname "LDAP://CN=Ken Dyer,CN=Users,DC=fabrikam,DC=com" -Type Full -Retrieve -Format X500DN
    Outputs "CN=Ken Dyer,CN=Users,DC=fabrikam,DC=com". The -Type parameter indicates that the AD path contains a provider (LDAP), and -Retrieve retrieves the path without the provider. The -Retrieve and -Format parameters are optional.

    .EXAMPLE
    PS C:\> Get-ADPathname "CN=Ken Dyer,CN=Users,DC=fabrikam,DC=com" -RemoveLeafElement
    This command removes the last element from the AD path ("CN=Ken Dyer") and outputs "CN=Users,DC=fabrikam,DC=com".

    .EXAMPLE
    PS C:\> Get-ADPathname "CN=Jeff Smith,CN=H/R,DC=fabrikam,DC=com" -EscapedMode On
    This command escapes the needed characters in the AD path and outputs "CN=Jeff Smith,CN=H\/R,DC=fabrikam,DC=com".

    .EXAMPLE
    PS C:\> Get-ADPathname "CN=H/R,DC=fabrikam,DC=com" -AddLeafElement "CN=Jeff Smith"
    This command adds the leaf element to the AD path and outputs "CN=Jeff Smith,CN=H/R,DC=fabrikam,DC=com".

    .EXAMPLE
    PS C:\> Get-ADPathname "CN=Jeff Smith,CN=H/R,DC=fabrikam,DC=com" -RemoveLeafElement
    This command removes the last element from the AD path ("CN=Jeff Smith") and outputs "CN=H/R,DC=fabrikam,DC=com".

    .EXAMPLE
    PS C:\> Get-ADPathname "CN=Ken Dyer,CN=Users,DC=fabrikam,DC=com" -Split
    This command splits the AD path and outputs a list of the elements: "CN=Ken Dyer", "CN=Users", "DC=fabrikam", and "DC=com".

    .EXAMPLE
    PS C:\> Get-Content ADPaths.txt | Get-ADPathname -EscapedMode On
    This command outputs all of the AD paths listed in the file ADPaths.txt with the needed escape characters.

    .EXAMPLE
    PS C:\> Get-ADPathname "CN=Users,DC=fabrikam,DC=com" -GetElement 0 -ValuesOnly
    This command gets the left-most element from the path and outputs "Users". Without the -ValuesOnly parameter, this command will output "CN=Users".

    .EXAMPLE
    PS C:\> Get-ADPathname -GetEscapedElement "OU=H/R"
    This command inserts the needed escape characters and outputs "OU=H\/R".

    .LINK
    ADSI IADSPathname Interface - http://msdn.microsoft.com/en-us/library/windows/desktop/aa706070.aspx
    ADS_FORMAT_ENUM Enumeration - http://msdn.microsoft.com/en-us/library/windows/desktop/aa772261.aspx
    #>

    [CmdletBinding(DefaultParameterSetName="Retrieve")]
    param(
      [parameter(ParameterSetName="Retrieve",Position=0,ValueFromPipeline=$TRUE)]
      [parameter(ParameterSetName="AddLeafElement",Position=0,Mandatory=$TRUE)]
      [parameter(ParameterSetName="RemoveLeafElement",Position=0,Mandatory=$TRUE)]
      [parameter(ParameterSetName="GetElement",Position=0,Mandatory=$TRUE)]
      [parameter(ParameterSetName="GetNumElements",Position=0,Mandatory=$TRUE)]
      [parameter(ParameterSetName="Split",Position=0,Mandatory=$TRUE)]
        [String[]]
        $Path,
      [parameter(ParameterSetName="Retrieve")]
      [parameter(ParameterSetName="AddLeafElement")]
      [parameter(ParameterSetName="RemoveLeafElement")]
      [parameter(ParameterSetName="GetElement")]
      [parameter(ParameterSetName="GetNumElements")]
      [parameter(ParameterSetName="Split")]
        [String] [ValidateSet("DN","Full")]
        $Type,
      [parameter(ParameterSetName="Retrieve")]
        [Switch]
        $Retrieve,
      [parameter(ParameterSetName="AddLeafElement",Mandatory=$TRUE)]
        [String[]]
        $AddLeafElement,
      [parameter(ParameterSetName="GetElement",Mandatory=$TRUE)]
        [UInt32]
        $GetElement,
      [parameter(ParameterSetName="RemoveLeafElement",Mandatory=$TRUE)]
        [Switch]
        $RemoveLeafElement,
      [parameter(ParameterSetName="GetNumElements",Mandatory=$TRUE)]
        [Switch]
        $GetNumElements,
      [parameter(ParameterSetName="Split",Mandatory=$TRUE)]
        [Switch]
        $Split,
      [parameter(ParameterSetName="Retrieve")]
      [parameter(ParameterSetName="AddLeafElement")]
      [parameter(ParameterSetName="RemoveLeafElement")]
        [String] [ValidateSet("Windows","WindowsNoServer","WindowsDN","WindowsParent","X500","X500NoServer","X500DN","X500Parent","Server","Provider","Leaf")]
        $Format,
      [parameter(ParameterSetName="Retrieve")]
      [parameter(ParameterSetName="AddLeafElement")]
      [parameter(ParameterSetName="RemoveLeafElement")]
      [parameter(ParameterSetName="GetElement")]
      [parameter(ParameterSetName="Split")]
        [String] [ValidateSet("Default","On","Off","OffEx")]
        $EscapedMode,
      [parameter(ParameterSetName="Retrieve")]
      [parameter(ParameterSetName="AddLeafElement")]
      [parameter(ParameterSetName="RemoveLeafElement")]
      [parameter(ParameterSetName="GetElement")]
      [parameter(ParameterSetName="Split")]
        [Switch]
        $ValuesOnly,
      [parameter(ParameterSetName="GetEscapedElement",Mandatory=$TRUE)]
        [String[]]
        $GetEscapedElement
    )

    begin {
      $ParamSetName = $PSCMDLET.ParameterSetName

      # Determine if we're using pipeline input.
      $PipelineInput = $FALSE
      if ( $ParamSetName -eq "Retrieve" ) {
        $PipelineInput = -not $PSBoundParameters.ContainsKey("Path")
      }

      # These hash tables improve code readability.
      $InputTypes = @{
        "Full" = 1
        "DN"   = 4
      }
      $OutputFormats = @{
        "Windows"         = 1 
        "WindowsNoServer" = 2 
        "WindowsDN"       = 3 
        "WindowsParent"   = 4 
        "X500"            = 5 
        "X500NoServer"    = 6 
        "X500DN"          = 7 
        "X500Parent"      = 8 
        "Server"          = 9 
        "Provider"        = 10
        "Leaf"            = 11
      }
      $EscapedModes = @{
        "Default" = 1
        "On"      = 2
        "Off"     = 3
        "OffEx"   = 4
      }
      $DisplayTypes = @{
        "Full"       = 1
        "ValuesOnly" = 2
      }

      # Invokes a method on a COM object that lacks a type library. If the COM
      # object uses more than one parameter, specify an array as the $parameters
      # parameter. The $outputType parameter coerces the function's output to the
      # specified type (default is [String]).
      function Invoke-Method {
        param(
          [__ComObject] $object,
          [String] $method,
          $parameters,
          [System.Type] $outputType = "String"
        )
        $output = $object.GetType().InvokeMember($method, "InvokeMethod", $NULL, $object, $parameters)
        if ( $output ) { $output -as $outputType }
      }

      # Sets a property on a COM object that lacks a type library.
      function Set-Property {
        param(
          [__ComObject] $object,
          [String] $property,
          $parameters
        )
        [Void] $object.GetType().InvokeMember($property, "SetProperty", $NULL, $object, $parameters)
      }

      # Creates the Pathname COM object. It lacks a type library so we use the
      # above Invoke-Method and Set-Property functions to interact with it.
      $Pathname = new-object -comobject "Pathname"

      # Set defaults for -Type and -Format. Use separate variables in case of
      # pipeline input.
      if ( $Type ) { $InputType = $Type } else { $InputType = "DN" }
      if ( $Format ) { $OutputFormat = $Format } else { $OutputFormat = "X500DN" }
      # Enable escaped mode if requested.
      if ( $EscapedMode ) {
        Set-Property $Pathname "EscapedMode" $EscapedModes[$EscapedMode]
      }
      # Output values only if requested.
      if ( $ValuesOnly ) {
        Invoke-Method $Pathname "SetDisplayType" $DisplayTypes["ValuesOnly"]
      }

      # -Retrieve parameter
      function Get-ADPathname-Retrieve {
        param(
          [String] $path,
          [Int] $inputType,
          [Int] $outputFormat
        )
        try {
          Invoke-Method $Pathname "Set" ($path,$inputType)
          Invoke-Method $Pathname "Retrieve" $outputFormat
        }
        catch [System.Management.Automation.MethodInvocationException] {
          write-error -exception $_.Exception.InnerException
        }
      }

      # -AddLeafElement parameter
      function Get-ADPathname-AddLeafElement {
        param(
          [String] $path,
          [Int] $inputType,
          [String] $element,
          [Int] $outputFormat
        )
        try {
          Invoke-Method $Pathname "Set" ($path,$inputType)
          Invoke-Method $Pathname "AddLeafElement" $element
          Invoke-Method $Pathname "Retrieve" $outputFormat
        }
        catch [System.Management.Automation.MethodInvocationException] {
          write-error -exception $_.Exception.InnerException
        }
      }

      # -RemoveLeafElement parameter
      function Get-ADPathname-RemoveLeafElement {
        param(
          [String] $path,
          [Int] $inputType,
          [Int] $outputFormat
        )
        try {
          Invoke-Method $Pathname "Set" ($path,$inputType)
          Invoke-Method $Pathname "RemoveLeafElement"
          Invoke-Method $Pathname "Retrieve" $outputFormat
        }
        catch [System.Management.Automation.MethodInvocationException] {
          write-error -exception $_.Exception.InnerException
        }
      }

      # -GetElement parameter
      function Get-ADPathname-GetElement {
        param(
          [String] $path,
          [Int] $inputType,
          [Int] $elementIndex
        )
        try {
          Invoke-Method $Pathname "Set" ($path,$inputType)
          Invoke-Method $Pathname "GetElement" $elementIndex
        }
        catch [System.Management.Automation.MethodInvocationException] {
          write-error -exception $_.Exception.InnerException
        }
      }

      # -GetNumElements parameter
      function Get-ADPathname-GetNumElements {
        param(
          [String] $path,
          [Int] $inputType
        )
        try {
          Invoke-Method $Pathname "Set" ($path,$inputType)
          Invoke-Method $Pathname "GetNumElements" -outputtype "UInt32"
        }
        catch [System.Management.Automation.MethodInvocationException] {
          write-error -exception $_.Exception.InnerException
        }
      }

      # -Split parameter
      function Get-ADPathname-Split {
        param(
          [String] $path,
          [Int] $inputType
        )
        try {
          Invoke-Method $Pathname "Set" ($path,$inputType)
          $numElements = Invoke-Method $Pathname "GetNumElements" -outputtype "UInt32"
          for ( $i = 0; $i -lt $numElements; $i++ ) {
            Invoke-Method $Pathname "GetElement" $i
          }
        }
        catch [System.Management.Automation.MethodInvocationException] {
          write-error -exception $_.Exception.InnerException
        }
      }

      # -GetEscapedElement parameter
      function Get-ADPathname-GetEscapedElement {
        param(
          [String] $element
        )
        try {
          Invoke-Method $Pathname "GetEscapedElement" (0,$element)
        }
        catch [System.Management.Automation.MethodInvocationException] {
          write-error -exception $_.Exception.InnerException
        }
      }
    }

    process {
      # The process block uses 'if'/'elseif' instead of 'switch' because 'switch'
      # replaces '$_', and we need '$_' in case of pipeline input.

      # "Retrieve" is the only parameter set that that accepts pipeline input.
      if ( $ParamSetName -eq "Retrieve" ) {
        if ( $PipelineInput ) {
          if ( $_ ) {
            Get-ADPathname-Retrieve $_ $InputTypes[$InputType] $OutputFormats[$OutputFormat]
          }
          else {
            write-error "You must provide pipeline input or specify the -Path parameter." -category SyntaxError
          }
        }
        else {
          $Path | foreach-object {
            Get-ADPathname-Retrieve $_ $InputTypes[$InputType] $OutputFormats[$OutputFormat]
          }
        }
      }
      elseif ( $ParamSetName -eq "AddLeafElement" ) {
        $AddLeafElement | foreach-object {
          Get-ADPathname-AddLeafElement $Path[0] $InputTypes[$InputType] $_ $OutputFormats[$OutputFormat]
        }
      }
      elseif ( $ParamSetName -eq "RemoveLeafElement" ) {
        $Path | foreach-object {
          Get-ADPathname-RemoveLeafElement $_ $InputTypes[$InputType] $OutputFormats[$OutputFormat]
        }
      }
      elseif ( $ParamSetName -eq "GetElement" ) {
        $Path | foreach-object {
          Get-ADPathname-GetElement $_ $InputTypes[$InputType] $GetElement
        }
      }
      elseif ( $ParamSetName -eq "GetNumElements" ) {
        $Path | foreach-object {
          Get-ADPathname-GetNumElements $_ $InputTypes[$InputType]
        }
      }
      elseif ( $ParamSetName -eq "Split" ) {
        Get-ADPathname-Split $Path[0] $InputTypes[$InputType]
      }
      elseif ( $ParamSetName -eq "GetEscapedElement" ) {
        $GetEscapedElement | foreach-object {
          Get-ADPathname-GetEscapedElement $_
        }
      }
    }
}
#endregion Functions - AD

#region Functions - Asset Report Project
Function Create-ReportSection
{
    #** This function is specific to this script and does all kinds of bad practice
    #   stuff. Use this function neither to learn from or judge me please. **
    #
    #   That being said, this function pretty much does all the report output
    #   options and layout magic. It depends upon the report layout hash and
    #   $HTMLRendering global variable hash.
    #
    #   This function generally shouldn't need to get changed in any way to customize your
    #   reports.
    #
    # .EXAMPLE
    #    Create-ReportSection -Rpt $ReportSection -Asset $Asset 
    #                         -Section 'Summary' -TableTitle 'System Summary'
    
    [CmdletBinding()]
    param(
        [parameter()]
        $Rpt,
        
        [parameter()]
        [string]$Asset,

        [parameter()]
        [string]$Section,
        
        [parameter()]
        [string]$TableTitle        
    )
    BEGIN
    {
        Add-Type -AssemblyName System.Web
    }
    PROCESS
    {}
    END
    {
        # Get our section type
        $RptSection = $Rpt['Sections'][$Section]
        $SectionType = $RptSection['Type']
        
        switch ($SectionType)
        {
            'Section'     # default to a data section
            {
                Write-Verbose -Message ('Create-ReportSection: {0}: {1}' -f $Asset,$Section)
                $ReportElementSource = @($RptSection['AllData'][$Asset])
                if ((($ReportElementSource.Count -gt 0) -and 
                     ($ReportElementSource[0] -ne $null)) -or 
                     ($RptSection['ShowSectionEvenWithNoData']))
                {
                    $SourceProperties = $RptSection['ReportTypes'][$ReportType]['Properties']
                    
                    #region report section type and layout
                    $TableType = $RptSection['ReportTypes'][$ReportType]['TableType']
                    $ContainerType = $RptSection['ReportTypes'][$ReportType]['ContainerType']

                    switch ($TableType)
                    {
                        'Horizontal' 
                        {
                            $PropertyCount = $SourceProperties.Count
                            $Vertical = $false
                        }
                        'Vertical' {
                            $PropertyCount = 2
                            $Vertical = $true
                        }
                        default {
                            if ((($SourceProperties.Count) -ge $HorizontalThreshold))
                            {
                                $PropertyCount = 2
                                $Vertical = $true
                            }
                            else
                            {
                                $PropertyCount = $SourceProperties.Count
                                $Vertical = $false
                            }
                        }
                    }
                    #endregion report section type and layout
                    
                    $Table = ''
                    If ($PropertyCount -ne 0)
                    {
                        # Create our future HTML table header
                        $SectionLink = '<a href="{0}"></a>' -f $Section
                        $TableHeader = $HTMLRendering['TableTitle'][$HTMLMode] -replace '<0>',$PropertyCount
                        $TableHeader = $SectionLink + ($TableHeader -replace '<1>',$TableTitle)

                        if ($RptSection.ContainsKey('Comment'))
                        {
                            if ($RptSection['Comment'] -ne $false)
                            {
                                $TableComment = $HTMLRendering['TableComment'][$HTMLMode] -replace '<0>',$PropertyCount
                                $TableComment = $TableComment -replace '<1>',$RptSection['Comment']
                                $TableHeader = $TableHeader + $TableComment
                            }
                        }
                        
                        $AllTableElements = @()
                        Foreach ($TableElement in $ReportElementSource)
                        {
                            $AllTableElements += $TableElement | Select $SourceProperties
                        }

                        # If we are creating a vertical table it takes a bit of transformational work
                        if ($Vertical)
                        {
                            $Count = 0
                            foreach ($Element in $AllTableElements)
                            {
                                $Count++
                                $SingleElement = [string]($Element | ConvertTo-PropertyValue | ConvertTo-Html)
                                if ($Rpt['Configuration']['PostProcessingEnabled'])
                                {
                                    # Add class elements for even/odd rows
                                    $SingleElement = Format-HTMLTable $SingleElement -ColorizeMethod 'ByEvenRows' -Attr 'class' -AttrValue 'even' -WholeRow
                                    $SingleElement = Format-HTMLTable $SingleElement -ColorizeMethod 'ByOddRows' -Attr 'class' -AttrValue 'odd' -WholeRow
                                    if ($RptSection.ContainsKey('PostProcessing') -and 
                                       ($RptSection['PostProcessing'].Value -ne $false))
                                    {
                                        $Rpt['Configuration']['PostProcessingEnabled'].Value
                                        $Table = $(Invoke-Command ([scriptblock]::Create($RptSection['PostProcessing'])))
                                    }
                                }
                                $SingleElement = [Regex]::Match($SingleElement, "(?s)(?<=</tr>)(.+)(?=</table>)").Value
                                $Table += $SingleElement 
                                if ($Count -ne $AllTableElements.Count)
                                {
                                    $Table += '<tr class="divide"><td></td><td></td></tr>'
                                }
                            }
                            $Table = '<table class="list">' + $TableHeader + $Table + '</table>'
                            $Table = [System.Web.HttpUtility]::HtmlDecode($Table)
                        }
                        # Otherwise it is a horizontal table
                        else
                        {
                            [string]$Table = $AllTableElements | ConvertTo-Html
                            if ($Rpt['Configuration']['PostProcessingEnabled'])
                            {
                                # Add class elements for even/odd rows
                                $Table = Format-HTMLTable $Table -ColorizeMethod 'ByEvenRows' -Attr 'class' -AttrValue 'even' -WholeRow
                                $Table = Format-HTMLTable $Table -ColorizeMethod 'ByOddRows' -Attr 'class' -AttrValue 'odd' -WholeRow
                                if ($RptSection.ContainsKey('PostProcessing'))
                                
                                {
                                    if ($RptSection.ContainsKey('PostProcessing'))
                                    {
                                        if ($RptSection['PostProcessing'] -ne $false)
                                        {
                                            $Table = $(Invoke-Command ([scriptblock]::Create($RptSection['PostProcessing'])))
                                        }
                                    }
                                }
                            }
                            # This will gank out everything after the first colgroup so we can replace it with our own spanned header
                            $Table = [Regex]::Match($Table, "(?s)(?<=</colgroup>)(.+)(?=</table>)").Value
                            $Table = '<table>' + $TableHeader + $Table + '</table>'
                            $Table = [System.Web.HttpUtility]::HtmlDecode(($Table))
                        }
                    }
                    
                    $Output = $HTMLRendering['SectionContainers'][$HTMLMode][$ContainerType]['Head'] + 
                              $Table + $HTMLRendering['SectionContainers'][$HTMLMode][$ContainerType]['Tail']
                    $Output
                }
            }
            'SectionBreak'
            {
                if ($Rpt['Configuration']['SkipSectionBreaks'] -eq $false)
                {
                    $Output = $HTMLRendering['CustomSections'][$SectionType] -replace '<0>',$TableTitle
                    $Output
                }
            }
        }
    }
}

Function Get-ADForestReportInformation
{
    [CmdletBinding()]
    param
    (
        [Parameter( HelpMessage="The custom report hash variable structure you plan to report upon")]
        $ReportContainer,
        [Parameter( HelpMessage="A sorted hash of enabled report elements.")]
        $SortedRpts
    )
    BEGIN
    {
        $verbose_timer = $verbose_starttime = Get-Date
        $ldapregex = [regex]'(?<LDAPType>^.+)\=(?<LDAPName>.+$)'
        try
        {
            $ADConnected = $true
            $schema = [DirectoryServices.ActiveDirectory.ActiveDirectorySchema]::GetCurrentSchema()
            $forest = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()
            $GCs = $forest.FindAllGlobalCatalogs()
            $GCNames = @($GCs | Select Name)
            $ForestDCs = @($forest.Domains | %{$_.DomainControllers} | Select Name)
            $ForestGCs = @((($GCs | Sort-Object -Property Name) | Select Name))
            $schemapartition = $schema.Name
            $RootDSC = [adsi]"LDAP://RootDSE"
            $DomNamingContext = $RootDSC.RootDomainNamingContext
            $ConfigNamingContext = $RootDSC.configurationNamingContext
            $Lync_ConfigPartition = 'None'

            $Path_LDAPPolicies = "LDAP://CN=Default Query Policy,CN=Query-Policies,CN=Directory Service,CN=Windows NT,CN=Services,$($ConfigNamingContext)"
            $Path_RecycleBinFeature = "LDAP://CN=Recycle Bin Feature,CN=Optional Features,CN=Directory Service,CN=Windows NT,CN=Services,$($ConfigNamingContext)"
            $Path_TombstoneLifetime = "LDAP://CN=Directory Service,CN=Windows NT,CN=Services,$($ConfigNamingContext)"
            $Path_ExchangeOrg = "LDAP://CN=Microsoft Exchange,CN=Services,$($ConfigNamingContext)"
            $Path_ExchangeVer = "LDAP://CN=ms-Exch-Schema-Version-Pt,$($SchemaPartition)"
            $Path_LyncVer = "LDAP://CN=ms-RTC-SIP-SchemaVersion,$($SchemaPartition)"
            $Path_ADSubnets = "LDAP://CN=Subnets,CN=Sites,$($ConfigNamingContext)"
            $Path_ADSiteLinks = "LDAP://CN=Sites,$($ConfigNamingContext)"
            
            $ExchangeFederations = @()
            $ExchangeServers = @()
            $Lync_Elements = @()
            $Sites = @()
            $SiteSubnets = @()
            $AllSiteConnections = @()
            $SiteLinks = @()
            $DomainControllers = @()
            $Domains = @()
            $DomainDFS = @()
            $DomainDFSR = @()
            $DomainTrusts = @()
            $DomainDNSZones = @()
            $DomainGPOs = @()
            $NPSServers = @()
            $DomainPrinters = @()
            $DomainPrivGroups = @()
        }
        catch
        {
            $ADConnected = $false
        }
    }
    PROCESS
    {}
    END
    {
        if ($ADConnected)
        {
            Write-Verbose -Message ('Get-ADForestReportInformation {0}: Forest Info - {1}' -f $forest.Name,$((New-TimeSpan $verbose_timer ($verbose_timer = get-date)).totalseconds))
            #region Forest Settings
            # Recycle Bin Feature check
            $RecycleBinEnabled = $false
            if ([ADSI]::Exists($Path_RecycleBinFeature))
            {
                $RecycleBinAttribs = Search-AD -Properties * -SearchRoot $Path_RecycleBinFeature
                if ($RecycleBinAttribs.PSObject.Properties.Match('msDS-EnabledFeatureBL').Count) 
                {
                    $RecycleBinEnabled = $True
                }
            }

            if ([ADSI]::Exists($Path_TombstoneLifetime))
            {
                [ADSI]$TombstoneConfig = $Path_TombstoneLifetime
                $TombstoneLife = $TombstoneConfig.TombstoneLifetime
                $DeletedObjectLife = $TombstoneConfig."msDS-DeletedObjectLifetime"
                if ($TombstoneLife -ne $null)
                {
                    $TotalObjectBackupLife = $TombstoneLife
                }
                if ($deletedObjectLife) {
                    if (!$TombstoneLife -or 
                        ($DeletedObjectLife -lt $TombstoneLife)) 
                    {
                        $TotalObjectBackupLife = $deletedObjLifetime
                    }
                }
            }
            else
            {
                $TombstoneLife = 'NA'
                $DeletedObjectLife = 'NA'
                $TotalObjectBackupLife = 'NA'
            }
            if ([ADSI]::Exists($Path_LDAPPolicies))
            {
                [ADSI]$LDAPPoliciesConfig = $Path_LDAPPolicies
                $LDAPAdminLimits = $LDAPPoliciesConfig.LDAPAdminLimits
            }
            else
            {
                $LDAPAdminLimits = $null
            }
            #endregion Forest Settings
            
            #region DHCP Servers
            $DHCPServers = @(Search-AD -Filter '(objectclass=dHCPClass)' `
                                       -Properties Name,WhenCreated `
                                       -SearchRoot "LDAP://$([string]$ConfigNamingContext)" | 
                             Where {$_.Name -ne 'DhcpRoot'})
            #endregion DHCP Servers
            
            #region Exchange

            $ExchangeServerCount = 0
            if ([ADSI]::Exists($Path_ExchangeVer))
            {
                Write-Verbose -Message ('Get-ADForestReportInformation {0}: Exchange - {1}' -f $forest.Name,$((New-TimeSpan $verbose_timer ($verbose_timer = get-date)).totalseconds))
                [ADSI]$SchemaPathExchange = $Path_ExchangeVer
                $ExchangeSchema = ($SchemaPathExchange | Select rangeUpper).rangeUpper
                $ExchangeVersion = $SchemaHashExchange[$ExchangeSchema]
                $Props_ExchOrgs = @('distinguishedName',
                                    'Name')
                $Props_ExchServers = @('adspath',
                                       'Name',
                                       'msexchserversite',
                                       'msexchcurrentserverroles',
                                       'adminDisplayName',
                                       'whencreated',
                                       'serialnumber',
                                       'msexchproductid')
                $Props_ExchFeds = @('Name',
                                    'msExchFedIsEnabled',
                                    'msExchFedDomainNames',
                                    'msExchFedEnabledActions',
                                    'msExchFedTargetApplicationURI',
                                    'msExchFedTargetAutodiscoverEPR',
                                    'msExchVersion')

                if ([ADSI]::Exists($Path_ExchangeOrg))
                {
                    $ExchOrgs = @(Search-AD -Filter '(&(objectClass=msExchOrganizationContainer))' `
                                            -Properties $Props_ExchOrgs `
                                            -SearchRoot $Path_ExchangeOrg)
                    foreach ($ExchOrg in $ExchOrgs)
                    {
                        $ExchServers = @(Search-AD -Filter '(objectCategory=msExchExchangeServer)' `
                                                   -Properties $Props_ExchServers `
                                                   -SearchRoot "LDAP://$([string]$ExchOrg.distinguishedname)")
                        $ExchangeServerCount += $ExchServers.Count
                        foreach ($ExchServer in $ExchServers)
                        {
                            $AdminGroup = Get-ADPathName $ExchServer.adspath -GetElement 2 -ValuesOnly
                            $ExchSite =  Get-ADPathName $ExchServer.msexchserversite -GetElement 0 -ValuesOnly
                            $ExchRole = $ExchServer.msexchcurrentserverroles
                            # only have two roles in Exchange 2013 so we process a bit differently
                            if ($ExchServer.serialNumber -like "Version 15*")
                            {
                                switch ($ExchRole) {
                                    '54' {
                                        $ExchRole = 'MAILBOX'
                                    }
                                    '16385' {
                                        $ExchRole = 'CAS'
                                    }
                                    '16439' {
                                        $ExchRole = 'MAILBOX, CAS'
                                    }
                                }
                            }
                            else
                            {
                                if($ExchRole -ne 0)
                                {
                                    $ExchRole = [Enum]::Parse('MSExchCurrentServerRolesFlags', $ExchRole)
                                }
                            }
                            $exchserverprops = @{
                                Organization = $ExchOrg.Name
                                AdminGroup   = $AdminGroup
                                Name         = $ExchServer.adminDisplayName
                                Role         = $ExchRole
                                Site         = $ExchSite
                                Created      = $ExchServer.whencreated
                                Serial       = $ExchServer.serialnumber
                                ProductID    = $ExchServer.msexchproductid
                            }
                            $ExchangeServers += New-Object PSObject -Property $exchserverprops
                        }
                        $ExchangeFeds = @(Search-AD -Filter '(objectCategory=msExchFedSharingRelationship)' `
                                                   -Properties $Props_ExchFeds -DontJoinAttributeValues `
                                                   -SearchRoot "LDAP://CN=Federation,$([string]$ExchOrg.distinguishedname)")
                        Foreach ($ExchFed in $ExchangeFeds)
                        {
                            $ExchangeFedProps = @{
                                Organization = $ExchOrg.Name
                                Name = $ExchFed.Name
                                Enabled = $ExchFed.msExchFedIsEnabled
                                Domains = @($ExchFed.msExchFedDomainNames)
                                AllowedActions = @($ExchFed.msExchFedEnabledActions)
                                TargetAppURI = $ExchFed.msExchFedTargetApplicationURI
                                TargetAutodiscoverEPR = $ExchFed.msExchFedTargetAutodiscoverEPR
                                ExchangeVersion = $ExchFed.msExchVersion
                            }
                            $ExchangeFederations += New-Object psobject -Property $ExchangeFedProps
                        }
                    }
                }
            }
            else
            {
                $ExchangeVersion = 'Exchange Not Installed'
            }
            #endregion Exchange

            #region OCS/Lync
            $Lync_InternalServers = @()
            $Lync_EdgeServers = @()
            $Lync_Pools = @()
            $Lync_OtherServers = @()
            $LyncServerCount = 0
            $LyncPoolCount = 0
            if([ADSI]::Exists($Path_LyncVer))
            {
                Write-Verbose -Message ('Get-ADForestReportInformation {0}: Lync/OCS - {1}' -f $forest.Name,$((New-TimeSpan $verbose_timer ($verbose_timer = get-date)).totalseconds))
                # Get Lync version in forest
                [ADSI]$SchemaPathLync = $Path_LyncVer
                $LyncSchema = ($SchemaPathLync | Select rangeUpper).rangeUpper
                $LyncVersion = $SchemaHashLync[$LyncSchema]
                
                # Find Lync AD config partition location
                $LyncPathSearch = @(Search-AD -Filter '(objectclass=msRTCSIP-Service)' -SearchRoot "LDAP://$([string]$DomNamingContext)")
                if ($LyncPathSearch.count -ge 1)
                {
                    $OCSADContainer = ($LyncPathSearch[0]).adspath
                    $Lync_ConfigPartition = 'System'
                }
                else
                {
                    $LyncPathSearch = @(Search-AD -Filter '(objectclass=msRTCSIP-Service)' -SearchRoot "LDAP://$ConfigNamingContext")
                    if ($LyncPathSearch.count -ge 1)
                    {
                        $OCSADContainer = ($LyncPathSearch[0]).adspath
                        $Lync_ConfigPartition = 'Configuration'
                    }
                }
                
                # All internal Lync servers
                Search-AD -Filter '(&(objectClass=msRTCSIP-TrustedServer))' `
                          -Properties 'msrtcsip-trustedserverfqdn',Name `
                          -SearchRoot $OCSADContainer | 
                Sort-Object msrtcsip-trustedserverfqdn | %{ 
                    $LyncElementProps = @{
                        LyncElement = 'Server'
                        LyncElementType = 'Internal'
                        LyncElementName = $_.Name
                        LyncElementFQDN = $_.'msrtcsip-trustedserverfqdn'
                    }
                    $Lync_Elements += New-Object PSObject -Property $LyncElementProps
                }
                # All edge Lync servers
                Search-AD -Filter '(&(objectClass=msRTCSIP-EdgeProxy))' `
                          -Properties cn,Name,'msrtcsip-edgeproxyfqdn' `
                          -SearchRoot $OCSADContainer | 
                Sort-Object msrtcsip-edgeproxyfqdn | %{
                    $LyncElementProps = @{
                        LyncCN = $_.cn
                        LyncElement = 'Server'
                        LyncElementType = 'Edge'
                        LyncElementName = $_.Name
                        LyncElementFQDN = $_.'msrtcsip-edgeproxyfqdn'
                    }
                    $Lync_Elements += New-Object PSObject -Property $LyncElementProps
                }
                # All Lync global topology servers
                Search-AD -Filter '(&(objectClass=msRTCSIP-GlobalTopologySetting))' `
                          -Properties cn,Name,'msrtcsip-backendserver' `
                          -SearchRoot $OCSADContainer | 
                Sort-Object msrtcsip-backendserver | %{
                    $LyncElementProps = @{
                        LyncCN = $_.cn
                        LyncElement = 'Server'
                        LyncElementType = 'Backend'
                        LyncElementName = $_.Name
                        LyncElementFQDN = $_.'msrtcsip-backendserver'
                    }
                    $Lync_Elements += New-Object PSObject -Property $LyncElementProps
                }
                
                $LyncServerCount = $Lync_Elements.Count
                
                # All Lync pools
                $Lync_Pools = @(Search-AD -Filter '(&(objectClass=msRTCSIP-Pool))' `
                                          -Properties cn,dnshostname,'msrtcsip-pooldisplayname' `
                                          -SearchRoot $OCSADContainer | 
                                    Sort-Object dnshostname)
                $LyncPoolCount = $Lync_Pools.Count
                $Lync_Pools | %{
                    $LyncElementProps = @{
                        LyncCN = $_.cn
                        LyncElement = 'Pool'
                        LyncElementType = 'Pool'
                        LyncElementName = $_.'msrtcsip-pooldisplayname'
                        LyncElementFQDN = $_.dnshostname
                    }
                    $Lync_Elements += New-Object PSObject -Property $LyncElementProps
                }
            }
            else
            {
                $LyncSchema = $false
                $LyncVersion = 'Lync Not Installed'
            }
            #endregion OCS/Lync

            $ForestDataProps = @{
                ForestName = $forest.Name
                ForestFunctionalLevel = $forest.ForestMode
                SchemaMaster = $forest.SchemaRoleOwner
                DomainNamingMaster = $forest.NamingRoleOwner
                Sites = @(($forest.Sites | Sort-Object -Property Name | Select Name))
                Domains = @(($forest.Domains | Sort-Object -Property Name | Select Name))
                DomainControllers = $ForestDCs
                DomainControllersCount = $ForestDCs.Count
                GlobalCatalogs = $ForestGCs
                ExchangeServerCount = $ExchangeServerCount
                LyncADContainer = $Lync_ConfigPartition
                LyncServerCount = $LyncServerCount
                LyncPoolCount = $LyncPoolCount
                ExchangeVersion = [string]$ExchangeVersion
                ExchangeServers = $ExchangeServers
                LyncVersion = [string]$LyncVersion
                LyncElements = $Lync_Elements
                TombstoneLifetime = $TombstoneLife
                RecycleBinEnabled = $RecycleBinEnabled
                DeletedObjectLife = $DeletedObjectLife
                LDAPAdminLimits = $LDAPAdminLimits
            }
            $ForestData = New-Object psobject -Property $ForestDataProps
            
            #region AD site subnets
            Write-Verbose -Message ('Get-ADForestReportInformation {0}: Site Subnets - {1}' -f $forest.Name,$((New-TimeSpan $verbose_timer ($verbose_timer = get-date)).totalseconds))
            $AD_SiteSubnets = @(Search-AD -Filter '(&(objectClass=subnet))' `
                                       -Properties name,location,siteobject `
                                       -SearchRoot $Path_ADSubnets | 
                                Sort-Object Name)
            Foreach ($Subnet in $AD_SiteSubnets)
            {
                if ($Subnet.siteobject -eq $null)
                {
                    $SiteName = ''
                }
                else
                {
                    $SiteName = Get-ADPathName $Subnet.siteobject -GetElement 0 -ValuesOnly
                }
                #$SiteName = [regex]::Match(($Subnet.siteobject).Split(',')[0], '(?<=CN=).+').Value
                $SiteSubnetProps = @{
                    'Name' = $Subnet.name
                    'Location' = $Subnet.location
                    'SiteName' = $SiteName
                }
                $SiteSubnets += New-Object PSObject -Property $SiteSubnetProps
            }
            #endregion AD site subnets

            #region AD Sites
            Write-Verbose -Message ('Get-ADForestReportInformation {0}: Sites - {1}' -f $forest.Name,$((New-TimeSpan $verbose_timer ($verbose_timer = get-date)).totalseconds))
            $Prop_SitesExtended = @('Name',
                                    'DistinguishedName')
            $Prop_SiteConns = @('Name',
                                'DistinguishedName',
                                'Options',
                                'FromServer',
                                'EnabledConnection')
            $AD_SitesExtended = @(Search-AD -Filter '(&(objectClass=site))' `
                                 -Properties $Prop_SitesExtended `
                                 -SearchRoot "LDAP://CN=Sites,$([string]$ConfigNamingContext)")
            $AD_Sites = @([System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest().Sites)

            ForEach($Site In $AD_Sites) 
            {            
                $SiteDN = [string]($AD_SitesExtended | Where {$_.Name -eq $Site.Name}).DistinguishedName
                $AD_SiteConnections = Search-AD -Filter '(&(objectClass=nTDSConnection))' `
                                                -Properties $Prop_SiteConns `
                                                -SearchRoot "LDAP://$SiteDN"
                $SiteConnections = @()
                if ($AD_SiteConnections -ne $null)
                {
                    Foreach ($SiteConnection in $AD_SiteConnections)
                    {
                        $tmpsiteconn = @($SiteConnection.Options)
                        If(($tmpsiteconn.Count -eq 0) -or ($SiteConnection.Options -eq 0) -or ($Site.Options -eq 'None'))
                        {
                            $SiteConnectionOptions = 'None'
                        }
                        Else
                        {
                            $SiteConnectionOptions = [Enum]::Parse('nTDSSiteConnectionSettingsFlags', $SiteConnection.Options)
                        }
                        
                        $FromServer = Get-ADPathName $SiteConnection.FromServer -GetElement 1 -ValuesOnly
                        $Server = Get-ADPathName $SiteConnection.distinguishedName -GetElement 2 -ValuesOnly

                        $SiteConnProps = @{
                            'DistinguishedName' = $SiteConnection.DistinguishedName
                            'Enabled' = $SiteConnection.EnabledConnection
                            'Options' = $SiteConnectionOptions
                            'FromServer' = $FromServer
                            'Server' = $Server
                        }
                        $SiteConnections += New-Object PSObject -Property $SiteConnProps
                        $AllSiteConnections += New-Object PSObject -Property $SiteConnProps
                    }
                }
                if (($Site.InterSiteTopologyGenerator -ne $null) -and ($Site.InterSiteTopologyGenerator -ne 'None'))
                {
                    $ISTGName = $Site.InterSiteTopologyGenerator | %{[string]$_.Name}
                }
                else
                {
                    $ISTGName = 'None'
                }
                $SiteProps = @{
                        'SiteName' = $Site.Name
                        #'DistinguishedName' = $DistinguishedName
                        'Domains' = @($Site.Domains | %{[string]$_.Name})
                        'Options' = $Site.Options
                        'Location' = $Site.Location
                        'ISTG' = $ISTGName
                        'SiteLinks' = @($Site.SiteLinks | %{[string]$_.Name})
                        'AdjacentSites' = @($Site.AdjacentSites | %{[string]$_.Name})
                        'BridgeheadServers' = ($Site.BridgeheadServers | %{[string]$_.Name})
                        'Connections' = $SiteConnections
                        'ConnectionCount' = $SiteConnections.Count
                        'Subnets' = @($Site.Subnets | %{[string]$_.Name})
                        'SubnetCount' = @($Site.Subnets).Count
                        'Servers' = @($Site.Servers | %{[string]$_.Name})
                        'ServerCount' = @($Site.Servers).Count
                }
                $Sites += New-Object PSObject -Property $SiteProps
            }
            #endregion AD Sites

            #region AD Site Links
            Write-Verbose -Message ('Get-ADForestReportInformation {0}: Site Links - {1}' -f $forest.Name,$((New-TimeSpan $verbose_timer ($verbose_timer = get-date)).totalseconds))

            $AD_SitesLinks = @(Search-AD -Filter '(&(objectClass=siteLink))' `
                                         -Properties cn,replInterval,siteList,options `
                                         -SearchRoot $Path_ADSiteLinks -DontJoinAttributeValues)

            Foreach ($SiteLink in $AD_SitesLinks)
            {
                $SitesInSiteLink = @()
                foreach ($Site in $SiteLink.siteList)
                {
                    $SiteName = Get-ADPathName $Site -GetElement 0 -ValuesOnly
                    $SitesInSiteLink += [string]$SiteName
                }
                $SiteLinkProp = @{
                    Name = $SiteLink.cn
                    repInterval = $SiteLink.replInterval
                    Sites = $SitesInSiteLink
                    ChangeNotification = ($SiteLink.options -eq 1)
                }
                $SiteLinks += new-object psobject -Property $SiteLinkProp
            }
            #endregion AD Site Links

            $SitesSummary = New-Object PSObject -Property @{
                'SiteCount' = $Sites.Count
                'SiteSubnetCount' = $SiteSubnets.Count
                'SiteLinkCount' = $SiteLinks.Count
                'SiteConnectionCount' = $AllSiteConnections.Count
                'SitesWithoutSiteConnections' = @($Sites | Where {$_.ConnectionCount -eq 0}).Count
                'SitesWithoutISTG' = @($Sites | Where {$_.ISTG -eq 'None'}).Count
                'SitesWithoutSubnets' = @($Sites | Where {$_.SubnetCount -eq 0}).Count
                'SitesWithoutServers' = @($Sites | Where {$_.ServerCount -eq 0}).Count
            }
            
            #region Domains
            Write-Verbose -Message ('Get-ADForestReportInformation {0}: Domains - {1}' -f $forest.Name,$((New-TimeSpan $verbose_timer ($verbose_timer = get-date)).totalseconds))
            
            ForEach ($Dom in $Forest.Domains) 
            { 
                $CurDomainContext = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext("Domain", $Dom.Name)
                $DomainDN = 'dc=' + $Dom.Name.Replace('.', ',dc=')
                $NetBIOSName = Get-NETBiosName $DomainDN $ConfigNamingContext
                if ($Dom.Name -eq ($Forest.RootDomain).Name)
                {
                    $IsForestRoot = $True
                    $SchemaMaster = $forest.SchemaRoleOwner
                    $DomainNamingMaster = $forest.NamingRoleOwner
                }
                else
                {
                    $IsForestRoot = $False
                    $SchemaMaster = 'NA'
                    $DomainNamingMaster = 'NA'
                }
                try
                {
                    $CurDomain = [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($CurDomainContext)
                    $CurDomainDetails = [ADSI]"LDAP://$($CurDomain)"
                    $lngMaxPwdAge = $CurDomainDetails.ConvertLargeIntegerToInt64(($CurDomainDetails.maxPwdAge).Value)
                    $lngMinPwdAge = $CurDomainDetails.ConvertLargeIntegerToInt64(($CurDomainDetails.minPwdAge).Value)
                    
                    $DomainFunctionalLevel = $Dom.DomainMode
                    # RID Pool info
                    $Path_RIDManager = "LDAP://CN=RID Manager$,CN=System,$DomainDN"
                    $RIDInfo = Search-AD -Filter '(&(objectClass=rIDManager))' `
                                         -Properties rIDAvailablePool `
                                         -SearchRoot $Path_RIDManager
                    $RIDproperty = $RIDInfo.rIDAvailablePool
                    [int32]$totalSIDS = $($RIDproperty) / ([math]::Pow(2,32))
                    [int64]$temp64val = $totalSIDS * ([math]::Pow(2,32))
                    $RIDsIssued = [int32]($($RIDproperty) - $temp64val)
                    $RIDsRemaining = $totalSIDS - $RIDsIssued
                    $PDCEmulator = $Dom.PdcRoleOwner | select Name
                    $RIDMaster = $Dom.RidRoleOwner | select Name
                    $InfrastructureMaster = $Dom.InfrastructureRoleOwner | Select Name
                    $DomainDCs = @($Dom.DomainControllers | Select Name)
                    $lockoutThreshold = $CurDomainDetails.lockoutThreshold
                    $pwdHistoryLength = $CurDomainDetails.pwdHistoryLength
                    $minPwdLength = $CurDomainDetails.minPwdLength
                    $MaxPwdAge = -$lngMaxPwdAge/(600000000 * 1440)
                    $MinPwdAge = -$lngMinPwdAge/(600000000 * 1440)
                    $DomainAccessible = $true
                }
                catch
                {
                    Write-Warning ('Get-ADForestReportInformation: Issue with {0} Domain - {1}' -f $Dom.Name,$_.Exception.Message)
                    $DomainFunctionalLevel = 'NA'
                    $RIDsIssued = 0
                    $RIDsRemaining = 0
                    $PDCEmulator = 'NA'
                    $RIDMaster = 'NA'
                    $InfrastructureMaster = 'NA'
                    $DomainDCs = 'NA'
                    $lockoutThreshold = 0
                    $pwdHistoryLength = 0
                    $minPwdLength = 0
                    $MaxPwdAge = 0
                    $MinPwdAge = 0
                    $DomainAccessible = $false
                }
                $DomainProps = @{
                    DN = $DomainDN
                    Accessible = $DomainAccessible
                    Domain = $Dom.Name
                    NetBIOSName = $NetBIOSName
                    DomainFunctionalLevel = $DomainFunctionalLevel
                    IsForestRoot = $IsForestRoot
                    SchemaMaster = $SchemaMaster
                    DomainNamingMaster = $DomainNamingMaster
                    PDCEmulator = $PDCEmulator
                    RIDMaster = $RIDMaster
                    InfrastructureMaster = $InfrastructureMaster
                    DomainControllers = $DomainDCs
                    lockoutThreshold = $lockoutThreshold
                    pwdHistoryLength = $pwdHistoryLength
                    maxPwdAge = $MaxPwdAge
                    minPwdAge = $MinPwdAge
                    minPwdLength = $minPwdLength
                    RIDSIssued = $RIDsIssued
                    RIDSRemaining = $RIDsRemaining
                    #Sid = $DomSid
                }
                $Domains += New-Object psobject -Property $DomainProps
                if ($DomainAccessible)
                {
                    #region DCs
                    Write-Verbose -Message ('Get-ADForestReportInformation {0}: DCs - {1}' -f $forest.Name,$((New-TimeSpan $verbose_timer ($verbose_timer = get-date)).totalseconds))
                    ForEach ($DC in $Dom.DomainControllers)
                    {
                        $IsGC = $false
                        $IsInfraMaster = $false
                        $IsNamingMaster = $false
                        $IsSchemaMaster = $false
                        $IsRidMaster = $false
                        $IsPdcMaster = $false
                        
                        if ($GCNames -match $DC.Name) { $IsGC = $true }
                        if ($DC.Roles -match 'RidRole') { $IsRidMaster = $true }
                        if ($DC.Roles -match 'PdcRole') { $IsPdcMaster = $true }
                        if ($DC.Roles -match 'InfrastructureRole') { $IsInfraMaster = $true }
                        if ($DC.Roles -match 'SchemaRole') { $IsSchemaMaster = $true }
                        if ($DC.Roles -match 'NamingRole') { $IsNamingMaster = $true }
                        $DCName = [string]$DC.Name
                        $DCName = $DCName.Split('.')[0]
                        $DCProps = @{
                            Forest = ($Dom.Forest).Name
                            Domain = $Dom.Name
                            Site = $DC.SiteName
                            Name = $DCName
                            OS = $DC.OSVersion
                            CurrentTime = $DC.CurrentTime
                            IPAddress = $DC.IPAddress
                          #  HighestUSN = $DC.HighestCommittedUsn
                            IsGC = $IsGC
                            IsInfraMaster = $IsInfraMaster
                            IsNamingMaster = $IsNamingMaster
                            IsSchemaMaster = $IsSchemaMaster
                            IsRidMaster = $IsRidMaster
                            IsPdcMaster = $IsPdcMaster
                        }
                        $DomainControllers += New-Object psobject -Property $DCProps
                    }
                    #endregion DCs
                 
                    #region DFS information
                    $Props_DFSItems = @( 'Name',
                                         'distinguishedName',
                                         'remoteServerName')
                    $Props_DFSGroupTopology = @( 'Name',
                                                 'distinguishedName',
                                                 'msDFSR-ComputerReference')
                    Write-Verbose -Message ('Get-ADForestReportInformation {0}: DFS - {1}' -f $forest.Name,$((New-TimeSpan $verbose_timer ($verbose_timer = get-date)).totalseconds))
                    $DFSDN = "CN=Dfs-Configuration,CN=System,$($DomainDN)"
                    $DFSItems = @(Search-AD -Filter '(&(objectClass=fTDfs))' `
                                            -Properties $Props_DFSItems `
                                            -SearchRoot "LDAP://$DFSDN")
                    foreach ($DFSItem in $DFSItems)
                    {
                        $DomDFSProps = @{
                            Domain = $Dom.Name
                            DN = $DFSItem.distinguishedName
                            Name = $DFSItem.Name
                            RemoteServerName = $DFSItem.remoteServerName -replace ('\*',"")
                        }
                        $DomainDFS += New-Object psobject -Property $DomDFSProps
                    }
                    #endregion DFS information
                    
                    #region DFSR information
                    Write-Verbose -Message ('Get-ADForestReportInformation {0}: DFSR - {1}' -f $forest.Name,$((New-TimeSpan $verbose_timer ($verbose_timer = get-date)).totalseconds))
                    $DFSRDN = "CN=DFSR-GlobalSettings,CN=System,$($DomainDN)"
                    $DFSRGroups = @(Search-AD -Filter '(&(objectClass=msDFSR-ReplicationGroup))' `
                                           -Properties Name,distinguishedName `
                                           -SearchRoot "LDAP://$($DFSRDN)")
                    foreach ($DFSRGroup in $DFSRGroups)
                    {
                        $DFSRGC = @()
                        $DFSRGTop = @()
                        $DFSRGroupContent = @(Search-AD -Filter '(&(objectClass=msDFSR-ContentSet))' `
                                           -Properties Name `
                                           -SearchRoot "LDAP://CN=Content,$($DFSRGroup.distinguishedName)")
                        $DFSRGroupTopology = @(Search-AD -Filter '(&(objectClass=msDFSR-Member))' `
                                           -Properties $Props_DFSGroupTopology `
                                           -SearchRoot "LDAP://CN=Topology,$($DFSRGroup.distinguishedName)")
                        $DFSRGC = @($DFSRGroupContent | %{$_.Name})
                        foreach ($DFSRGroupTopologyItem in $DFSRGroupTopology)
                        {
                            $DFSRServerName = Get-ADPathName $DFSRGroupTopologyItem.'msDFSR-ComputerReference' -GetElement 0 -ValuesOnly
                            $DFSRGTop += [string]$DFSRServerName
                        }
                        $DomDFSRProps = @{
                            Domain = $Dom.Name
                            Name = $DFSRGroup.Name
                            Content = $DFSRGC
                            RemoteServerName = $DFSRGTop
                        }
                        $DomainDFSR += New-Object psobject -Property $DomDFSRProps
                    }
                    #endregion DFSR information

                    #region AD Trusts
                    $ADProps_Trusts = @( 'trusttype',
                                         'trustattributes',
                                         'trustdirection',
                                         'flatname',
                                         'trustpartner',
                                         'whencreated',
                                         'whenchanged')
                    Write-Verbose -Message ('Get-ADForestReportInformation {0}: Trusts - {1}' -f $forest.Name,$((New-TimeSpan $verbose_timer ($verbose_timer = get-date)).totalseconds))
                    $TrustsDN = "CN=System,$($DomainDN)"
                    $AD_Trusts = @(Search-AD -Filter '(&(objectClass=trustedDomain))' `
                                             -SearchRoot "LDAP://$TrustsDN" `
                                             -Properties $ADProps_Trusts)
                    Foreach ($Trust in $AD_Trusts)
                    {
                        switch ($Trust.trusttype) 
                        {
                            1 { $TrustType = 'Downlevel (Windows NT)'}
                            2 { $TrustType = 'Uplevel (Active Directory)'}
                            3 { $TrustType = 'MIT (non-Windows)'}
                            4 { $TrustType = 'DCE (Theoretical)'}
                            default { $TrustType = $Trust.trusttype }
                        }
                        $TrustAttributes = [Enum]::Parse('MSTrustAttributeFlags', $Trust.trustattributes)
                        switch ($Trust.trustdirection)
                        {
                            1 { $TrustDirection = "Inbound"}
                            2 { $TrustDirection = "Outbound"}
                            3 { $TrustDirection = "Bidirectional"}
                            default { $TrustDirection = $Trust.trustdirection }
                        }
                        $TrustProps = @{
                            Domain = $Dom.Name
                            Name = $Trust.flatname
                            TrustedDomain = $Trust.trustpartner
                            Direction = $TrustDirection
                            Attributes = $TrustAttributes
                            TrustType = $TrustType
                            Created = $Trust.whencreated
                            Modified = $Trust.whenchanged
                        }
                        $DomainTrusts += New-Object PSObject -Property $TrustProps
                    }
                    #endregion AD Trusts
                    
                    #region AD Integrated DNS Zones
                    Write-Verbose -Message ('Get-ADForestReportInformation {0}: DNS Zones - {1}' -f $forest.Name,$((New-TimeSpan $verbose_timer ($verbose_timer = get-date)).totalseconds))
                    # Pre-Windows 2003
                    $Path_DNSZoneDN = "LDAP://CN=MicrosoftDNS,CN=System,$DomainDN"
                    $AD_Zones = @(Search-AD -SearchRoot $Path_DNSZoneDN `
                                            -Filter '(objectclass=dnsZone)' `
                                            -Properties name,whencreated,whenchanged,distinguishedName)
                    if ($AD_Zones[0] -ne $null)
                    {
                        Foreach ($DNSZone in $AD_Zones)
                        {
                            $DNSEntryCount = @(Search-AD -SearchRoot "LDAP://$($DNSZone.distinguishedName)" `
                                                         -Filter '(objectclass=dnsNode)')
                            $DNSZoneProps = @{
                                Domain = $Dom.Name
                                AppPartition = 'Legacy'
                                Name  = $DNSZone.name
                                RecordCount = $DNSEntryCount.Count
                                Created = $DNSZone.whencreated
                                Changed = $DNSZone.whenchanged
                            }
                            $DomainDNSZones += New-Object psobject -Property $DNSZoneProps
                        }
                    }
                    $Path_DNSForestZoneDN = "LDAP://DC=ForestDnsZones,$DomainDN"
                    if ([ADSI]::Exists($Path_DNSForestZoneDN))
                    {
                        $AD_ForestZones = @(Search-AD -SearchRoot $Path_DNSForestZoneDN  `
                                                      -Filter '(objectclass=dnsZone)' `
                                                      -Properties name,whencreated,whenchanged,distinguishedName)
                        Foreach ($DNSZone in $AD_ForestZones)
                        {
                            $DNSEntryCount = @(Search-AD -SearchRoot "LDAP://$($DNSZone.distinguishedName)" `
                                                         -Filter '(objectclass=dnsNode)')
                            $DNSZoneProps = @{
                                Domain = $Dom.Name
                                AppPartition = 'Forest'
                                Name  = $DNSZone.name
                                RecordCount = $DNSEntryCount.Count
                                Created = $DNSZone.whencreated
                                Changed = $DNSZone.whenchanged
                            }
                            $DomainDNSZones += New-Object psobject -Property $DNSZoneProps
                        }
                    }
                    
                    $Path_DNSDomainZoneDN = "LDAP://DC=DomainDnsZones,$DomainDN"
                    if ([ADSI]::Exists($Path_DNSDomainZoneDN))
                    {
                        $AD_DomainZones = @(Search-AD -SearchRoot $Path_DNSDomainZoneDN `
                                                      -Filter '(objectclass=dnsZone)' `
                                                      -Properties name,whencreated,whenchanged,distinguishedName)
                        Foreach ($DNSZone in $AD_DomainZones)
                        {
                            $DNSEntryCount = @(Search-AD -SearchRoot "LDAP://$($DNSZone.distinguishedName)" `
                                                         -Filter '(objectclass=dnsNode)')
                            $DNSZoneProps = @{
                                Domain = $Dom.Name
                                AppPartition = 'Domain'
                                Name  = $DNSZone.name
                                RecordCount = $DNSEntryCount.Count
                                Created = $DNSZone.whencreated
                                Changed = $DNSZone.whenchanged
                            }
                            $DomainDNSZones += New-Object psobject -Property $DNSZoneProps
                        }
                    }
                    #endregion AD Integrated DNS Zones
                    
                    #region GPOs
                    Write-Verbose -Message ('Get-ADForestReportInformation {0}: GPOs - {1}' -f $forest.Name,$((New-TimeSpan $verbose_timer ($verbose_timer = get-date)).totalseconds))
                    $AD_DomainGPOs = @(Search-AD -SearchRoot "LDAP://$DomainDN" `
                                                 -Filter '(objectCategory=groupPolicyContainer)' `
                                                 -Properties displayname,whencreated,whenchanged)
                    Foreach ($GPO in $AD_DomainGPOs)
                    {
                        $DomainGPOProps = @{
                            Domain  = $Dom.Name
                            Name    = $GPO.displayname
                            Created = $GPO.whencreated
                            Changed = $GPO.whenchanged
                        }
                        $DomainGPOs += New-Object psobject -Property $DomainGPOProps
                    }
                    #endregion GPOs
                    
                    #region SMS Servers
                    Write-Verbose -Message ('Get-ADForestReportInformation {0}: Domain SMS Servers - {1}' -f $forest.Name,$((New-TimeSpan $verbose_timer ($verbose_timer = get-date)).totalseconds))

                    $SMSServers = @(Search-AD -Filter '(objectclass=mSSMSManagementPoint)' `
                                              -Properties dNSHostName,mSSMSSiteCode,mSSMSVersion,mSSMSDefaultMP,mSSMSDeviceManagementPoint `
                                              -SearchRoot "LDAP://$DomainDN" | 
                                    Select @{n='Domain';e={$Dom.Name}},dNSHostName,mSSMSSiteCode,mSSMSVersion,mSSMSDefaultMP,mSSMSDeviceManagementPoint)
                    #endregion SMS Servers

                    #region SMS Sites
                    Write-Verbose -Message ('Get-ADForestReportInformation {0}: Domain SMS Sites - {1}' -f $forest.Name,$((New-TimeSpan $verbose_timer ($verbose_timer = get-date)).totalseconds))
                    $SMSSites = @()
                    $SMSSiteDetails = @(Search-AD -Filter '(objectclass=mSSMSSite)' `
                                              -Properties Name,mSSMSSiteCode,mSSMSRoamingBoundaries `
                                              -SearchRoot "LDAP://$DomainDN" -DontJoinAttributeValues)
                    $SMSSiteDetails | Foreach {
                        $SMSSiteProps = @{
                            'Domain' = $Dom.Name
                            'Name' = $_.Name
                            'mSSMSSiteCode' = $_.mSSMSSiteCode
                            'mSSMSRoamingBoundaries' = @($_.mSSMSRoamingBoundaries)
                        }
                        $SMSSites += New-Object psobject -Property $SMSSiteProps
                    }
                    #endregion SMS Sites
                    
                    #region NPS Servers
                    Write-Verbose -Message ('Get-ADForestReportInformation {0}: Domain NPS Servers - {1}' -f $forest.Name,$((New-TimeSpan $verbose_timer ($verbose_timer = get-date)).totalseconds))
                    $NPSServers += @((Search-AD -SearchRoot "LDAP://$DomainDN" `
                                              -Filter "(ObjectCategory=group)(Name=RAS and IAS Servers)" `
                                              -Properties member -DontJoinAttributeValues).member | 
                                    Foreach {
                                        [adsi]"LDAP://$($_)" | select @{n='Domain';e={$Dom.Name}},
                                                                      @{n='Name';e={-join $_.name}},
                                                                      @{n='Type';e={$_.schemaclassname}}
                                    })
                    #endregion NPS Servers
                    
                    #region Printers
                    Write-Verbose -Message ('Get-ADForestReportInformation {0}: Domain Printers - {1}' -f $forest.Name,$((New-TimeSpan $verbose_timer ($verbose_timer = get-date)).totalseconds))
                    $DomainPrinters += @(Search-AD -SearchRoot "LDAP://$DomainDN" `
                                              -Filter "(objectCategory=printQueue)" `
                                              -Properties Name,ServerName,printShareName,location,drivername | 
                                        Select @{n='Domain';e={$Dom.Name}},Name,ServerName,printShareName,location,driverName)
                    #endregion Printers
                    #endregion Domains
                }
            }
            
            #region Populate Data
            Write-Verbose -Message ('Get-ADForestReportInformation {0}: Section Data - {1}' -f $forest.Name,$((New-TimeSpan $verbose_timer ($verbose_timer = get-date)).totalseconds))
            $SortedRpts | %{ 
                switch ($_.Section) {
                    'ForestSummary' {
                        $ReportContainer['Sections'][$_]['AllData'][$ForestData.ForestName] = 
                            @($ForestData)
                    }
                    'SiteSummary' {
                        $ReportContainer['Sections'][$_]['AllData'][$ForestData.ForestName] = 
                            @($SitesSummary)
                    }
                    'ForestFeatures' {
                        $ReportContainer['Sections'][$_]['AllData'][$ForestData.ForestName] = 
                            @($ForestData)
                    }
                    'ForestDHCPServers' {
                        $ReportContainer['Sections'][$_]['AllData'][$ForestData.ForestName] = 
                            @($DHCPServers)
                    }
                    'ForestExchangeInfo' {
                        $ReportContainer['Sections'][$_]['AllData'][$ForestData.ForestName] = 
                            @($ForestData.ExchangeServers)
                    }
                    'ForestExchangeFederations' {
                        $ReportContainer['Sections'][$_]['AllData'][$ForestData.ForestName] = 
                            @($ExchangeFederations)
                    }
                    'ForestLyncInfo' {
                        $ReportContainer['Sections'][$_]['AllData'][$ForestData.ForestName] = 
                            @($ForestData.LyncElements)
                    }
                    'ForestSiteSummary' {
                        $ReportContainer['Sections'][$_]['AllData'][$ForestData.ForestName] = 
                            @($Sites)
                    }
                    'ForestSiteDetails' {
                        $ReportContainer['Sections'][$_]['AllData'][$ForestData.ForestName] = 
                            @($Sites)
                    }
                    'ForestSiteSubnets' {
                        $ReportContainer['Sections'][$_]['AllData'][$ForestData.ForestName] = 
                            @($SiteSubnets)
                    }
                    'ForestSiteConnections' {
                        $ReportContainer['Sections'][$_]['AllData'][$ForestData.ForestName] = 
                            @($AllSiteConnections)
                    }
                    'ForestSiteLinks' {
                        $ReportContainer['Sections'][$_]['AllData'][$ForestData.ForestName] = 
                            @($SiteLinks)
                    }
                    'ForestDomains' {
                        $ReportContainer['Sections'][$_]['AllData'][$ForestData.ForestName] = 
                            @($Domains)
                    }
                    'ForestDomainDCs' {
                        $ReportContainer['Sections'][$_]['AllData'][$ForestData.ForestName] = 
                            @($DomainControllers)
                    }
                    'ForestDomainPasswordPolicy' {
                        $ReportContainer['Sections'][$_]['AllData'][$ForestData.ForestName] = 
                            @($Domains)
                    }
                    'ForestDomainTrusts' {
                        $ReportContainer['Sections'][$_]['AllData'][$ForestData.ForestName] = 
                            @($DomainTrusts)
                    }
                    'ForestDomainDFSShares' {
                        $ReportContainer['Sections'][$_]['AllData'][$ForestData.ForestName] = 
                            @($DomainDFS)
                    }
                    'ForestDomainDFSRShares' {
                        $ReportContainer['Sections'][$_]['AllData'][$ForestData.ForestName] = 
                            @($DomainDFSR)
                    }
                    'ForestDomainDNSZones' {
                        $ReportContainer['Sections'][$_]['AllData'][$ForestData.ForestName] = 
                            @($DomainDNSZones)
                    }
                    'ForestDomainGPOs' {
                        $ReportContainer['Sections'][$_]['AllData'][$ForestData.ForestName] = 
                            @($DomainGPOs)
                    }
                    'ForestDomainNPSServers' {
                        $ReportContainer['Sections'][$_]['AllData'][$ForestData.ForestName] = 
                            @($NPSServers)
                    }
                    'ForestDomainSCCMServers' {
                        $ReportContainer['Sections'][$_]['AllData'][$ForestData.ForestName] = 
                            @($SMSServers)
                    }
                    'ForestDomainSCCMSites' {
                        $ReportContainer['Sections'][$_]['AllData'][$ForestData.ForestName] = 
                            @($SMSSites)
                    }
                    'ForestDomainPrinters' {
                        $ReportContainer['Sections'][$_]['AllData'][$ForestData.ForestName] = 
                            @($DomainPrinters)
                    }
                }
            }
            #endregion Populate Data
            
            #region Create Diagrams
            Write-Verbose -Message ('Get-ADForestReportInformation {0}: Diagrams - {1}' -f $forest.Name,$((New-TimeSpan $verbose_timer ($verbose_timer = get-date)).totalseconds))
            # Replication Connection diagram
            $ReplicationDiagram = @'
digraph test {
 rankdir = LR
 
'@
            ForEach ($Site in $Sites)
            {
                ForEach ($ReplCon in $Site.Connections)
                {
                    $ReplicationDiagram += @"    
            
 "$($ReplCon.FromServer)" -> "$($ReplCon.Server)"[label = "Replicates To"]
"@
               }
            }
            $ReplicationDiagram += @'

}
'@
            If ($AD_CreateDiagramSourceFiles)
            {
                $ReplicationDiagram | Out-File -Encoding ASCII '.\ReplicationDiagram.txt'
            }
            If ($AD_CreateDiagrams)
            {
                
                $ReplicationDiagram | & "$($Graphviz_Path)dot.exe" -Tpng -o ReplicationDiagram.png
            }
            
            # Domain Trust Connection diagram
            $TrustDiagram = @'
digraph test {
 rankdir = LR
 
'@
            ForEach ($Trust in $DomainTrusts)
            {
                $TrustDiagram += @"

 "$($Trust.Domain)" -> "$($Trust.TrustedDomain)"[label = "Trusts"]
"@
            }

            $TrustDiagram += @'

}
'@
            If ($AD_CreateDiagramSourceFiles)
            {
                $TrustDiagram | Out-File -Encoding ASCII '.\DomainTrustDiagram.txt'
            }
            If ($AD_CreateDiagrams)
            {
                $TrustDiagram | & "$($Graphviz_Path)dot.exe" -Tpng -o DomainTrustDiagram.png
            }
            
            # Site Adjacency Diagram
            $SiteAdjacencyDiagram = @'
digraph test {
 rankdir = LR
 
'@
            ForEach ($Site in $Sites)
            {
                Foreach ($AdjSite in $Site.AdjacentSites)
                {
                    $SiteAdjacencyDiagram += @"    
        
     "$($Site.SiteName)" -> "$($AdjSite)"[label = "Adjacent To"]
"@
                }
            }

            $SiteAdjacencyDiagram += @'

}
'@
            If ($AD_CreateDiagramSourceFiles)
            {
                $SiteAdjacencyDiagram | Out-File -Encoding ASCII '.\SiteAdjDiagram.txt'
            }
            If ($AD_CreateDiagrams)
            {
                $SiteAdjacencyDiagram | & "$($Graphviz_Path)dot.exe" -Tpng -o SiteAdjDiagram.png
            }
            #endregion Create Diagrams
            
            $ReportContainer['Configuration']['Assets'] = $ForestData.ForestName
            Return $ForestData.ForestName
            Write-Verbose -Message ('Get-ADForestReportInformation {0}: Finished - {1}' -f $forest.Name,$((New-TimeSpan $verbose_timer ($verbose_timer = get-date)).totalseconds))
        }
    }
}

Function Get-ADDomainReportInformation
{
    [CmdletBinding()]
    param
    (
        [Parameter( HelpMessage="The custom report hash variable structure you plan to report upon")]
        $ReportContainer,
        [Parameter( HelpMessage="A sorted hash of enabled report elements.")]
        $SortedRpts
    )
    BEGIN
    {
        try
        {
            $verbose_timer = Get-Date
            $Filter_Users = '(samAccountType=805306368)'
            $Filter_User_Locked = '(samAccountType=805306368)(lockoutTime:1.2.840.113556.1.4.804:=4294967295)'
            $Filter_User_PasswordChangeReq = '(samAccountType=805306368)(pwdLastSet=0)(!useraccountcontrol:1.2.840.113556.1.4.803:=2)'
            $Filter_User_Enabled = '(samAccountType=805306368)(!(userAccountControl:1.2.840.113556.1.4.803:=2))'
            $Filter_User_Disabled = '(samAccountType=805306368)(useraccountcontrol:1.2.840.113556.1.4.803:=2)'
            $Filter_User_NoPasswordReq = '(samAccountType=805306368)(UserAccountControl:1.2.840.113556.1.4.803:=32)'
            $Filter_User_PasswordNeverExpires = '(samAccountType=805306368)(UserAccountControl:1.2.840.113556.1.4.803:=65536)'
            $Filter_User_DialinEnabled = '(samAccountType=805306368)(msNPAllowDialin=TRUE)'
            $Filter_User_UnconstrainedDelegation = '(samAccountType=805306368)(userAccountControl:1.2.840.113556.1.4.803:=524288)'
            $Filter_User_NotTrustedForDelegation = '(samAccountType=805306368)(userAccountControl:1.2.840.113556.1.4.803:=524288)'
            $Filter_User_NoPreauth = '(samAccountType=805306368)(userAccountControl:1.2.840.113556.1.4.803:=4194304)'
            $Filter_User_ControlAccessWithNPS = '(samAccountType=805306368)(!(msNPAllowDialin=*))'

            $RootDSC = [adsi]"LDAP://RootDSE"
            $DomNamingContext = $RootDSC.RootDomainNamingContext
            $ConfigNamingContext = $RootDSC.configurationNamingContext
            $Forest = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()
            $Domains = @($Forest.Domains | %{[string]$_.Name})
            
            $ADConnected = $true
        }
        catch
        {
            $ADConnected = $false
        }
    }
    PROCESS
    {}
    END
    {
        if ($ADConnected)
            {
            Foreach ($Dom in $Domains)
            {
                $CurDomainContext = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext("Domain", $Dom)
                try
                {
                    $CurDomain = [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($CurDomainContext)
                    Write-Verbose -Message ('Get-ADDomainReportInformation: Start - {0}' -f $verbose_timer)
                    Write-Verbose -Message ('Get-ADDomainReportInformation: Domain - {0}' -f $Dom)
                    $UserStats = $null
                    $GroupStats = $null
                    $PrivGroups = $null
                    $PrivGroupMembers = $null
                    $TotalPrivGroupCount = 0
                    
                    $DomainDN = 'dc=' + $Dom.Replace('.', ',dc=')
                    $Splat_SearchAD = @{
                        'SearchRoot' = "LDAP://$DomainDN"
                        'Properties' = $UserAttribs
                    }
                    if ($EXPORTTOCSV_ALLUSERS)
                    {
                        Write-Verbose -Message ('Get-ADDomainReportInformation: Export all users in domain - {0}' -f $Dom)
                        Search-AD -Properties $UserAttribs `
                                  -Filter '(samAccountType=805306368)' `
                                  -SearchRoot "LDAP://$DomainDN" |
                            Normalize-ADUsers -Attribs $UserAttribs | 
                                Append-ADUserAccountControl |
                                    Export-Csv -NoTypeInformation "allusers_$Dom.csv"
                        Write-Verbose -Message ('Get-ADDomainReportInformation: Timer - {0}' -f $((New-TimeSpan $verbose_timer ($verbose_timer = get-date)).totalseconds))
                    }
                    Write-Verbose -Message ('Get-ADDomainReportInformation: Domain User Stats - {0}' -f $Dom)
                    $UserStats = New-Object psobject -Property @{
                        'Total' = @(Search-AD @Splat_SearchAD -Filter $Filter_Users).Count
                        'Enabled' = @(Search-AD @Splat_SearchAD -Filter $Filter_User_Enabled).Count
                        'Disabled' = @(Search-AD @Splat_SearchAD -Filter $Filter_User_Disabled).Count
                        'Locked' = @(Search-AD @Splat_SearchAD -Filter $Filter_User_Locked).Count
                        'PwdDoesNotExpire' = @(Search-AD @Splat_SearchAD -Filter $Filter_User_PasswordNeverExpires).Count
                        'PwdNotRequired' = @(Search-AD @Splat_SearchAD -Filter $Filter_User_NoPasswordReq).Count
                        'PwdMustChange' = @(Search-AD @Splat_SearchAD -Filter $Filter_User_PasswordChangeReq).Count
                        'DialInEnabled' = @(Search-AD @Splat_SearchAD -Filter $Filter_User_DialinEnabled).Count
                        'UnconstrainedDelegation' = @(Search-AD @Splat_SearchAD -Filter $Filter_User_UnconstrainedDelegation).Count
                        'NotTrustedForDelegation' = @(Search-AD @Splat_SearchAD -Filter $Filter_User_NotTrustedForDelegation).Count
                        'NoPreAuthRequired' = @(Search-AD @Splat_SearchAD -Filter $Filter_User_NoPreauth).Count
                        'ControlAccessWithNPS' = @(Search-AD @Splat_SearchAD -Filter $Filter_User_ControlAccessWithNPS).Count
                    }
                    Write-Verbose -Message ('Get-ADDomainReportInformation: Timer - {0}' -f $((New-TimeSpan $verbose_timer ($verbose_timer = get-date)).totalseconds))
                    $AllGroups = @(
                        Search-AD -Properties groupType `
                                  -Filter '(objectClass=group)' `
                                  -SearchRoot "LDAP://$DomainDN"
                    )
                    Write-Verbose -Message ('Get-ADDomainReportInformation: Domain Group Stats - {0}' -f $Dom)
                    $GroupStats = New-Object psobject -Property @{
                        'Total' = $AllGroups.Count
                        'Builtin' = @($AllGroups | Where {$_.groupType -eq '-2147483643'}).Count
                        'UniversalSecurity' = @($AllGroups | Where {$_.groupType -eq '-2147483640'}).Count
                        'UniversalDist' = @($AllGroups | Where {$_.groupType -eq '8'}).Count
                        'GlobalSecurity' = @($AllGroups | Where {$_.groupType -eq '-2147483646'}).Count
                        'GlobalDist' = @($AllGroups | Where {$_.groupType -eq '2'}).Count
                        'DomainLocalSecurity' = @($AllGroups | Where {$_.groupType -eq '-2147483644'}).Count
                        'DomainLocalDist' = @($AllGroups | Where {$_.groupType -eq '4'}).Count
                    }
                    $PrivGroups = @(Get-ADPrivilegedGroups -Domain $Dom)
                    $PrivUsers = @(Get-ADDomainPrivAccounts -Domain $Dom)
                    Write-Verbose -Message ('Get-ADDomainReportInformation: Timer - {0}' -f $((New-TimeSpan $verbose_timer ($verbose_timer = get-date)).totalseconds))
                    if ($EXPORTTOCSV_PRIVUSERS)
                    {
                        Write-Verbose -Message ('Get-ADDomainReportInformation: Exporting privileged users - {0}' -f $Dom)
                        $PrivUsers | Export-Csv -NoTypeInformation "privusers_$Dom.csv"
                        Write-Verbose -Message ('Get-ADDomainReportInformation: Timer - {0}' -f $((New-TimeSpan $verbose_timer ($verbose_timer = get-date)).totalseconds))
                    }
                    $PrivGroupStats = @()
                    
                    ForEach ($PrivGroup in $PrivGroups)
                    {
                        Foreach ($PrivGrp in $AD_PrivilegedGroups)
                        {
                            if ($PrivGrp -eq $PrivGroup.Group)
                            {
                                $PrivGroupCount = @($PrivUsers | Where {$_.PrivGroup -eq $PrivGrp}).Count
                                $TotalPrivGroupCount = $TotalPrivGroupCount + $PrivGroupCount
                                $PrivGroupStatProp = @{
                                    AdminGroup =  $PrivGrp
                                    DisplayName = $PrivGroup.GroupName
                                    MemberCount = $PrivGroupCount
                                }
                                $PrivGroupStats += New-Object psobject -Property $PrivGroupStatProp
                            }
                        }
                    }
                    #region Populate Data
                    $SortedRpts | %{ 
                        switch ($_.Section) {
                            'UserAccountStats1' {
                                $ReportContainer['Sections'][$_]['AllData'][$Dom] = 
                                    @($UserStats)
                            }
                            'UserAccountStats2' {
                                $ReportContainer['Sections'][$_]['AllData'][$Dom] = 
                                    @($UserStats)
                            }
                            'GroupStats' {
                                $ReportContainer['Sections'][$_]['AllData'][$Dom] = 
                                    @($GroupStats)
                            }
                            'PrivGroupStats' {
                                $ReportContainer['Sections'][$_]['AllData'][$Dom] = 
                                    @($PrivGroupStats)
                            }
                            'PrivGroup_EnterpriseAdmins' {
                                $ReportContainer['Sections'][$_]['AllData'][$Dom] = 
                                    @($PrivUsers | 
                                      Where {$_.PrivGroup -eq 'Enterprise Admins'} |
                                      Sort-Object -Property PasswordAge -Descending)
                            }
                            'PrivGroup_SchemaAdmins' {
                                $ReportContainer['Sections'][$_]['AllData'][$Dom] = 
                                    @($PrivUsers | 
                                      Where {$_.PrivGroup -eq 'Schema Admins'} |
                                      Sort-Object -Property PasswordAge -Descending)
                            }
                            'PrivGroup_DomainAdmins' {
                                $ReportContainer['Sections'][$_]['AllData'][$Dom] = 
                                    @($PrivUsers | 
                                      Where {$_.PrivGroup -eq 'Domain Admins'} |
                                      Sort-Object -Property PasswordAge -Descending)
                            }
                            'PrivGroup_Administrators' {
                                $ReportContainer['Sections'][$_]['AllData'][$Dom] = 
                                    @($PrivUsers | 
                                      Where {$_.PrivGroup -eq 'Administrators'} |
                                      Sort-Object -Property PasswordAge -Descending)
                            }
                            'PrivGroup_AccountOperators' {
                                $ReportContainer['Sections'][$_]['AllData'][$Dom] = 
                                    @($PrivUsers | 
                                      Where {$_.PrivGroup -eq 'Account Operators'} |
                                      Sort-Object -Property PasswordAge -Descending)
                            }
                            'PrivGroup_ServerOperators' {
                                $ReportContainer['Sections'][$_]['AllData'][$Dom] = 
                                    @($PrivUsers | 
                                      Where {$_.PrivGroup -eq 'Server Operators'} |
                                      Sort-Object -Property PasswordAge -Descending)
                            }
                            'PrivGroup_BackupOperators' {
                                $ReportContainer['Sections'][$_]['AllData'][$Dom] = 
                                    @($PrivUsers | 
                                      Where {$_.PrivGroup -eq 'Backup Operators'} |
                                      Sort-Object -Property PasswordAge -Descending)
                            }
                            'PrivGroup_PrintOperators' {
                                $ReportContainer['Sections'][$_]['AllData'][$Dom] = 
                                    @($PrivUsers | 
                                      Where {$_.PrivGroup -eq 'Print Operators'} |
                                      Sort-Object -Property PasswordAge -Descending)
                            }
                            'PrivGroup_CertPublishers' {
                                $ReportContainer['Sections'][$_]['AllData'][$Dom] = 
                                    @($PrivUsers | 
                                      Where {$_.PrivGroup -eq 'Cert Publishers'} |
                                      Sort-Object -Property PasswordAge -Descending)
                            }
                        }
                    }
                    #endregion Populate Data
                }
                catch
                {
                    Write-Warning ('Get-ADForestReportInformation: Issue with {0} Domain - {1}' -f $Dom,$_.Exception.Message)
                }
            }
            $ReportContainer['Configuration']['Assets'] = $Domains
            Return $Domains
        }
    }
}

Function New-ReportDelivery
{
    [CmdletBinding()]
    param
    (
        [Parameter( HelpMessage="Report body, typically in HTML format", ValueFromPipeline=$true )]
        [string[]]
        $Report,
        
        [Parameter( ParameterSetName="EmailReport", HelpMessage="Send email of resulting report?")]
        [Parameter( ParameterSetName = "EmailAndSaveReport")]                    
        [switch]
        $SendMail,
        
        [Parameter( ParameterSetName="EmailReport", HelpMessage="Email server to relay report through")]
        [Parameter( ParameterSetName = "EmailAndSaveReport")]
        [string]
        $EmailRelay = ".",
        
        [Parameter( ParameterSetName="EmailReport", HelpMessage="Email sender")]
        [Parameter( ParameterSetName = "EmailAndSaveReport")]
        [string]
        $EmailSender='systemreport@localhost',
        
        [Parameter( ParameterSetName="EmailReport", Mandatory=$true, HelpMessage="Email recipient")]
        [Parameter( ParameterSetName = "EmailAndSaveReport")]
        [string]
        $EmailRecipient,
        
        [Parameter( ParameterSetName="EmailReport", HelpMessage="Email subject")]
        [Parameter( ParameterSetName = "EmailAndSaveReport")]
        [string]
        $EmailSubject='System Report',
        
        [Parameter( ParameterSetName="EmailReport", HelpMessage="Email report(s) as attachement")]
        [Parameter( ParameterSetName = "EmailAndSaveReport")]
        [Parameter( ParameterSetName = "EmailReportAsAttachment")]
        [switch]
        $EmailAsAttachment,
        
        [Parameter( ParameterSetName="EmailReport", HelpMessage="Force email to be sent anonymously?")]
        [Parameter( ParameterSetName = "EmailAndSaveReport")]
        [switch]
        $ForceAnonymous,

        [Parameter( ParameterSetName="SaveReport", HelpMessage="Save the report?")]
        [Parameter( ParameterSetName = "EmailAndSaveReport")]
        [switch]
        $SaveReport,
        
        [Parameter( ParameterSetName="SaveReport", HelpMessage="Zip the report(s).")]
        [Parameter( ParameterSetName = "EmailAndSaveReport")]
        [Parameter( ParameterSetName = "EmailReportAsAttachment")]
        [switch]
        $ZipReport
    )
    BEGIN
    {
        $Reports = @()      # Save a list of report paths in case we will be emailing as attachments
        if ($SaveReport)
        {
            $ReportFormat = 'HTML'
        }
        if ($SaveAsPDF)
        {
            $PdfGenerator = "$((Get-Location).Path)\NReco.PdfGenerator.dll"
            if (Test-Path $PdfGenerator)
            {
                $ReportFormat = 'PDF'
                $PdfGenerator = "$((Get-Location).Path)\NReco.PdfGenerator.dll"
                $Assembly = [Reflection.Assembly]::LoadFrom($PdfGenerator) #| Out-Null
                $PdfCreator = New-Object NReco.PdfGenerator.HtmlToPdfConverter
            }
        }
    }
    PROCESS
    {
        switch ($ReportFormat) {
            'PDF' {
                $ReportOutput = $PdfCreator.GeneratePdf([string]$Report)
                $ReportName = $ReportName -replace '.html','.pdf'
                Add-Content -Value $ReportOutput `
                            -Encoding byte `
                            -Path ($ReportName)
            }
            'HTML' {
                $Report | Out-File $ReportName
            }
        }
        $Reports += $ReportName
    }
    END
    {
        if ($Sendmail)
        {
            $SendMailSplat = @{
                'From' = $EmailSender
                'To' = $EmailRecipient
                'Subject' = $EmailSubject
                'Priority' = 'Normal'
                'smtpServer' = $EmailRelay
                'BodyAsHTML' = $true
            }
            if ($ForceAnonymous)
            {
                $Pass = ConvertTo-SecureString –String 'anonymous' –AsPlainText -Force
                $Creds = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList "NT AUTHORITY\ANONYMOUS LOGON", $pass
                $SendMailSplat.Credential = $creds

            }
            if ($EmailAsAttachment)
            {
                if ($ZipReport)
                {
                    $ZipName = $ReportName -replace '.html','.zip'
                    $Reports | New-ZipFile -ZipFilePath $ZipName -Append
                }
                else
                {
                    $SendMailSplat.Attachments = $Reports
                }
            }
            else
            {
                $SendMailSplat.Body = $Report
            }
            send-mailmessage @SendMailSplat
        }
    }
}

Function New-ReportOutput
{
    [CmdletBinding()]
    param
    (
        [Parameter( HelpMessage="Report body, typically in HTML format",
                    ValueFromPipeline=$true,
                    Mandatory=$true )]
        [string]
        $Report,
        
        [Parameter( HelpMessage="Save the report as a PDF. If the PDF library is not available the default format, HTML, will be used instead.")]
        [switch]
        $SaveAsPDF,
        
        [Parameter( HelpMessage="Postpend timestamp to file name.")]
        [switch]
        $Postpendtimestamp,
        
        [Parameter( HelpMessage="Prepend timestamp to file name.")]
        [switch]
        $Prependtimestamp,
        
        [Parameter( HelpMessage="If output already exists do not overwrite.")]
        [switch]
        $NoOverwrite,
        
        [Parameter( HelpMessage="If saving the report, what do you want to call it?")]
        [string]
        $ReportName="Report.html",
        
        [Parameter( HelpMessage="Where are you saving the report (defaults to local temp directory)?")]
        [string]
        $ReportPath=$env:Temp
    )
    BEGIN
    {
        $timestamp = Get-Date -Format ddmmyyyy-HHMMss
        if ($Prependtimestamp)
        {
            $ReportName="$timestamp_$($ReportName.Split('.')[0]).$($ReportName.Split('.')[1])"
        }
        if ($Postpendtimestamp)
        {
            $ReportName="$($ReportName.Split('.')[0])_$timestamp.$($ReportName.Split('.')[1])"
        }
        $ReportFormat = 'HTML'
        if ($SaveAsPDF)
        {
            $PdfGenerator = "$((Get-Location).Path)\NReco.PdfGenerator.dll"
            if (Test-Path $PdfGenerator)
            {
                try {
                    $ReportFormat = 'PDF'
                    $PdfGenerator = "$((Get-Location).Path)\NReco.PdfGenerator.dll"
                    $Assembly = [Reflection.Assembly]::LoadFrom($PdfGenerator) #| Out-Null
                    $PdfCreator = New-Object NReco.PdfGenerator.HtmlToPdfConverter
                }
                catch {
                    $ReportFormat = 'HTML'
                }
            }
        }
    }
    PROCESS
    {}
    END
    {
        switch ($ReportFormat) {
            'PDF' {
                $ReportOutput = $PdfCreator.GeneratePdf([string]$Report)
                if ($ReportName -notmatch "\.pdf$") 
                {
                    if ($ReportName -match "\.html{0,1}$") 
                    {
                        $ReportName = [System.Text.RegularExpressions.Regex]::Replace($ReportName,"\.html{0,1}$", '.pdf');
                    }
                    else
                    {
                        $ReportName = "$($ReportName).pdf"
                    }
                }
                if ((Test-Path "$ReportPath\$ReportName") -and $NoOverwrite)
                {
                    $retval = $false
                }
                else
                {
                    Add-Content -Value $ReportOutput `
                                -Encoding byte `
                                -Path ("$ReportPath\$ReportName")
                    $retval = "$ReportPath\$ReportName"
                }
            }
            'HTML' {
                if ($ReportName -notmatch "\.html{0,1}$")
                {
                    if ($ReportName -match "\.pdf$") 
                    {
                        $ReportName = [System.Text.RegularExpressions.Regex]::Replace($ReportName,"\.pdf$", '.html');
                    }
                    else
                    {
                        $ReportName = "$($ReportName).html"
                    }
                }
                if ((Test-Path "$ReportPath\$ReportName") -and $NoOverwrite)
                {
                    $retval = $false
                }
                else
                {
                    $Report | Out-File "$ReportPath\$ReportName"
                    $retval = "$ReportPath\$ReportName"
                }
            }
        }
        return $retval
    }
}

Function New-SelfContainedAssetReport
{
    <#
    .SYNOPSIS
        Generates a new asset report from gathered data.
    .DESCRIPTION
        Generates a new asset report from gathered data. The information 
        gathering routine generates the output root elements.
    .PARAMETER ReportContainer
        The custom report hash vaiable structure you plan to report upon.
    .PARAMETER DontGatherData
        If your report container already has all the data from a prior run and
        you are just creating a different kind of report with the same data, enable this switch
    .PARAMETER ReportType
        The report type.
    .PARAMETER HTMLMode
        The HTML rendering type (DynamicGrid or EmailFriendly).
    .PARAMETER ExportToExcel
        Export an excel document.
    .PARAMETER EmailRelay
        Email server to relay report through.
    .PARAMETER EmailSender
        Email sender.
    .PARAMETER EmailRecipient
        Email recipient.
    .PARAMETER EmailSubject
        Email subject.
    .PARAMETER SendMail
        Send email of resulting report?
    .PARAMETER ForceAnonymous
        Force email to be sent anonymously?
    .PARAMETER SaveReport
        Save the report?
    .PARAMETER SaveAsPDF
        Save the report as a PDF. If the PDF library is not available the default format, HTML, will be used instead.
    .PARAMETER OutputMethod
        If saving the report, will it be one big report or individual reports?
    .PARAMETER ReportName
        If saving the report, what do you want to call it? This is only used if one big report is being generated.
    .PARAMETER ReportNamePrefix
        Prepend an optional prefix to the report name?
    .PARAMETER ReportLocation
        If saving multiple reports, where will they be saved?
    .EXAMPLE
        New-SelfContainedAssetReport -ReportContainer $ADForestReport -ExportToExcel `
            -SaveReport `
            -OutputMethod 'IndividualReport' `
            -HTMLMode 'DynamicGrid'

        Description:
        ------------------
        Create a forest active directory report.
    .NOTES
        Version    : 1.0.0 10/15/2013
                     - First release

        Author     : Zachary Loeber

        Disclaimer : This script is provided AS IS without warranty of any kind. I 
                     disclaim all implied warranties including, without limitation,
                     any implied warranties of merchantability or of fitness for a 
                     particular purpose. The entire risk arising out of the use or
                     performance of the sample scripts and documentation remains
                     with you. In no event shall I be liable for any damages 
                     whatsoever (including, without limitation, damages for loss of 
                     business profits, business interruption, loss of business 
                     information, or other pecuniary loss) arising out of the use of or 
                     inability to use the script or documentation. 

        Copyright  : I believe in sharing knowledge, so this script and its use is 
                     subject to : http://creativecommons.org/licenses/by-sa/3.0/
    .LINK
        http://www.the-little-things.net/
    .LINK
        http://nl.linkedin.com/in/zloeber

    #>

    #region Parameters
    [CmdletBinding()]
    PARAM
    (
        [Parameter(Mandatory=$true,
                   HelpMessage='The custom report hash variable structure you plan to report upon')]
        $ReportContainer,
        
        [Parameter(HelpMessage='Do not gather data, this assumes $Reportcontainer has been pre-populated.')]
        [switch]
        $DontGatherData,
        
        [Parameter( HelpMessage='The report type')]
        [string]
        $ReportType = '',
        
        [Parameter( HelpMessage='The HTML rendering type (DynamicGrid or EmailFriendly)')]
        [ValidateSet('DynamicGrid','EmailFriendly')]
        [string]
        $HTMLMode = 'DynamicGrid',
        
        [Parameter( HelpMessage='Export an excel document as part of the output')]
        [switch]
        $ExportToExcel,
        
        [Parameter( HelpMessage='Skip html/pdf generation, only produce an excel report (if switch is enabled)')]
        [switch]
        $NoReport,
        
        [Parameter( HelpMessage='Email server to relay report through')]
        [string]
        $EmailRelay = '.',
        
        [Parameter( HelpMessage='Email sender')]
        [string]
        $EmailSender='systemreport@localhost',
     
        [Parameter( HelpMessage='Email recipient')]
        [string]
        $EmailRecipient='default@yourdomain.com',
        
        [Parameter( HelpMessage='Email subject')]
        [string]
        $EmailSubject='System Report',
        
        [Parameter( HelpMessage='Send email of resulting report?')]
        [switch]
        $SendMail,
        
        [Parameter( HelpMessage="Force email to be sent anonymously?")]
        [switch]
        $ForceAnonymous,

        [Parameter( HelpMessage='Save the report?')]
        [switch]
        $SaveReport,
        
        [Parameter( HelpMessage='Save the data gathered for later processing?')]
        [switch]
        $SaveData,
        
        [Parameter( HelpMessage='Save the data gathered for later processing?')]
        [string]
        $SaveDataFile='DataFile.xml',
        
        [Parameter( HelpMessage='Skip information gathering?')]
        [switch]
        $SkipInformationGathering,
        
        [Parameter( HelpMessage='Save the report as a PDF. If the PDF library is not available the default format, HTML, will be used instead.')]
        [switch]
        $SaveAsPDF,

        [Parameter( HelpMessage='Zip up the report(s)?')]
        [switch]
        $ZipReport,
       
        [Parameter( HelpMessage='How to process report output?')]
        [ValidateSet('OneBigReport','IndividualReport','NoReport')]
        [string]
        $OutputMethod='OneBigReport',
        
        [Parameter( HelpMessage='If saving the report, what do you want to call it?')]
        [string]
        $ReportName='Report.html',
        
        [Parameter( HelpMessage='Prepend an optional prefix to the report name?')]
        [string]
        $ReportNamePrefix='',
        
        [Parameter( HelpMessage='If saving multiple reports, where will they be saved?')]
        [string]
        $ReportLocation='.'
    )
    #endregion Parameters
    BEGIN
    {
        # Use this to keep a splat of our CmdletBinding options
        $VerboseDebug=@{}
        If ($PSBoundParameters.ContainsKey('Verbose')) 
        {
            If ($PSBoundParameters.Verbose -eq $true)
            {
                $VerboseDebug.Verbose = $true
            } 
            else 
            {
                $VerboseDebug.Verbose = $false
            }
        }
        If ($PSBoundParameters.ContainsKey('Debug')) 
        {
            If ($PSBoundParameters.Debug -eq $true)
            {
                $VerboseDebug.Debug = $true 
            } 
            else 
            {
                $VerboseDebug.Debug = $false
            }
        }

        $ReportOutputSplat = @{
            'SaveAsPDF' = $SaveAsPDF
        }
        
        # Some basic initialization
        $AssetReports = ''
        $FinishedReportPaths = @()
        
        if (($ReportType -eq '') -or ($ReportContainer['Configuration']['ReportTypes'] -notcontains $ReportType))
        {
            $ReportType = $ReportContainer['Configuration']['ReportTypes'][0]
        }
        # There must be a more elegant way to do this hash sorting but this also allows
        # us to pull a list of only the sections which are defined and need to be generated.d
        $SortedReports = @()
        Foreach ($Key in $ReportContainer['Sections'].Keys) 
        {
            if ($ReportContainer['Sections'][$Key]['ReportTypes'].ContainsKey($ReportType))
            {
                if ($ReportContainer['Sections'][$Key]['Enabled'] -and 
                    ($ReportContainer['Sections'][$Key]['ReportTypes'][$ReportType] -ne $false))
                {
                    $_SortedReportProp = @{
                                            'Section' = $Key
                                            'Order' = $ReportContainer['Sections'][$Key]['Order']
                                          }
                    $SortedReports += New-Object -Type PSObject -Property $_SortedReportProp
                }
            }
        }
        $SortedReports = $SortedReports | Sort-Object Order
    }
    PROCESS
    {}
    END 
    {
        if ($SkipInformationGathering)
        {
            $AssetNames = @($ReportContainer['Configuration']['Assets'])
        }
        else
        {
            # Information Gathering, Your custom script block must return the 
            #   array of strings (keys) which consist of the Root elements of your
            #   desired reports.
            Write-Verbose -Message ('New-SelfContainedAssetReport: Invoking information gathering script...')
            $AssetNames = 
                @(Invoke-Command ([scriptblock]::Create($ReportContainer['Configuration']['PreProcessing'])))
        }
        if ($AssetNames.Count -ge 1)
        {
            if ($SaveData)
            {
                $ReportContainer | Export-CliXml -Path ($ReportNamePrefix + $SaveDataFile)
            }
            # if we are to export all data to excel, then we do so per section
            #   then per Asset
            if ($ExportToExcel)
            {
                Write-Verbose -Message ('New-SelfContainedAssetReport: Exporting to excel...')
                # First make sure we have data to export, this shlould also weed out non-data sections meant for html
                #  (like section breaks and such)
                $ProcessExcelReport = $false
                foreach ($ReportSection in $SortedReports)
                {
                    if ($ReportContainer['Sections'][$ReportSection.Section]['AllData'].Count -gt 0)
                    {
                        $ProcessExcelReport = $true
                    }
                }

                #region Excel
                if ($ProcessExcelReport)
                {
                    # Create the excel workbook
                    try
                    {
                        $Excel = New-Object -ComObject Excel.Application -ErrorAction Stop
                        $ExcelExists = $True
                        $Excel.visible = $True
                        #Start-Sleep -s 1
                        $Workbook = $Excel.Workbooks.Add()
                        $Excel.DisplayAlerts = $false
                    }
                    catch
                    {
                        Write-Warning ('Issues opening excel: {0}' -f $_.Exception.Message)
                        $ExcelExists = $False
                    }
                    if ($ExcelExists)
                    {
                        # going through every section, but in reverse so it shows up in the correct
                        #  sheet in excel. 
                        $SortedExcelReports = $SortedReports | Sort-Object Order -Descending
                        Foreach ($ReportSection in $SortedExcelReports)
                        {
                            $SectionData = $ReportContainer['Sections'][$ReportSection.Section]['AllData']
                            $SectionProperties = $ReportContainer['Sections'][$ReportSection.Section]['ReportTypes'][$ReportType]['Properties']
                            
                            # Gather all the asset information in the section (remember that each asset may
                            #  be pointing to an array of psobjects)
                            $TransformedSectionData = @()                        
                            foreach ($asset in $SectionData.Keys)
                            {
                                # Get all of our calculated properties, then add in the asset name
                                $TempProperties = $SectionData[$asset] | Select $SectionProperties
                                $TransformedSectionData += ($TempProperties | Select @{n='AssetName';e={$asset}},*)
                            }
                            if (($TransformedSectionData.Count -gt 0) -and ($TransformedSectionData -ne $null))
                            {
                                $temparray1 = $TransformedSectionData | ConvertTo-MultiArray
                                if ($temparray1 -ne $null)
                                {    
                                    $temparray = $temparray1.Value
                                    $starta = [int][char]'a' - 1
                                    
                                    if ($temparray.GetLength(1) -gt 26) 
                                    {
                                        $col = [char]([int][math]::Floor($temparray.GetLength(1)/26) + $starta) + [char](($temparray.GetLength(1)%26) + $Starta)
                                    } 
                                    else 
                                    {
                                        $col = [char]($temparray.GetLength(1) + $starta)
                                    }
                                    
                                    Start-Sleep -s 1
                                    $xlCellValue = 1
                                    $xlEqual = 3
                                    $BadColor = 13551615    #Light Red
                                    $BadText = -16383844    #Dark Red
                                    $GoodColor = 13561798    #Light Green
                                    $GoodText = -16752384    #Dark Green
                                    $Worksheet = $Workbook.Sheets.Add()
                                    $Worksheet.Name = $ReportSection.Section
                                    $Range = $Worksheet.Range("a1","$col$($temparray.GetLength(0))")
                                    $Range.Value2 = $temparray

                                    #Format the end result (headers, autofit, et cetera)
                                    [void]$Range.EntireColumn.AutoFit()
                                    [void]$Range.FormatConditions.Add($xlCellValue,$xlEqual,'TRUE')
                                    $Range.FormatConditions.Item(1).Interior.Color = $GoodColor
                                    $Range.FormatConditions.Item(1).Font.Color = $GoodText
                                    [void]$Range.FormatConditions.Add($xlCellValue,$xlEqual,'OK')
                                    $Range.FormatConditions.Item(2).Interior.Color = $GoodColor
                                    $Range.FormatConditions.Item(2).Font.Color = $GoodText
                                    [void]$Range.FormatConditions.Add($xlCellValue,$xlEqual,'FALSE')
                                    $Range.FormatConditions.Item(3).Interior.Color = $BadColor
                                    $Range.FormatConditions.Item(3).Font.Color = $BadText
                                    
                                    # Header
                                    $range = $Workbook.ActiveSheet.Range("a1","$($col)1")
                                    $range.Interior.ColorIndex = 19
                                    $range.Font.ColorIndex = 11
                                    $range.Font.Bold = $True
                                    $range.HorizontalAlignment = -4108
                                }
                            }
                        }
                        # Get rid of the blank default worksheets
                        $Workbook.Worksheets.Item("Sheet1").Delete()
                        $Workbook.Worksheets.Item("Sheet2").Delete()
                        $Workbook.Worksheets.Item("Sheet3").Delete()
                    }
                }
                #endregion Excel
            }

            foreach ($Asset in $AssetNames)
            {
                # First check if there is any data to report upon for each asset
                $ContainsData = $false
                $SectionCount = 0
                Foreach ($ReportSection in $SortedReports)
                {
                    if ($ReportContainer['Sections'][$ReportSection.Section]['AllData'].ContainsKey($Asset))
                    {
                        $ContainsData = $true
                    }
                }
                
                # If we have any data then we have a report to create
                if ($ContainsData)
                {
                    $AssetReport = ''
                    $AssetReport += $HTMLRendering['ServerBegin'][$HTMLMode] -replace '<0>',$Asset
                    $UsedSections = 0
                    $TotalSectionsPerRow = 0
                    
                    Foreach ($ReportSection in $SortedReports)
                    {
                        if ($ReportContainer['Sections'][$ReportSection.Section]['ReportTypes'][$ReportType])
                        {
                            #region Section Calculation
                            # Use this code to track where we are at in section usage
                            #  and create new section groups as needed
                            
                            # Current section type
                            $CurrContainer = $ReportContainer['Sections'][$ReportSection.Section]['ReportTypes'][$ReportType]['ContainerType']
                            
                            # Grab first two digits found in the section container div
                            $SectionTracking = ([Regex]'\d{1}').Matches($HTMLRendering['SectionContainers'][$HTMLMode][$CurrContainer]['Head'])
                            if (($SectionTracking[1].Value -ne $TotalSectionsPerRow) -or `
                                ($SectionTracking[0].Value -eq $SectionTracking[1].Value) -or `
                                (($UsedSections + [int]$SectionTracking[0].Value) -gt $TotalSectionsPerRow) -and `
                                (!$ReportContainer['Sections'][$ReportSection.Section]['ReportTypes'][$ReportType]['SectionOverride']))
                            {
                                $NewGroup = $true
                            }
                            else
                            {
                                $NewGroup = $false
                                $UsedSections += [int]$SectionTracking[0].Value
                            }
                            
                            if ($NewGroup)
                            {
                                if ($UsedSections -ne 0)
                                {
                                    $AssetReport += $HTMLRendering['SectionContainerGroup'][$HTMLMode]['Tail']
                                }
                                $AssetReport += $HTMLRendering['SectionContainerGroup'][$HTMLMode]['Head']
                                $UsedSections = [int]$SectionTracking[0].Value
                                $TotalSectionsPerRow = [int]$SectionTracking[1].Value
                            }
                            #endregion Section Calculation
                            $AssetReport += Create-ReportSection  -Rpt $ReportContainer `
                                                                  -Asset $Asset `
                                                                  -Section $ReportSection.Section `
                                                                  -TableTitle $ReportContainer['Sections'][$ReportSection.Section]['Title']
                        }
                    }
                    
                    $AssetReport += $HTMLRendering['SectionContainerGroup'][$HTMLMode]['Tail']
                    $AssetReport += $HTMLRendering['ServerEnd'][$HTMLMode]
                    $AssetReports += $AssetReport
                    
                }
                # If we are creating per-asset reports then create one now, otherwise keep going
                if (($OutputMethod -eq 'IndividualReport') -and ($AssetReports -ne ''))
                {
                    $ReportOutputSplat.Report = ($HTMLRendering['Header'][$HTMLMode] -replace '<0>',$Asset) + 
                                                $AssetReports + 
                                                $HTMLRendering['Footer'][$HTMLMode]
                    $ReportOutputSplat.ReportName = $ReportNamePrefix + $Asset + '.html'
                    $ReportOutputSplat.ReportPath = $ReportLocation
            
                    $FinishedReportPath = New-ReportOutput @ReportOutputSplat
                    if ($FinishedReportPath -ne $false)
                    {
                        $FinishedReportPaths += $FinishedReportPath
                    }
                    $AssetReports = ''
                }
            }
            
            # If one big report is getting sent/saved do so now
            if (($OutputMethod -eq 'OneBigReport') -and ($AssetReports -ne ''))
            {
                $FullReport = ($HTMLRendering['Header'][$HTMLMode] -replace '<0>',$Asset) + 
                               $AssetReports + 
                               $HTMLRendering['Footer'][$HTMLMode]
                $ReportOutputSplat.ReportName = $ReportName
                $ReportOutputSplat.ReportPath = $ReportLocation
                $ReportOutputSplat.Report = ($HTMLRendering['Header'][$HTMLMode] -replace '<0>','Multiple Systems') + 
                                                    $AssetReports + 
                                                    $HTMLRendering['Footer'][$HTMLMode]
                $FinishedReportPath = New-ReportOutput @ReportOutputSplat
                if ($FinishedReportPath -ne $false)
                {
                    $FinishedReportPaths += $FinishedReportPath
                }
            }
            
            if ($ZipReport)
            {
                $ZipReportName = "$($ReportOutputSplat.ReportName).zip"
                $FinishedReportPaths | Add-Zip $ZipReportName
                $FinishedReportPaths | Remove-Item
                $FinishedReportPaths = @($ZipReportName)
            }
            if ($SendMail)
            {
                $ReportDeliverySplat = @{
                    'EmailSender' = $EmailSender
                    'EmailRecipient' = $EmailRecipient
                    'EmailSubject' = $EmailSubject
                    'EmailRelay' = $EmailRelay
                    'SendMail' = $SendMail
                    'ForceAnonymous' = $ForceAnonymous
                }
                
                if ($ZipReport -or ($FinishedReportPaths.Count -gt 1))
                {}
                New-ReportDelivery @ReportDeliverySplat
            }
        }
    }
}

Function Load-AssetDataFile ($FileToLoad)
{
    $ReportStructure = Import-Clixml -Path $FileToLoad
    # Export/Import XMLCLI isn't going to deal with our embedded scriptblocks (named expressions)
    # so we manually convert them back to scriptblocks like the rockstars we are...
    Foreach ($Key in $ReportStructure['Sections'].Keys) 
    {
        if ($ReportStructure['Sections'][$Key]['Type'] -eq 'Section')  # if not a section break
        {
            Foreach ($ReportTypeKey in $ReportStructure['Sections'][$Key]['ReportTypes'].Keys)
            {
                $ReportStructure['Sections'][$Key]['ReportTypes'][$ReportTypeKey]['Properties'] | 
                    ForEach {
                        $_['e'] = [Scriptblock]::Create($_['e'])
                    }
            }
        }
    }
    Return $ReportStructure
}
#endregion Functions - Asset Report Project

#region Main
$reportsplat = @{}
if ($LoadData)
{
    if (Test-Path ("forest_" + $DataFile))
    {
        $ADForestReport = Load-AssetDataFile "forest_$DataFile"
    }
    if (Test-Path ("domain_" + $DataFile))
    {
        $ADDomainReport = Load-AssetDataFile "domain_$DataFile"
    }
    $reportsplat.SkipInformationGathering = $true
}
elseif ($SaveData)
{
    $reportsplat.SaveData = $true
    $reportsplat.SaveDataFile = $DataFile
}

if ($Verbosity)
{
    $reportsplat.Verbose = $true
}

switch ($ReportFormat) {
	'HTML' {
        $reportsplat.SaveReport = $true
        $reportsplat.OutputMethod = 'IndividualReport'
	}
	'Excel' {
        $reportsplat.NoReport = $true
        $reportsplat.ReportType = 'ExportToExcel'
        $reportsplat.ExportToExcel = $true
	}
    'Custom' {
        # Fill this out as you see fit
	}
}

switch ($ReportType)
{
    { @("Forest", "ForestAndDomain") -contains $_ } {
        # Create a new forest report
        New-SelfContainedAssetReport `
                -ReportContainer $ADForestReport `
                -ReportNamePrefix 'forest_' `
                @reportsplat
    }
    { @("Domain", "ForestAndDomain") -contains $_ } {
        # Create a new per-domain report
        New-SelfContainedAssetReport `
                -ReportContainer $ADDomainReport `
                -ReportNamePrefix 'domain_' `
                @reportsplat
    }
    'Custom' {
        # Fill out as you wish
    }
}
#endregion Main

move-item ./forest* ./Audit
move-item ./domain* ./Audit

### Zips data
# Write-Host "Zipping data..."
# Calls upon vbs script to zip the data. Said vbs script should be in the same directory as this script.
# cscript zipper.vbs audit Audit.zip


### Creates hash of zipped data

function Get-FolderHash ($folder) {
 dir $folder -Recurse | ?{!$_.psiscontainer} | %{[Byte[]]$contents += [System.IO.File]::ReadAllBytes($_.fullname)}
 $hasher = [System.Security.Cryptography.SHA1]::Create()
 [string]::Join("",$($hasher.ComputeHash($contents) | %{"{0:x2}" -f $_}))
}

$audit_hash = Get-FolderHash .\Audit
$the_date = date
echo "Audit    MD5     $audit_hash     $the_date" > .\Audit_File_Hash.txt


