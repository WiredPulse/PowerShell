#Uses WMI to uninstall a program. It can be slow but does support the -computername switch.

wmic product where "name like 'UniversalForwarder'" call uninstall /nointeractive