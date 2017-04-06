<#
.SYNOPSIS
    This script will return the SID for all Domain computer accounts.

.OUTPUTS
        Name                         SID                                                                                       
        ----                         ---                                                                                       
        DC1-lab                     S-1-5-21-3259443097-3599676039-1305684680-1000                                            
        WK1-lab                     S-1-5-21-3259443097-3599676039-1305684680-1103                                            
        WK2-lab                     S-1-5-21-3259443097-3599676039-1305684680-1107                                            
                                          
.LINK
    
#>


import-module activedirectory
get-adcomputer -filter * | select Name, SID