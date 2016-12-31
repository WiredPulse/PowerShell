<#
SYNOPSIS:
    Gets domain trust information

UNDERSTANDING OUTPUT:
    TrustedAttributes = Direction of Trust
        1 = Non-Transitive
        2 = Transitive

    TrustedDirection = Direction of Trust
        1 = Incoming only
        2 = Outgoing only
        3 = Two-way
    
#>

Get-WmiObject -Class Microsoft_DomainTrustStatus -Namespace ROOT\MicrosoftActiveDirectory | Select-Object PSComputername, TrustedDomain, TrustAttributes, TrustDirection, TrustType |fl
