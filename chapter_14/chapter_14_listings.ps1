# Listing 14-1
Get-ADComputer -Identity $env:COMPUTERNAME -Properties ServicePrincipalNames | Select-Object -ExpandProperty ServicePrincipalNames

# Listing 14-2
$credout = New-LsaCredentialHandle -Package "Kerberos" -UseFlag Outbound
$spn = "HOST/$env:COMPUTERNAME"
$client = New-LsaClientContext -CredHandle $credout -Target $spn
Format-LsaAuthToken -Token $client.Token

# Listing 14-3
$credin = New-LsaCredentialHandle -Package "Kerberos" -UseFlag Inbound
$server = New-LsaServerContext -CredHandle $credin
Update-LsaServerContext -Server $server -Token $client.Token

# Listing 14-4
$credout = New-LsaCredentialHandle -Package "Kerberos" -UseFlag Outbound
$spn = "RestrictedKrbHost/$env:COMPUTERNAME"
$client = New-LsaClientContext -CredHandle $credout -Target $spn
Format-LsaAuthToken -Token $client.Token
$credin = New-LsaCredentialHandle -Package "Kerberos" -UseFlag Inbound
$server = New-LsaServerContext -CredHandle $credin
Update-LsaServerContext -Server $server -Token $client.Token
Use-NtObject($token = Get-LsaAccessToken $server) {
    Get-NtLogonSession $token | Format-Table
}

# Listing 14-5
$client = New-LsaClientContext -CredHandle $credout -Target "RestrictedKrbHost/$env:COMPUTERNAME" -RequestAttribute MutualAuth
Format-LsaAuthToken -Token $client.Token
$server = New-LsaServerContext -CredHandle $credin
Update-LsaServerContext -Server $server -Token $client.Token
$ap_rep = $server.Token
$ap_rep | Format-LsaAuthToken

# Listing 14-6
$credout = New-LsaCredentialHandle -Package "Kerberos" -UseFlag Outbound
$client = New-LsaClientContext -CredHandle $credout -Target "HTTP/graphite"
Format-LsaAuthToken -Token $client.Token

# Listing 14-7
$key = Get-KerberosKey -Password "AlicePassw0rd" -KeyType ARCFOUR_HMAC_MD5 -NameType SRV_INST -Principal "HTTP/graphite@mineral.local"
$key.Key | Out-HexDump

# Listing 14-8
$ap_req = Unprotect-LsaAuthToken -Token $client.Token -Key $key
$ap_req | Format-LsaAuthToken

# Listing 14-16
$sesskey = (Unprotect-LsaAuthToken -Token $ap_req -Key $key).Ticket.Key
Unprotect-LsaAuthToken -Token $ap_rep -Key $sesskey | Format-LsaAuthToken

# Listing 14-17
Set-ADAccountControl -Identity alice -TrustedForDelegation $true
Get-ADUser -Identity alice -Properties TrustedForDelegation | Select-Object TrustedForDelegation

# Listing 14-18
$credout = New-LsaCredentialHandle -Package "Kerberos" -UseFlag Outbound
$client = New-LsaClientContext -CredHandle $credout -Target "HTTP/graphite" -RequestAttribute MutualAuth, Delegate
$key = Get-KerberosKey -Password "AlicePassw0rd" -KeyType ARCFOUR_HMAC_MD5 -NameType SRV_INST -Principal "HTTP/graphite@mineral.local"
Unprotect-LsaAuthToken -Token $client.Token -Key $key | Format-LsaAuthToken

# Listing 14-20
$credin = New-LsaCredentialHandle -Package "Kerberos" -UseFlag Inbound
$server = New-LsaServerContext -CredHandle $credin
Update-LsaServerContext -Server $server -Client $client
Use-NtObject($token = Get-LsaAccessToken $server) {
    Format-NtToken $token -Information
}

# Listing 14-21
$spns = @{'msDS-AllowedToDelegateTo'=@('CIFS/graphite')}
Set-ADUser -Identity alice -Add $spns

# Listing 14-22
Get-ADUser -Identity alice -Properties 'msDS-AllowedToDelegateTo' | Select-Object -Property 'msDS-AllowedToDelegateTo'

# Listing 14-23
Set-ADAccountControl -Identity alice -TrustedToAuthForDelegation $true
Get-ADUser -Identity alice -Properties TrustedToAuthForDelegation | Select-Object -Property TrustedToAuthForDelegation

# Listing 14-24
Show-NtTokenEffective
$token = Get-NtToken -S4U -User bob -Domain MINERAL
Format-NtToken $token
Format-NtToken $token -Information

# Listing 14-25
Set-ADUser -Identity alice -PrincipalsAllowedToDelegateToAccount (Get-ADComputer GRAPHITE)
Get-ADUser -Identity alice -Properties PrincipalsAllowedToDelegateToAccount | Select-Object PrincipalsAllowedToDelegateToAccount
$name = "msDS-AllowedToActOnBehalfOfOtherIdentity"
(Get-ADUser -Identity alice -Properties $name)[$name] | ConvertTo-NtSecurityDescriptor | Format-NtSecurityDescriptor -Summary

# Listing 14-26
Set-ADUser -Identity alice -AccountNotDelegated $true
Get-ADUser -Identity alice -Properties AccountNotDelegated | Select-Object AccountNotDelegated
$client = New-LsaClientContext -CredHandle $credout -Target "HTTP/graphite"
Unprotect-LsaAuthToken -Token $client.Token -Key $key | Format-LsaAuthToken

# Listing 14-27
$credout = New-LsaCredentialHandle -Package "Kerberos" -UseFlag Outbound
$client = New-LsaClientContext -CredHandle $credout -Target bob@mineral.local
Format-LsaAuthToken -Token $client.Token

# Listing 14-28
$credin = New-LsaCredentialHandle -Package "Kerberos" -UseFlag Inbound -ReadCredential
$server = New-LsaServerContext -CredHandle $credin
Update-LsaServerContext -Server $server -Client $client
Format-LsaAuthToken -Token $server.Token

# Listing 14-29
Update-LsaClientContext -Client $client -Server $server
Format-LsaAuthToken -Token $client.Token

# Listing 14-30
Update-LsaServerContext -Server $server -Client $client
Use-NtObject($token = Get-LsaAccessToken $server) {
    Get-NtLogonSession $token | Format-Table
}

# Listing 14-31
Get-KerberosTicket | Select-Object ServiceName, EndTime
Get-KerberosTicket | Select-Object -First 1 | Format-KerberosTicket

# Listing 14-33
Get-ADUser -Filter {
 ObjectClass -eq 'user'
} -Properties ServicePrincipalName | Where-Object ServicePrincipalName -ne $null | Select SamAccountName, ServicePrincipalName

# Listing 14-34
$creds = New-LsaCredentialHandle -Package "Kerberos" -UseFlag Outbound
$client = New-LsaClientContext -CredHandle $creds -Target "MSSQL/topaz.mineral.local"
Format-LsaAuthToken $client

# Listing 14-35
$pwds = "ABC!!!!", "SQLRUS", "DBPassw0rd"
foreach($pwd in $pwds) {
    $key = Get-KerberosKey -Password $pwd -KeyType ARCFOUR_HMAC_MD5 -NameType SRV_INST -Principal "MSSQL/topaz.mineral.local@mineral.local"
    $dec_token = Unprotect-LsaAuthToken -Key $key -Token $client.Token
    if ($dec_token.Ticket.Decrypted) {
        Write-Host "Decrypted ticket with password: $pwd"
        break
    }
}
