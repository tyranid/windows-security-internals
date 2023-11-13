#Requires -RunAsAdministrator

# Listing 13-12
$credout = Invoke-NtToken -System {
    New-LsaCredentialHandle -Package "NTLM" -UseFlag Outbound
}
