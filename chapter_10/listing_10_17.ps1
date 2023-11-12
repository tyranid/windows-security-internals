#Requires -RunAsAdministrator

# Listing 10-17
$policy = Get-LsaPolicy
$secret = Get-LsaSecret -Policy $policy -Name "DPAPI_SYSTEM"
Format-NtSecurityDescriptor $secret -Summary
$value = $secret.Query()
$value
$value.CurrentValue | Out-HexDump -ShowAll