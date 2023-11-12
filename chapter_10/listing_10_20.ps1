#Requires -RunAsAdministrator

# Listing 10-20
$domain_sid = Get-NtSid -SecurityAuthority Nt -RelativeIdentifier 99
$user_sid = Get-NtSid -BaseSid $domain_sid -RelativeIdentifier 1000
$domain = "CUSTOMDOMAIN"
$user = "USER"
Invoke-NtToken -System {
    Add-NtSidName -Domain $domain -Sid $domain_sid -Register
    Add-NtSidName -Domain $domain -Name $user -Sid $user_sid -Register
    Use-NtObject($policy = Get-LsaPolicy) {
        Get-LsaName -Policy $policy -Sid $domain_sid, $user_sid
    }
    Remove-NtSidname -Sid $user_sid -Unregister
    Remove-NtSidName -Sid $domain_sid -Unregister
}