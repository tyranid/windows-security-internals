#Requires -RunAsAdministrator

# Listing 12-12
$domain_sid = Get-NtSid "S-1-5-99"
$group_sid = Get-NtSid -BaseSid $domain_sid -RelativeIdentifier
$user_sid = Get-NtSid -BaseSid $domain_sid -RelativeIdentifier
$domain = "CUSTOMDOMAIN"
$group = "ALL USERS"
$user = "USER"
$token = Invoke-NtToken -System {
 Add-NtSidName -Domain $domain -Sid $domain_sid -Register
 Add-NtSidName -Domain $domain -Name $group -Sid $group_sid -Register
 Add-NtSidName -Domain $domain -Name $user -Sid $user_sid -Register
 Add-NtAccountRight -Sid $user_sid -LogonType SeInteractiveLogonRight
 Get-NtToken -Logon -Domain $domain -User $user -LogonProvider Virtual -LogonType Interactive
 Remove-NtAccountRight -Sid $user_sid -LogonType SeInteractiveLogonRight
 Remove-NtSidName -Sid $domain_sid -Unregister
}
Format-NtToken $token -User -Group
$token.Close()