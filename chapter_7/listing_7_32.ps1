#Requires -RunAsAdministrator
# Listing 7-32
$sd = New-NtSecurityDescriptor
$attr = New-NtSecurityAttribute "EnableSecure" -LongValue 1
Add-NtSecurityDescriptorAce $sd -Type ResourceAttribute -Sid "WD" -SecurityAttribute $attr -Flags ObjectInherit, ContainerInherit
$capid = "S-1-17-3260955821-1180564752-1365479606-2616254494"
Add-NtSecurityDescriptorAce $sd -Type ScopedPolicyId -Sid $capid -Flags ObjectInherit, ContainerInherit
Format-NtSecurityDescriptor $sd -SecurityInformation Attribute, Scope
Enable-NtTokenPrivilege SeSecurityPrivilege
Set-Win32SecurityDescriptor $sd MACHINE\SOFTWARE\PROTECTED -Type RegistryKey -SecurityInformation Scope, Attribute