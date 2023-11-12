#Requires -RunAsAdministrator
$dir = Get-NtDirectory "\BaseNamedObjects" -Access AccessSystemSecurity
Enable-NtTokenPrivilege SeSecurityPrivilege
$dir = Get-NtDirectory "\BaseNamedObjects" -Access AccessSystemSecurity
$dir.GrantedAccess