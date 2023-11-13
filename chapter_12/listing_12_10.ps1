#Requires -RunAsAdministrator

# Listing 12-10
$password = Read-Host -AsSecureString -Prompt "Password"
$user = New-LocalUser -Name "Test" -Password $password
$sid = $user.Sid.Value
$token = Get-NtToken -Logon -User $user.Name -Password $password -LogonType Interactive
$token.ElevationType
$token.Close()
Add-NtAccountRight -Privilege SeDebugPrivilege -Sid $sid
$token = Get-NtToken -Logon -User $user.Name -SecurePassword $password -LogonType Interactive
Enable-NtTokenPrivilege -Token $token SeDebugPrivilege -PassThru
$token.ElevationType
$token.Close()
$token = Get-NtToken -Logon -User $user.Name -SecurePassword $password -LogonType Network
Enable-NtTokenPrivilege -Token $token SeDebugPrivilege -PassThru
$token.ElevationType
$token.Close()
Add-NtAccountRight -LogonType SeDenyInteractiveLogonRight -Sid $sid
Add-NtAccountRight -LogonType SeBatchLogonRight -Sid $sid
Get-NtToken -Logon -User $user.Name -SecurePassword $password -LogonType Interactive
$token = Get-NtToken -Logon -User $user.Name -SecurePassword $password -LogonType Batch
Get-NtTokenGroup $token | Where-Object {$_.Sid.Name -eq "NT AUTHORITY\BATCH"}
$token.Close()
Remove-NtAccountRight -Privilege SeDebugPrivilege -Sid $sid
Remove-NtAccountRight -LogonType SeDenyInteractiveLogonRight -Sid $sid
Remove-NtAccountRight -LogonType SeBatchLogonRight -Sid $sid
Remove-LocalUser $user