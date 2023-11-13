#Requires -RunAsAdministrator

# Listing 12-4
$password = Read-Host -AsSecureString -Prompt "Password"
$token = Get-NtToken -Logon -User user -Domain $env:COMPUTERNAME -Password $password -LogonType Network
Get-NtLogonSession -Token $token
$token.Close()