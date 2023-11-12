#Requires -RunAsAdministrator

# Listing 10-16
$policy = Get-LsaPolicy -Access ViewLocalInformation
Get-LsaAccount -Policy $policy -InfoOnly
$sid = Get-NtSid -KnownSid BuiltinUsers
$account = Get-LsaAccount -Policy $policy -Sid $sid
Format-NtSecurityDescriptor -Object $account -Summary

$account.Privileges
$account.SystemAccess