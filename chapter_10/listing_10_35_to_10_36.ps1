#Requires -RunAsAdministrator

Enable-NtTokenPrivilege SeBackupPrivilege
New-PSDrive -PSProvider NtObjectManager -Name SEC -Root ntkey:MACHINE

# Listing 10-35
ls -Depth 1 -Recurse SEC:\SECURITY

# Listing 10-36
ls SEC:\SECURITY\Policy\Secrets
ls SEC:\SECURITY\Policy\Secrets\DPAPI_SYSTEM
$key = Get-Item SEC:\SECURITY\Policy\Secrets\DPAPI_SYSTEM\CurrVal
$key.DefaultValue.Data | Out-HexDump -ShowAll