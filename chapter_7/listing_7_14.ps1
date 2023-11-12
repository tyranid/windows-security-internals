#Requires -RunAsAdministrator
$owner = Get-NtSid -KnownSid Null
$sd = New-NtSecurityDescriptor -Type Mutant -Owner $owner -Group $owner -EmptyDacl
Enable-NtTokenPrivilege SeTakeOwnershipPrivilege
Get-NtGrantedAccess $sd -Access WriteOwner -PassResult
Disable-NtTokenPrivilege SeTakeOwnershipPrivilege
Get-NtGrantedAccess $sd -Access WriteOwner -PassResult