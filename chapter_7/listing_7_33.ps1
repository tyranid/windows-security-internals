# Listing 7-33
Import-Module ".\chapter_7_access_check_impl.psm1" -Force
$sd = New-NtSecurityDescriptor "O:SYG:SYD:(A;;GR;;;WD)" -Type File -MapGeneric
$type = Get-NtType File
$desired_access = Get-NtAccessMask -FileAccess GenericRead -MapGenericRights
Get-PSGrantedAccess -SecurityDescriptor $sd -GenericMapping $type.GenericMapping -DesiredAccess $desired_access
$desired_access = Get-NtAccessMask -FileAccess WriteOwner
Get-PSGrantedAccess -SecurityDescriptor $sd -GenericMapping $type.GenericMapping -DesiredAccess $desired_access
$token = Get-NtToken -Linked
Enable-NtTokenPrivilege -Token $token SeTakeOwnershipPrivilege
Get-PSGrantedAccess -Token $token -SecurityDescriptor $sd -GenericMapping $type.GenericMapping -DesiredAccess 0x80000