#Requires -RunAsAdministrator
Enable-NtTokenPrivilege SeDebugPrivilege
$imp = Use-NtObject($p = Get-NtProcess -Name lsass.exe) {
 Get-NtToken -Process $p -Duplicate
}
Enable-NtTokenPrivilege SeCreateTokenPrivilege -Token $imp
$token = Invoke-NtToken $imp {
 New-NtToken -User "S-1-0-0" -Group "S-1-1-0"
}
Format-NtToken $token -User -Group
$token.Close()