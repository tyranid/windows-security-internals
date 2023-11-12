#Requires -RunAsAdministrator
$new_dir = New-NtDirectory "ABC" -Win32Path
Get-NtSecurityDescriptor $new_dir | Select {$_.Owner.Sid.Name}
Enable-NtTokenPrivilege SeRestorePrivilege
Use-NtObject($dir = Get-NtDirectory "ABC" -Win32Path -Access WriteOwner) {
  $sid = Get-NtSid -KnownSid World
  $sd = New-NtSecurityDescriptor -Owner $sid
  Set-NtSecurityDescriptor $dir $sd -SecurityInformation Owner
}
Get-NtSecurityDescriptor $new_dir | Select {$_.Owner.Sid.Name}
$new_dir.Close()