#Requires -RunAsAdministrator

# Listing 15-13
Enable-NtTokenPrivilege SeDebugPrivilege
$token = Use-NtObject($ps = Get-NtProcess -Name "winlogon.exe" -Access QueryLimitedInformation) {
    $p = $ps | Select-Object -First 1
    Get-NtToken -Process $p -Duplicate
}
$user_token = Get-NtToken
$ba = Invoke-NtToken -Token $token 
    Enable-NtTokenPrivilege SeTrustedCredmanAccessPrivilege
    Backup-Win32Credential -Token $user_token
}
Select-BinaryString -Byte $ba -Type Unicode |
Select-String "^Domain:" -Context 0, 2