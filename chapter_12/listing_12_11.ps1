#Requires -RunAsAdministrator

$curr_sid = Get-NtSid
if ($curr_sid.ToString() -ne "S-1-5-18") {
     throw "Must be run as the SYSTEM user."
}

# Listing 12-11
#$username = "GRAPHITE\user"
$username = "BORON\tyranid"
$console = Get-NtConsoleSession | Where-Object FullyQualifiedUserName -eq $username
$token = Get-NtToken -Duplicate -TokenType Primary
Enable-NtTokenPrivilege SeTcbPrivilege
$token.SessionId = $console.SessionId
$cmd = "cmd.exe"
$proc = New-Win32Process $cmd -Token $token -Desktop "WinSta0\Default" -CreationFlags NewConsole
$proc.Process.SessionId -eq $console.SessionId
$proc.Dispose()
$token.Close()