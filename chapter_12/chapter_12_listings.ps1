# Listing 12-1
Get-LsaPackage | Select-Object Name, Comment

# Listing 12-3
Get-NtConsoleSession

# Listing 12-4
$password = Read-Host -AsSecureString -Prompt "Password"
$token = Get-NtToken -Logon -User user -Domain $env:COMPUTERNAME -Password $password -LogonType Network
Get-NtLogonSession -Token $token

# Listing 12-5
Get-NtTokenId -Authentication
Get-NtTokenId -Token $token -Origin

# Listing 12-6
Get-NtTokenIntegrityLevel -Token $token
Test-NtTokenImpersonation $token
Set-NtTokenIntegrityLevel -Token $token Medium
Test-NtTokenImpersonation $token

# Listing 12-7
$token = Get-NtToken -Logon -User user -Domain $env:COMPUTERNAME -Password $password -LogonType Interactive
New-Win32Process cmd.exe -Token $token

# Listing 12-8
$creds = Read-LsaCredential
$proc = New-Win32Process -CommandLine cmd.exe -Credential $creds
$proc.Process.User