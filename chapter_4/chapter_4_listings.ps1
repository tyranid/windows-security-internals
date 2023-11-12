# Listing 4-1
$token = Get-NtToken
$token.User
$token.Close()

# Listing 4-2
$token = Get-NtToken
Format-NtToken $token -All
$token.Close()

# Listing 4-3
$token = Get-NtToken
Invoke-NtToken $token {
 Get-NtDirectory -Path "\"
} -ImpersonationLevel Impersonation

Invoke-NtToken $token {
 Get-NtDirectory -Path "\"
} -ImpersonationLevel Identification
$token.Close()

# Listing 4-4 and 4-5
$token = Get-NtToken
$imp_token = Copy-NtToken -Token $token -ImpersonationLevel Delegation
$imp_token.ImpersonationLevel
$imp_token.TokenType
$pri_token = Copy-NtToken -Token $imp_token -Primary
$pri_token.TokenType
$pri_token.ImpersonationLevel
$imp_token.Close()
$pri_token.Close()
$token.Close()

# Listing 4-6
$token = Get-NtToken
$imp_token = Copy-NtToken -Token $token -ImpersonationLevel Identification
$pri_token = Copy-NtToken -Token $imp_token -Primary
$imp_token.Close()
$token.Close()

# Listing 4-7
Invoke-NtToken -Anonymous {Get-NtToken -Pseudo -Primary | Get-NtTokenSid}
Invoke-NtToken -Anonymous {Get-NtToken -Pseudo -Impersonation | Get-NtTokenSid}
Invoke-NtToken -Anonymous {Get-NtToken -Pseudo -Effective | Get-NtTokenSid}
Invoke-NtToken -Anonymous {Get-NtToken -Pseudo -Effective} | Get-NtTokenSid

# Listing 4-8
$token = Get-NtToken
Get-NtTokenGroup $token
$token.Close()

# Listing 4-9
$token = Get-NtToken
Get-NtTokenSid $token -Owner
Set-NtTokenSid -Owner -Sid "S-1-2-3-4"
$token.Close()

# Listing 4-10
$token = Get-NtToken
Get-NtTokenSid $token -Integrity
$token.Close()

# Listing 4-11
$token = Get-NtToken -Duplicate
Set-NtTokenIntegrityLevel Low -Token $token
Get-NtTokenSid $token -Integrity
$token.Close()

# Listing 4-12
$token = Get-NtToken
Get-NtTokenGroup -Device -Token $token
$token.Close()

# Listing 4-13
$token = Get-NtToken
Get-NtTokenPrivilege -Token $token
$token.Close()

# Listing 4-14
$token = Get-NtToken
Get-NtTokenPrivilege $token -Privileges SeChangeNotifyPrivilege | Format-List
$token.Close()

# Listing 4-15
$token = Get-NtToken -Duplicate
Enable-NtTokenPrivilege SeTimeZonePrivilege -Token $token -PassThru
Disable-NtTokenPrivilege SeTimeZonePrivilege -Token $token -PassThru
$token.Close()

# Listing 4-16
$token = Get-NtToken -Duplicate
Get-NtTokenPrivilege $token -Privileges SeTimeZonePrivilege
Remove-NtTokenPrivilege SeTimeZonePrivilege -Token $token
Get-NtTokenPrivilege $token -Privileges SeTimeZonePrivilege
$token.Close()

# Listing 4-17
$token = Get-NtToken -Duplicate
Enable-NtTokenPrivilege SeChangeNotifyPrivilege
Disable-NtTokenPrivilege SeTimeZonePrivilege
Test-NtTokenPrivilege SeChangeNotifyPrivilege
Test-NtTokenPrivilege SeTimeZonePrivilege, SeChangeNotifyPrivilege -All
Test-NtTokenPrivilege SeTimeZonePrivilege, SeChangeNotifyPrivilege -All -PassResult
$token.Close()

# Listing 4-18
$token = Get-NtToken -Filtered -RestrictedSids RC -SidsToDisable WD -Flags DisableMaxPrivileges
Get-NtTokenGroup $token -Attributes UseForDenyOnly
Get-NtTokenGroup $token -Restricted
Get-NtTokenPrivilege $token
$token.Restricted
$token.Close()

# Listing 4-19
$token = Get-NtToken -Filtered -RestrictedSids WR -Flags WriteRestricted
Get-NtTokenGroup $token -Restricted
$token.Restricted
$token.WriteRestricted
$token.Close()

# Listing 4-20
Get-NtSid -PackageName 'my_package' -ToSddl
Get-NtSid -PackageName 'my_package' -RestrictedPackageName "CHILD" -ToSddl
Get-NtSid -KnownSid CapabilityInternetClient -ToSddl
Get-NtSid -CapabilityName registryRead -ToSddl
Get-NtSid -CapabilityName registryRead -CapabilityGroup -ToSddl

# Listing 4-21
$token = Get-NtToken -LowBox -PackageSid 'my_package' -CapabilitySid "registryRead", "S-1-15-3-1"
Get-NtTokenGroup $token -Capabilities | Select-Object Name
$package_sid = Get-NtTokenSid $token -Package -ToSddl
$package_sid
Get-NtTokenIntegrityLevel $token
$token.Close()

# Listing 4-22
$token = Get-NtToken
$token.Elevated
$token.Close()

# Listing 4-23
ls C:\Windows\System32\*.exe | Get-Win32ModuleManifest

# Listing 4-24
Use-NtObject($token = Get-NtToken -Linked) {
 Format-NtToken $token -Group -Privilege -Integrity -Information
}

# Listing 4-25
Use-NtObject($token = Get-NtToken) {
 Format-NtToken $token -Group -Privilege -Integrity -Information
}

# Listing 4-26
$process = Start-Process "osk.exe" -PassThru
$token = Get-NtToken -ProcessId $process.Id
$token.UIAccess
$token.Close()

# Listing 4-27
$file = New-NtFile -Win32Path C:\Windows\hello.txt -Access GenericWrite
$token = Get-NtToken
$token.VirtualizationEnabled = $true
$file = New-NtFile -Win32Path C:\Windows\hello.txt -Access GenericWrite
$file.Win32PathName
$file.Close()
$token.VirtualizationEnabled = $fa
$token.Close()

# Listing 4-28
Show-NtTokenEffective -SecurityAttributes

# Listing 4-30
$token = Get-NtToken -Filtered -Flags DisableMaxPrivileges
Use-NtObject($proc = New-Win32Process notepad -Token $token) {
 $proc | Out-Host
}
$token2 = Get-NtToken -Filtered -Flags DisableMaxPrivileges -Token $token
$proc = New-Win32Process notepad -Token $token2
$token2.Close()
$token.Close()

# Listing 4-31
$proc = Get-NtProcess -Current
$token = Get-NtToken -Duplicate -TokenType Primary
Set-NtToken -Process $proc -Token $token
$token.Close()

# Listing 4-32
$token = Get-NtToken -Duplicate
Test-NtTokenImpersonation $token
Set-NtTokenIntegrityLevel -IntegrityLevel Low
Test-NtTokenImpersonation $token
Test-NtTokenImpersonation $token -ImpersonationLevel Identification

# Listing 4-33
$ps = Get-NtProcess -Access QueryLimitedInformation -FilterScript {
 Use-NtObject($token = Get-NtToken -Process $_ -Access Query) {
    $token.UIAccess
 }
}
$ps
$ps.Close()

# Listing 4-34
function Get-ImpersonationTokens {
 $hs = Get-NtHandle -ObjectType Token
 foreach($h in $hs) {
    try {
        Use-NtObject($token = Copy-NtObject -Handle $h) {
            if (Test-NtTokenImpersonation -Token $token) {
                Copy-NtObject -Object $token
            }
        }
    } catch {
    }
  }
}
$tokens = Get-ImpersonationTokens
$tokens | Where-Object Elevated
