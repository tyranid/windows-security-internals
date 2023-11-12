#Requires -RunAsAdministrator

# Listing 9-1
Get-NtAuditPolicy

# Listing 9-2
Get-NtAuditPolicy | Select-Object Name, Id

# Listing 9-3
Get-NtAuditPolicy -Category System -ExpandCategory

# Listing 9-4
Enable-NtTokenPrivilege SeSecurityPrivilege
Set-NtAuditPolicy -Category ObjectAccess -Policy Success, Failure -PassThru

Set-NtAuditPolicy -Category ObjectAccess -Policy None

# Listing 9-5
Enable-NtTokenPrivilege SeSecurityPrivilege
$sid = Get-NtSid
Set-NtAuditPolicy -Category ObjectAccess -User $sid -UserPolicy SuccessExclude
Get-NtAuditPolicy -User $sid -Category ObjectAccess -ExpandCategory

Set-NtAuditPolicy -Category ObjectAccess -User $sid -UserPolicy None

# Listing 9-6
Get-NtAuditPolicy -AllUser

# Listing 9-7
Enable-NtTokenPrivilege SeSecurityPrivilege
$sd = Get-NtAuditSecurity
Format-NtSecurityDescriptor $sd -Summary -MapGeneric

# Listing 9-8
Enable-NtTokenPrivilege SeSecurityPrivilege
$sd = Get-NtAuditSecurity
Add-NtSecurityDescriptorAce $sd -Sid "LA" -Access GenericAll
Set-NtAuditSecurity $sd

# Listing 9-9
$sd = New-NtSecurityDescriptor -Type Mutant
Add-NtSecurityDescriptorAce $sd -Type Audit -Access GenericAll -Flags SuccessfulAccess, FailedAccess -KnownSid World -MapGeneric
Enable-NtTokenPrivilege SeSecurityPrivilege
Clear-EventLog -LogName "Security"
Use-NtObject($m = New-NtMutant "ABC" -Win32Path -SecurityDescriptor $sd) {
 Use-NtObject($m2 = Get-NtMutant "ABC" -Win32Path) {
 }
}

# Listing 9-10
$filter = @{logname = 'Security'; id = @(4656)}
Get-WinEvent -FilterHashtable $filter | Select-Object -ExpandProperty Message

# Listing 9-11
Get-WinEvent -FilterHashtable $filter | Select-Object KeywordsDisplayNames

# Listing 9-12
$filter = @{logname = 'Security'; id = @(4658)}
Get-WinEvent -FilterHashtable $filter | Select-Object -ExpandProperty Message

# Listing 9-13
Enable-NtTokenPrivilege SeAuditPrivilege -WarningAction Stop
$owner = Get-NtSid -KnownSid Null
$sd = New-NtSecurityDescriptor -Type Mutant -Owner $owner -Group $owner
Add-NtSecurityDescriptorAce $sd -KnownSid World -Access GenericAll -MapGeneric
Add-NtSecurityDescriptorAce $sd -Type Audit -Access GenericAll -Flags SuccessfulAccess, FailedAccess -KnownSid World -MapGeneric
$handle = 0x1234
$r = Get-NtGrantedAccess $sd -Audit -SubsystemName "SuperSecurity" -ObjectTypeName "Badger" -ObjectName "ABC" -ObjectCreation -HandleId $handle -PassResult
Write-NtAudit -Close -SubsystemName "SuperSecurity" -HandleId $handle -GenerateOnClose:$r.GenerateOnClose

# Listing 9-14
Enable-NtTokenPrivilege SeSecurityPrivilege
$sd = New-NtSecurityDescriptor -Type File
Add-NtSecurityDescriptorAce $sd -Type Audit -KnownSid World -Access WriteData -Flags SuccessfulAccess
Set-NtAuditSecurity -GlobalSacl File -SecurityDescriptor $sd
Get-NtAuditSecurity -GlobalSacl File | Format-NtSecurityDescriptor -SecurityInformation Sacl -Summary

# Listing 9-15
Enable-NtTokenPrivilege SeSecurityPrivilege
$sd = Get-NtAuditSecurity
Set-NtSecurityDescriptorOwner $sd -KnownSid LocalSystem
Set-NtSecurityDescriptorGroup $sd -KnownSid LocalSystem
Get-NtGrantedAccess $sd -PassResult
Use-NtObject($token = Get-NtToken -Filtered -Flags LuaToken) {
 Get-NtGrantedAccess $sd -Token $token -PassResult
}

# Listing 9-16
Enable-NtTokenPrivilege SeDebugPrivilege, SeSecurityPrivilege
$ps = Get-NtProcess -Access QueryLimitedInformation, AccessSystemSecurity -FilterScript {
    $sd = Get-NtSecurityDescriptor $_ -SecurityInformation Sacl
    $sd.HasAuditAce
}
$ps | Format-NtSecurityDescriptor -SecurityInformation Sacl
$ps.Close()