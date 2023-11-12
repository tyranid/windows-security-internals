# Listing 8-1
$path = "\BaseNamedObjects\ABC\QRS\XYZ\OBJ"
$os = New-NtMutant $path -CreateDirectories
Enable-NtTokenPrivilege SeChangeNotifyPrivilege
Test-NtObject $path
$sd = New-NtSecurityDescriptor -EmptyDacl
Set-NtSecurityDescriptor "\BaseNamedObjects\ABC\QRS" $sd Dacl
Test-NtObject $path
Disable-NtTokenPrivilege SeChangeNotifyPrivilege
Test-NtObject $path
Test-NtObject "OBJ" -Root $os[1]
$os.Close()

# Listing 8-2
function Get-FastTraverseCheck {
 Param(
    $TokenFlags,
    $SecurityDescriptor,
    $AccessMask
 )
 if ($SecurityDescriptor.DaclNull) {
    return $true
 }
 if (($TokenFlags -band "IsFiltered, IsRestricted") -ne 0) {
    return $false
 }
 $sid = Get-Ntsid -KnownSid World
 foreach($ace in $SecurityDescriptor.Dacl) {
     if ($ace.IsInheritedOnly -or !$ace.IsAccessGranted($AccessMask)) {
        continue
     }
     if ($ace.IsDeniedAce) {
        return $false
     }
     if ($ace.IsAllowedAce -and $ace.Sid -eq $sid) {
        return $true
     }
 }
 return $false
}

# Listing 8-3
$token = Get-NtToken -Pseudo -Primary
$token.Flags
$token.ElevationType

# Listing 8-4
$sd = New-NtSecurityDescriptor -EmptyDacl
$m = New-NtMutant -Access ModifyState, ReadControl -SecurityDescriptor $sd
Use-NtObject($m2 = Copy-NtObject -Object $m) {
 $m2.GrantedAccess
}
$mask = Get-NtAccessMask -MutantAccess ModifyState
Use-NtObject($m2 = Copy-NtObject -Object $m -DesiredAccessMask $mask) {
 $m2.GrantedAccess
}
Use-NtObject($m2 = Copy-NtObject -Object $m -DesiredAccess GenericAll) {
 $m2.GrantedAccess
}
$m.Close()

# Listing 8-5
$m = New-NtMutant -Access ModifyState
Use-NtObject($m2 = Copy-NtObject -Object $m -DesiredAccess GenericAll) {
 $m2.GrantedAccess
}
Use-NtObject($m2 = Copy-NtObject -Object $m -NoRightsUpgrade) {
 Use-NtObject($m3 = Copy-NtObject -Object $m2 -DesiredAccess GenericAll) {}
}
$m.Close()

# Listing 8-6
$type = New-NtType -Name "Sandbox" -GenericRead 0x20000 -GenericAll 0x1F0001
$sd = New-NtSecurityDescriptor -NullDacl -Owner "SY" -Group "SY" -Type $type
Set-NtSecurityDescriptorIntegrityLevel $sd Medium -Policy NoReadUp
Get-NtGrantedAccess -SecurityDescriptor $sd -Access 0x20000 -PassResult
Use-NtObject($token = Get-NtToken -Duplicate -IntegrityLevel Low) {
 Get-NtGrantedAccess -SecurityDescriptor $sd -Access 0x20000 -Token $token -PassResult
}

# Listing 8-7
Invoke-NtToken -Current -IntegrityLevel Low {
 Get-NtHandle -ProcessId $pid
}

# Listing 8-8
Use-NtObject($token = Get-NtToken) {
 $token.IsSandbox
}

Use-NtObject($token = Get-NtToken -Duplicate -IntegrityLevel Low) {
 $token.IsSandbox
}

# Listing 8-9
Use-NtObject($ps = Get-NtProcess -FilterScript {$_.IsSandboxToken}) {
 $ps | ForEach-Object { Write-Host "$($_.ProcessId) $($_.Name)" }
}

# Listing 8-10
Get-Command Get-Accessible* | Format-Wide

# Listing 8-11
Get-AccessibleObject -Path "\"

# Listing 8-12
Get-AccessibleObject -Path \ | Format-NtSecurityDescriptor -Summary

# Listing 8-13
Get-AccessibleObject -Path "\" -Recurse

# Listing 8-14
$key = Get-NtKey HKLM\Software -Win32Path -Access ReadControl
Get-NtGrantedAccess -Object $key
$key.Close()

# Listing 8-15
$access = Get-NtAccessMask -SectionAccess MapWrite -AsGenericAccess
$objs = Use-NtObject($token = Get-NtToken -Duplicate -IntegrityLevel Low) {
 Get-AccessibleObject -Win32Path "\" -Recurse -Token $token -TypeFilter Section -Access $access
}

$objs | ForEach-Object {
 Use-NtObject($sect = Get-NtSection -Path $_.Name) {
    Use-NtObject($map = Add-NtSection $sect -Protection ReadWrite -ViewSize 4096) {
        Write-Host "$($sect.FullPath)"
        Out-HexDump -ShowHeader -ShowAscii -HideRepeating -Buffer $map | Out-Host
    }
 }
}