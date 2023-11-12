# Listing 7-1
$sd = New-NtSecurityDescriptor -EffectiveToken -Type Mutant
Format-NtSecurityDescriptor $sd -Summary
Get-NtGrantedAccess $sd -AsString
Get-NtGrantedAccess $sd -Access ModifyState -AsString
Clear-NtSecurityDescriptorDacl $sd
Format-NtSecurityDescriptor $sd -Summary
Get-NtGrantedAccess $sd -AsString

# Listing 7-6
function New-BaseSD {
    $owner = Get-NtSid -KnownSid LocalSystem
    $sd = New-NtSecurityDescriptor -Owner $owner -Group $owner -Type Mutant
    Add-NtSecurityDescriptorAce $sd -KnownSid Anonymous -Access GenericAll
    $sid = Get-NtSid
    Add-NtSecurityDescriptorAce $sd -Sid $sid -Access GenericAll
    Set-NtSecurityDescriptorIntegrityLevel $sd Untrusted
    Edit-NtSecurityDescriptor $sd -MapGeneric
    return $sd
}

# Listing 7-7
$sd = New-BaseSD
$trust_sid = Get-NtSid -TrustType ProtectedLight -TrustLevel Windows
Add-NtSecurityDescriptorAce $sd -Type ProcessTrustLabel -Access ModifyState -Sid $trust_sid
Get-NtGrantedAccess $sd -AsString
$token = Get-NtToken -Anonymous
$anon_trust_sid = Get-NtTokenSid -Token $token -TrustLevel
Compare-NtSid $anon_trust_sid $trust_sid -Dominates
Get-NtGrantedAccess $sd -Token $token -AsString
$token.Close()

# Listing 7-8
$sd = New-BaseSD
Add-NtSecurityDescriptorAce $sd -Type AccessFilter -KnownSid World -Access ModifyState -Condition "Exists TSA://ProcUnique" -MapGeneric
Format-NtSecurityDescriptor $sd -Summary -SecurityInformation AccessFilter
Show-NtTokenEffective -SecurityAttributes
Get-NtGrantedAccess $sd -AsString
Use-NtObject($token = Get-NtToken -Anonymous) {
 Get-NtGrantedAccess $sd -Token $token -AsString
}

# Listing 7-11
$sd = New-BaseSD
Format-NtSecurityDescriptor $sd -SecurityInformation Label -Summary
Use-NtObject($token = Get-NtToken -Anonymous) {
 Format-NtToken $token -Integrity
 Get-NtGrantedAccess $sd -Token $token -AsString
}
Remove-NtSecurityDescriptorIntegrityLevel $sd
Use-NtObject($token = Get-NtToken -Anonymous) {
 Get-NtGrantedAccess $sd -Token $token -AsString
}


# Listing 7-16
$owner = Get-NtSid -KnownSid World
$sd = New-NtSecurityDescriptor -Owner $owner -Group $owner -Type Mutant -EmptyDacl
Get-NtGrantedAccess $sd
Add-NtSecurityDescriptorAce $sd -KnownSid OwnerRights -Access ModifyState
Get-NtGrantedAccess $sd

# Listing 7-23
$sd = New-NtSecurityDescriptor -Owner "BA" -Group "BA" -Type Mutant
Add-NtSecurityDescriptorAce $sd -KnownSid World -Access GenericAll
Add-NtSecurityDescriptorAce $sd -KnownSid AllApplicationPackages -Access GenericAll
Edit-NtSecurityDescriptor $sd -MapGeneric
Set-NtSecurityDescriptorIntegrityLevel $sd Medium
Use-NtObject($token = Get-NtToken -Duplicate -IntegrityLevel Low) {
 Get-NtGrantedAccess $sd -Token $token -AsString
}
$sid = Get-NtSid -PackageName "mandatory_access_lowbox_check"
Use-NtObject($token = Get-NtToken -LowBox -PackageSid $sid) {
 Get-NtGrantedAccess $sd -Token $token -AsString
}

# Listing 7-24
$sid = Get-NtSid -PackageName 'package_sid_low_il_test'
$token = Get-NtToken -LowBox -PackageSid $sid
$sd = New-NtSecurityDescriptor -Token $token -Type Mutant
Format-NtSecurityDescriptor $sd -Summary -SecurityInformation Dacl, Label
Get-NtGrantedAccess $sd -Token $token -AsString
$token.Close()
$low_token = Get-NtToken -Duplicate -IntegrityLevel Low
Get-NtGrantedAccess $sd -Token $low_token -AsString
$low_token.Close()

# Listing 7-26
$owner = Get-NtSid -KnownSid LocalSystem
$sd = New-NtSecurityDescriptor -Owner $owner -Group $owner -Type Mutant
Add-NtSecurityDescriptorAce $sd -KnownSid Self -Access GenericAll -MapGeneric
Get-NtGrantedAccess $sd -AsString
$principal = Get-NtSid
Get-NtGrantedAccess $sd -Principal $principal -AsString

# Listing 7-29
$tree = New-ObjectTypeTree (New-Guid) -Name "Object"
$set_1 = Add-ObjectTypeTree $tree (New-Guid) -Name "Property Set 1" -PassThru
$set_2 = Add-ObjectTypeTree $tree (New-Guid) -Name "Property Set 2" -PassThru
Add-ObjectTypeTree $set_1 (New-Guid) -Name "Property X"
Add-ObjectTypeTree $set_1 (New-Guid) -Name "Property Y"
$prop_z = New-Guid
Add-ObjectTypeTree $set_2 $prop_z -Name "Property Z"
$owner = Get-NtSid -KnownSid LocalSystem
$sd = New-NtSecurityDescriptor -Owner $owner -Group $owner -Type Mutant
Add-NtSecurityDescriptorAce $sd -KnownSid World -Access WriteOwner -MapGeneric -Type DeniedObject -ObjectType $prop_z
Add-NtSecurityDescriptorAce $sd -KnownSid World -Access ReadControl, WriteOwner -MapGeneric
Edit-NtSecurityDescriptor $sd -CanonicalizeDacl
Get-NtGrantedAccess $sd -PassResult -ObjectType $tree -Access ReadControl, WriteOwner | Format-Table Status, SpecificGrantedAccess, Name
Get-NtGrantedAccess $sd -PassResult -ResultList -ObjectType $tree -Access ReadControl, WriteOwner | Format-Table Status, SpecificGrantedAccess, Name

# Listing 7-30
Get-CentralAccessPolicy
$rules = Get-CentralAccessPolicy | Select-Object -ExpandProperty Rules
$rules | Format-Table
$sd = $rules[0].SecurityDescriptor
Format-NtSecurityDescriptor $sd -Type File -SecurityInformation Dacl

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
Get-PSGrantedAccess -Token $token -SecurityDescriptor $sd -GenericMapping $type.GenericMapping -DesiredAccess $desired_access
$token.Close()

# Listing 7-34
function Get-NameAndGrantedAccess {
    [CmdletBinding()]
    param(
        [parameter(Mandatory, ValueFromPipeline)]
        $Entry,
        [parameter(Mandatory)]
        $Root
    )
    PROCESS {
        $sd = Get-NtSecurityDescriptor -Path $Entry.Name -Root $Root -TypeName $Entry.NtTypeName -ErrorAction SilentlyContinue
        if ($null -ne $sd) {
            $granted_access = Get-NtGrantedAccess -SecurityDescriptor $sd
            if (!(Test-NtAccessMask $granted_access -Empty)) {
            $props = @{
                Name = $Entry.Name;
                NtTypeName = $Entry.NtTypeName
                GrantedAccess = $granted_access
            }
            New-Object -TypeName PSObject -Prop $props
        }
    }
 }
}
Use-NtObject($dir = Get-NtDirectory \BaseNamedObjects) {
 Get-NtDirectoryEntry $dir | Get-NameAndGrantedAccess -Root $dir
}