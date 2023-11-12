# Listing 6-2
Use-NtObject($d = Get-NtDirectory "\BaseNamedObjects" -Access ReadControl) {
 Get-NtSecurityDescriptor -Object $d
}

# Listing 6-3
Get-NtSecurityDescriptor "\BaseNamedObjects" -SecurityInformation Owner

# Listing 6-4
$creator = New-NtSecurityDescriptor -Type Mutant
Add-NtSecurityDescriptorAce $creator -Name "Everyone" -Access GenericRead
Format-NtSecurityDescriptor $creator
$token = Get-NtToken -Effective -Pseudo
$sd = New-NtSecurityDescriptor -Token $token -Creator $creator -Type Mutant
Format-NtSecurityDescriptor $sd

# Listing 6-5
Format-NtToken $token -Owner -PrimaryGroup

# Listing 6-6
Set-NtSecurityDescriptorOwner $creator -KnownSid LocalSystem
New-NtSecurityDescriptor -Token $token -Creator $creator -Type Mutant

# Listing 6-7
$creator = New-NtSecurityDescriptor -Type Mutant
Add-NtSecurityDescriptorAce $creator -Name "Everyone" -Access GenericRead
Use-NtObject($m = New-NtMutant -SecurityDescriptor $creator) {
 Format-NtSecurityDescriptor $m
}

# Listing 6-8
$token = Get-NtToken -Effective -Pseudo
$sd = New-NtSecurityDescriptor -Token $token -Type Mutant
Format-NtSecurityDescriptor $sd -HideHeader

# Listing 6-9
Format-NtToken $token -DefaultDacl

# Listing 6-10
Use-NtObject($m = New-NtMutant) {
 Format-NtSecurityDescriptor $m
}

# Listing 6-11
Get-NtType "Mutant" | Select-Object SecurityRequired

# Listing 6-12
Get-NtType Directory | Select-Object SecurityRequired
Use-NtObject($dir = New-NtDirectory) {
 Format-NtSecurityDescriptor $dir -Summary
}

# Listing 6-13
function New-ParentSD($AceFlags = 0, $Control = 0) {
 $owner = Get-NtSid -KnownSid BuiltinAdministrators
 $parent = New-NtSecurityDescriptor -Type Directory -Owner $owner -Group $owner
 Add-NtSecurityDescriptorAce $parent -Name "Everyone" -Access GenericAll
 Add-NtSecurityDescriptorAce $parent -Name "Users" -Access GenericAll -Flags $AceFlags
 Add-NtSecurityDescriptorControl $parent -Control $Control
 Edit-NtSecurityDescriptor $parent -MapGeneric
 return $parent
}

function Test-NewSD($AceFlags = 0,
                    $Control = 0,
                    $Creator = $null,
                    [switch]$Container) {
 $parent = New-ParentSD -AceFlags $AceFlags -Control $Control
 Write-Output "-= Parent SD =-"
 Format-NtSecurityDescriptor $parent -Summary
 if ($Creator -ne $null) {
    Write-Output "`r`n-= Creator SD =-"
    Format-NtSecurityDescriptor $creator -Summary
 }
 $auto_inherit_flags = @()
 if (Test-NtSecurityDescriptor $parent -DaclAutoInherited) {
    $auto_inherit_flags += "DaclAutoInherit"
 }
 if (Test-NtSecurityDescriptor $parent -SaclAutoInherited) {
    $auto_inherit_flags += "SaclAutoInherit"
 }
 if ($auto_inherit_flags.Count -eq 0) {
    $auto_inherit_flags += "None"
 }
 $token = Get-NtToken -Effective -Pseudo
 $sd = New-NtSecurityDescriptor -Token $token -Parent $parent -Creator $creator -Type Mutant -Container:$Container -AutoInherit $auto_inherit_flags
 Write-Output "`r`n-= New SD =-"
 Format-NtSecurityDescriptor $sd -Summary
}

# Listing 6-14
Test-NewSD

# Listing 6-15
Test-NewSD -AceFlags "ObjectInherit"

# Listing 6-16
Get-NtAccessMask (0x0001F0001 -band 0x0000F000F) -ToSpecificAccess Mutant

# Listing 6-17
Test-NewSD -AceFlags "ObjectInherit, InheritOnly"

# Listing 6-18
Test-NewSD -AceFlags "ContainerInherit, InheritOnly" -Container

# Listing 6-19
$ace_flags = "ContainerInherit, InheritOnly, NoPropagateInherit"
Test-NewSD -AceFlags $ace_flags -Container

# Listing 6-20
Test-NewSD -AceFlags "ObjectInherit" -Container

# Listing 6-21
$ace_flags = "ObjectInherit, InheritOnly"
Test-NewSD -AceFlags $ace_flags -Control "DaclAutoInherited"

# Listing 6-22
function New-CreatorSD($AceFlags = 0, $Control = 0, [switch]$NoDacl) {
    $creator = New-NtSecurityDescriptor -Type Mutant
    if (!$NoDacl) {
        Add-NtSecurityDescriptorAce $creator -Name "Network" -Access GenericAll
        Add-NtSecurityDescriptorAce $creator -Name "Interactive" -Access GenericAll -Flags $AceFlags
    }
    Add-NtSecurityDescriptorControl $creator -Control $Control
    Edit-NtSecurityDescriptor $creator -MapGeneric
    return $creator
}

# Listing 6-23
$creator = New-CreatorSD -NoDacl
Test-NewSD -Creator $creator -AceFlags "ObjectInherit, InheritOnly"

# Listing 6-24
$creator = New-CreatorSD
Test-NewSD -Creator $creator -AceFlags "ObjectInherit, InheritOnly"

# Listing 6-25
$creator = New-CreatorSD -AceFlags "Inherited"
Test-NewSD -Creator $creator -AceFlags "ObjectInherit, InheritOnly" -Control "DaclAutoInherited"

# Listing 6-26
$creator = New-CreatorSD -AceFlags "Inherited" -Control "DaclProtected"
Test-NewSD -Creator $creator -AceFlags "ObjectInherit, InheritOnly" -Control "DaclAutoInherited"

# Listing 6-27
$creator = New-CreatorSD -Control "DaclDefaulted"
Test-NewSD -Creator $creator -AceFlags "ObjectInherit, InheritOnly"
Test-NewSD -Creator $creator

# Listing 6-28
$parent = New-NtSecurityDescriptor -Type Directory
Add-NtSecurityDescriptorAce $parent -KnownSid CreatorOwner -Flags ContainerInherit, InheritOnly -Access GenericWrite
Add-NtSecurityDescriptorAce $parent -KnownSid CreatorGroup -Flags ContainerInherit, InheritOnly -Access GenericRead
Format-NtSecurityDescriptor $parent -Summary -SecurityInformation Dacl
$token = Get-NtToken -Effective -Pseudo
$sd = New-NtSecurityDescriptor -Token $token -Parent $parent -Type Directory -Container
Format-NtSecurityDescriptor $sd -Summary -SecurityInformation Dacl

# Listing 6-29
$token = Get-NtToken -Duplicate -IntegrityLevel Low
$sd = New-NtSecurityDescriptor -Token $token -Type Mutant
Format-NtSecurityDescriptor $sd -SecurityInformation Label -Summary
$token.Close()

# Listing 6-30
$creator = New-NtSecurityDescriptor -Type Mutant
Set-NtSecurityDescriptorIntegrityLevel $creator System
$token = Get-NtToken -Duplicate -IntegrityLevel Medium
New-NtSecurityDescriptor -Token $token -Creator $creator -Type Mutant
$sd = New-NtSecurityDescriptor -Token $token -Creator $creator -Type Mutant -AutoInherit AvoidPrivilegeCheck
Format-NtSecurityDescriptor $sd -SecurityInformation Label -Summary

# Listing 6-31
$parent = New-NtSecurityDescriptor -Type Mutant
Set-NtSecurityDescriptorIntegrityLevel $parent Low -Flags ObjectInherit
$token = Get-NtToken -Effective -Pseudo
$sd = New-NtSecurityDescriptor -Token $token -Parent $parent -Type Mutant
Format-NtSecurityDescriptor $sd -SecurityInformation Label -Summary

# Listing 6-32
 $token = Get-NtToken -Effective -Pseudo
$sd = New-NtSecurityDescriptor -Token $token -Type Mutant
-AutoInherit MaclNoReadUp, MaclNoWriteUp
PS> Format-NtSecurityDescriptor $sd -SecurityInformation Label -Summary

# Listing 6-33
$owner = Get-NtSid -KnownSid BuiltinAdministrators
$parent = New-NtSecurityDescriptor -Type Directory -Owner $owner -Group $owner
$type_1 = New-Guid
$type_2 = New-Guid
Add-NtSecurityDescriptorAce $parent -Name "SYSTEM" -Access GenericAll -Flags ObjectInherit -Type AllowedObject -ObjectType $type_1
Add-NtSecurityDescriptorAce $parent -Name "Everyone" -Access GenericAll -Flags ObjectInherit -Type AllowedObject -InheritedObjectType $type_1
Add-NtSecurityDescriptorAce $parent -Name "Users" -Access GenericAll -Flags ObjectInherit -InheritedObjectType $type_2 -Type AllowedObject
Format-NtSecurityDescriptor $parent -Summary -SecurityInformation Dacl
$token = Get-NtToken -Effective -Pseudo
$sd = New-NtSecurityDescriptor -Token $token -Parent $parent -Type Directory -ObjectType $type_2
Format-NtSecurityDescriptor $sd -Summary -SecurityInformation Dacl

# Listing 6-34
Get-NtAccessMask -SecurityInformation AllBasic -ToGenericAcces
Get-NtAccessMask -SecurityInformation AllBasic -ToGenericAccess -SetSecurity

# Listing 6-35
$owner = Get-NtSid -KnownSid BuiltinAdministrators
$obj_sd = New-NtSecurityDescriptor -Type Mutant -Owner $owner -Group $owner
Add-NtSecurityDescriptorAce $obj_sd -KnownSid World -Access GenericAll
Format-NtSecurityDescriptor $obj_sd -Summary -SecurityInformation Dacl
Edit-NtSecurityDescriptor $obj_sd -MapGeneric
$mod_sd = New-NtSecurityDescriptor -Type Mutant
Add-NtSecurityDescriptorAce $mod_sd -KnownSid Anonymous -Access GenericRead
Set-NtSecurityDescriptorControl $mod_sd DaclAutoInherited, DaclAutoInheritReq
Edit-NtSecurityDescriptor $obj_sd $mod_sd -SecurityInformation Dacl
Format-NtSecurityDescriptor $obj_sd -Summary -SecurityInformation Dacl

# Listing 6-36
Get-Win32SecurityDescriptor "$env:WinDir"
Format-Win32SecurityDescriptor "MACHINE\SOFTWARE" -Type RegistryKey -Summary

# Listing 6-37
$path = Join-Path "$env:TEMP" "TestFolder"
Use-NtObject($f = New-NtFile $path -Win32Path -Options DirectoryFile -Disposition OpenIf) {
 Set-NtSecurityDescriptor $f "D:AIARP(A;OICI;GA;;;WD)" Dacl
}
$item = Join-Path $path test.txt
"Hello World!" | Set-Content -Path $item
Format-Win32SecurityDescriptor $item -Summary -SecurityInformation Dacl
$sd = Get-Win32SecurityDescriptor $path
Add-NtSecurityDescriptorAce $sd -KnownSid Anonymous -Access GenericAll -Flags ObjectInherit,ContainerInherit,InheritOnly
Set-Win32SecurityDescriptor $path $sd Dacl
Format-Win32SecurityDescriptor $item -Summary -SecurityInformation Dacl

# Listing 6-38
$path = Join-Path "$env:TEMP\TestFolder" "test.txt"
$sd = New-NtSecurityDescriptor "D:(A;;GA;;;AU)"
Set-Win32SecurityDescriptor $path $sd Dacl,ProtectedDacl
Format-Win32SecurityDescriptor $path -Summary -SecurityInformation Dacl
Set-Win32SecurityDescriptor $path $sd Dacl,UnprotectedDacl
Format-Win32SecurityDescriptor $path -Summary -SecurityInformation Dacl

# Listing 6-39
$path = Join-Path "$env:TEMP\TestFolder" "test.txt"
Reset-Win32SecurityDescriptor $path Dacl
Format-Win32SecurityDescriptor $path -Summary -SecurityInformation Dacl

# Listing 6-40
$path = Join-Path "$env:TEMP" "TestFolder"
Search-Win32SecurityDescriptor $path | Format-Table
$path = Join-Path $path "new.txt"
"Hello" | Set-Content $path
Search-Win32SecurityDescriptor $path | Format-Table

# Listing 6-41
$token = Get-NtToken -Anonymous
$creator = New-NtSecurityDescriptor -Type Mutant
Add-NtSecurityDescriptorAce $creator -KnownSid World -Access GenericAll
$sd = New-NtSecurityDescriptor -Token $token -Creator $creator
Format-NtSecurityDescriptor $sd -Summary -SecurityInformation Owner,Group,Dacl
Set-NtSecurityDescriptorControl $creator ServerSecurity
$sd = New-NtSecurityDescriptor -Token $token -Creator $creator
Format-NtSecurityDescriptor $sd -Summary -SecurityInformation Owner,Group,Dacl

# Listing 6-42
function Get-NameAndOwner {
 [CmdletBinding()]
 param(
    [parameter(Mandatory, ValueFromPipeline)]
    $Entry,
    [parameter(Mandatory)]
    $Root
 )
 begin {
    $curr_owner = Get-NtSid -Owner
 }
 process {
    $sd = Get-NtSecurityDescriptor -Path $Entry.Name -Root $Root -TypeName $Entry.NtTypeName -ErrorAction SilentlyContinue
    if ($null -ne $sd -and $sd.Owner.Sid -ne $curr_owner) {
        [PSCustomObject] @{
            Name = $Entry.Name
            NtTypeName = $Entry.NtTypeName
            Owner = $sd.Owner.Sid.Name
            SecurityDescriptor = $sd
        }
    }
  }
}
Use-NtObject($dir = Get-NtDirectory \BaseNamedObjects) {
 Get-NtDirectoryEntry $dir | Get-NameAndOwner -Root $dir
}

# Listing 6-43
$entry = $null # Need to set this to a known value.
Get-NtGrantedAccess -SecurityDescriptor $entry.SecurityDescriptor

# Listing 6-44
(Get-Acl C:\ | ConvertTo-NtSecurityDescriptor).Owner.Sid