# Listing 2-1
Get-NtSid -Name "Users"

# Listing 2-2
Get-NtSid -Sddl "S-1-5-32-545"

# Listing 2-3
Get-NtType

# Listing 2-4
ls NtObject:\ | Sort-Object Name

# Listing 2-5
ls NtObject:\Dfs | Select-Object SymbolicLinkTarget
Get-Item NtObject:\Device\DfsClient | Format-Table

# Listing 2-10
Get-NtDirectory \THISDOESNOTEXIST
Get-NtStatus 0xC0000034 | Format-List

# Listing 2-11
Get-NtType | Select-Object Name, GenericMapping

# Listing 2-12
Get-NtTypeAccess -Type File

# Listing 2-13
Get-NtAccessMask -FileAccess ReadData, ReadAttributes, ReadControl
Get-NtAccessMask -FileAccess GenericRead
Get-NtAccessMask -FileAccess GenericRead -MapGenericRights
Get-NtAccessMask 0x120089 -AsTypeAccess File

# Listing 2-14
$mut = New-NtMutant
$mut.GrantedAccess
$mut.GrantedAccessMask
$mut.Close()

# Listing 2-15
Get-NtHandle -ProcessId $pid

# Listing 2-16
$m = New-NtMutant \BaseNamedObjects\ABC
$m.IsClosed
$m.Close()
$m.IsClosed

Use-NtObject($m = New-NtMutant \BaseNamedObjects\ABC) {
 $m.FullPath
}
$m.IsClosed

# Listing 2-17
$mut = New-NtMutant "\BaseNamedObjects\ABC"
$mut.GrantedAccess
Use-NtObject($dup = Copy-NtObject $mut) {
 $mut
 $dup
 Compare-NtObject $mut $dup
}

$mask = Get-NtAccessMask -MutantAccess ModifyState
Use-NtObject($dup = Copy-NtObject $mut -DesiredAccessMask $mask) {
 $dup.GrantedAccess
 Compare-NtObject $mut $dup
}

$mut.Close()

# Listing 2-18
$mut = New-NtMutant
$mut.ProtectFromClose = $true
Close-NtObject -SafeHandle $mut.Handle -CurrentProcess
$mut.ProtectFromClose = $false
$mut.Close()

# Listing 2-21
Get-NtObjectInformationClass Process

# Listing 2-22 and Listing 2-23
$proc = Get-NtProcess -Current
Get-NtObjectInformation $proc ProcessTimes
Get-NtObjectInformation $proc ProcessTimes -Length 32
Get-NtObjectInformation $proc ProcessTimes -AsObject
$proc | Format-List
$proc.CreationTime

# Listing 2-24
Get-NtObjectInformationClass Key
Get-NtObjectInformationClass Key -Set

# Listing 2-25
ls NtObject:\Device

# Listing 2-26
Use-NtObject($f = Get-NtFile "\SystemRoot\notepad.exe") {
 $f | Select-Object FullPath, NtTypeName
}

Get-Item NtObject:\Device\HarddiskVolume3

# Listing 2-27
Get-NtKernelModule

# Listing 2-28
Get-NtProcess -InfoOnly
Get-NtThread -InfoOnly

# Listing 2-29
$proc = Get-NtProcess -ProcessId $pid
$proc.CommandLine
$proc.Win32ImagePath
$proc.Close()

# Listing 2-30
Get-NtVirtualMemory
$addr = Add-NtVirtualMemory -Size 1000 -Protection ReadWrite
Get-NtVirtualMemory -Address $addr
Read-NtVirtualMemory -Address $addr -Size 4 | Out-HexDump
Write-NtVirtualMemory -Address $addr -Data @(1,2,3,4)
Read-NtVirtualMemory -Address $addr -Size 4 | Out-HexDump
Set-NtVirtualMemory -Address $addr -Protection ExecuteRead -Size 4
Get-NtVirtualMemory -Address $addr
Remove-NtVirtualMemory -Address $addr
Get-NtVirtualMemory -Address $addr

# Listing 2-31
$s = New-NtSection -Size 4096 -Protection ReadWrite
$m = Add-NtSection -Section $s -Protection ReadWrite
Get-NtVirtualMemory $m.BaseAddress
Remove-NtSection -Mapping $m
Get-NtVirtualMemory -Address 0x1C3DD0E0000
Add-NtSection -Section $s -Protection ExecuteRead
$s.Close()

# Listing 2-32
Get-NtVirtualMemory -Type Mapped | Where-Object Name -ne ""

# Listing 2-33
$sect = New-NtSectionImage -Win32Path "$env:WinDir\system32\notepad.exe"
$map = Add-NtSection -Section $sect -Protection ReadOnly
Get-NtVirtualMemory -Address $map.BaseAddress
Get-NtVirtualMemory -Type Image -Name "notepad.exe"
Out-HexDump -Buffer $map -ShowAscii -Length 128
Remove-NtSection -Mapping $map
$sect.Close()

# Listing 2-34
Get-AuthenticodeSignature "$env:WinDir\system32\notepad.exe" | Format-List

# Listing 2-35
ls NtObject:\REGISTRY

# Listing 2-36
$key = Get-NtKey \Registry\Machine\SOFTWARE\Microsoft\.NETFramework
Get-NtKeyValue -Key $key
$key.Close()

# Listing 2-37
$hs = Get-NtHandle -ObjectType File | Where-Object Name -Match Windows
$hs | Select-Object ProcessId, Handle, Name

# Listing 2-38
$ss = Get-NtHandle -ObjectType Section -GroupByAddress | Where-Object ShareCount -eq 2
$mask = Get-NtAccessMask -SectionAccess MapWrite
$ss = $ss | Where-Object { Test-NtAccessMask $_.AccessIntersection $mask }
foreach($s in $ss) {
 $count = ($s.ProcessIds | Where-Object {
    Test-NtProcess -ProcessId $_ -Access DupHandle
 }).Count
 if ($count -eq 1) {
    $s.Handles | Select ProcessId, ProcessName, Handle
 }
}

# Listing 2-39
$handle = $null # Replace with a valid section object from NtObject:\.
$sect = $handle.GetObject()
$map = Add-NtSection -Section $sect -Protection ReadWrite
$random = Get-RandomByte -Size $map.Length
Write-NtVirtualMemory -Mapping $map -Data $random
Out-HexDump -Buffer $map -Length 16 -ShowAddress -ShowHeader

# Listing 2-40
$proc = Get-NtProcess -ProcessId $pid -Access QueryLimitedInformation
Get-NtVirtualMemory -Process $proc | Where-Object {
    $_.Protect -band "ExecuteReadWrite"
}
$proc.Close()