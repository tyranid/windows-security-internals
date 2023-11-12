# Listing 5-1
$domain_sid = Get-NtSid -SecurityAuthority Nt -RelativeIdentifier 32
Get-NtSidName $domain_sid

# Listing 5-2
$user_sid = Get-NtSid -BaseSid $domain_sid -RelativeIdentifier 545
Get-NtSidName $user_sid
$user_sid.Name

# Listing 5-3
Get-NtSid -BaseSid $domain_sid -RelativeIdentifier 544

# Listing 5-4
Get-NtSid -KnownSid BuiltinAdministrators

# Listing 5-5
ConvertFrom-NtAceCondition 'WIN://TokenId == "XYZ"' | Out-HexDump -ShowAll

# Listing 5-6
$world = Get-NtSid -KnownSid World
$sd = New-NtSecurityDescriptor -Owner $world -Group $world -Type File
$sd | Format-Table

# Listing 5-7
$user = Get-NtSid
Add-NtSecurityDescriptorAce $sd -Sid $user -Access WriteData, ReadData
Add-NtSecurityDescriptorAce $sd -KnownSid Anonymous -Access GenericAll -Type Denied
Add-NtSecurityDescriptorAce $sd -Name "Everyone" -Access ReadData
Add-NtSecurityDescriptorAce $sd -KnownSid World -Access Delete -Type Audit -Flags FailedAccess
Set-NtSecurityDescriptorIntegrityLevel $sd Low
Set-NtSecurityDescriptorControl $sd DaclAutoInherited, SaclProtected
$sd | Format-Table
Get-NtSecurityDescriptorControl $sd
Get-NtSecurityDescriptorDacl $sd | Format-Table
Get-NtSecurityDescriptorSacl $sd | Format-Table

# Listing 5-8
Test-NtSecurityDescriptor $sd -DaclCanonical
Edit-NtSecurityDescriptor $sd -CanonicalizeDacl
Test-NtSecurityDescriptor $sd -DaclCanonical
Get-NtSecurityDescriptorDacl $sd | Format-Table

# Listing 5-9
Format-NtSecurityDescriptor $sd -ShowAll

# Listing 5-10
Format-NtSecurityDescriptor $sd -ShowAll -Summary

# Listing 5-11
Format-NtSecurityDescriptor $sd -SDKName -SecurityInformation Dacl

# Listing 5-12
Format-NtSecurityDescriptor $sd -ShowAll -Summary -Container

# Listing 5-13
$ba = ConvertFrom-NtSecurityDescriptor $sd
$ba | Out-HexDump -ShowAll

# Listing 5-14
$sddl = Format-NtSecurityDescriptor $sd -ToSddl -ShowAll
$sddl

# Listing 5-15
$sddl -split "(?=O:)|(?=G:)|(?=D:)|(?=S:)|(?=\()"

# Listing 5-16
Get-NtSid -Sddl "WD"

# Listing 5-17
Get-NtSid -Sddl (Get-NtSid) -ToName

# Listing 5-18
ConvertFrom-NtSecurityDescriptor $sd -AsBase64 -InsertLineBreaks

# Listing 5-19
$sid = Get-NtSid -SecurityAuthority Nt -RelativeIdentifier 100, 200, 300
$ba = ConvertFrom-NtSid -Sid $sid
$ba | Out-HexDump -ShowAll
$stm = [System.IO.MemoryStream]::new($ba)
$reader = [System.IO.BinaryReader]::new($stm)
$revision = $reader.ReadByte()
if ($revision -ne 1) {
 throw "Invalid SID revision"
}
$rid_count = $reader.ReadByte()
$auth = $reader.ReadBytes(6)
if ($auth.Length -ne 6) {
 throw "Invalid security authority length"
}
$rids = @()
while($rid_count -gt 0) {
 $rids += $reader.ReadUInt32()
 $rid_count--
}
$new_sid = Get-NtSid -SecurityAuthorityByte $auth -RelativeIdentifier $rids
$new_sid -eq $sid

# Listing 5-20
function Get-AccountSids {
 param(
    [parameter(Mandatory)]
    $BaseSid,
    [int]$MinRid = 0,
    [int]$MaxRid = 256
 )
 $i = $MinRid
 while($i -lt $MaxRid) {
    $sid = Get-NtSid -BaseSid $BaseSid -RelativeIdentifier $i
    $name = Get-NtSidName $sid
    if ($name.Source -eq "Account") {
        [PSCustomObject]@{
            Sid = $sid;
            Name = $name.QualifiedName;
            Use = $name.NameUse
        }
    }
    $i++
 }
}
$sid = Get-NtSid -SecurityAuthority Nt
Get-AccountSids -BaseSid $sid
$sid = Get-NtSid -BaseSid $sid -RelativeIdentifier 32
Get-AccountSids -BaseSid $sid -MinRid 512 -MaxRid 1024