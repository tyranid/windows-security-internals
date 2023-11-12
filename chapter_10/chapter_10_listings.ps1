# Listing 10-1
Get-LocalUser | Select-Object Name, Enabled, Sid

# Listing 10-2
Get-NtSid -Name $env:COMPUTERNAME

# Listing 10-4
Get-LocalGroup | Select-Object Name, Sid

# Listing 10-5
Get-LocalGroupMember -Name "Awesome Users"

# Listing 10-7
Get-NtAccountRight -Type Privilege

# Listing 10-9
$server = Connect-SamServer -ServerName 'localhost'
Format-NtSecurityDescriptor $server -Summary -MapGeneric

# Listing 10-10
Get-SamDomain -Server $server -InfoOnly
$domain = Get-SamDomain -Server $server -Name "$env:COMPUTERNAME"
$domain.PasswordInformation

# Listing 10-11
Get-SamUser -Domain $domain -InfoOnly
$user = Get-SamUser -Domain $domain -Name "WDAGUtilityAccount"
$user.UserAccountControl
Format-NtSecurityDescriptor $user -Summary

# Listing 10-12
Get-SamGroup -Domain $domain -InfoOnly
$group = Get-SamGroup $domain -Name "None"
Get-SamGroupMember -Group $group

# Listing 10-13
Get-SamAlias -Domain $domain -InfoOnly
$alias = Get-SamAlias -Domain $domain -Name "Awesome Users"
Get-SamAliasMember -Alias $alias

# Listing 10-14
$policy = Get-LsaPolicy
Format-NtSecurityDescriptor $policy -Summary

# Listing 10-15
$policy = Get-LsaPolicy -Access ViewLocalInformation
Get-LsaAccount -Policy $policy -InfoOnly
$sid = Get-NtSid -KnownSid BuiltinUsers
$account = Get-LsaAccount -Policy $policy -Sid $sid
Format-NtSecurityDescriptor -Object $account -Summary

# Listing 10-18
$policy = Get-LsaPolicy -ServerName "PRIMARYDC"
Get-LsaTrustedDomain -Policy $policy -InfoOnly

# Listing 10-19
$policy = Get-LsaPolicy -Access LookupNames
Get-LsaName -Policy $policy -Sid "S-1-1-0", "S-1-5-32-544"
Get-LsaSid -Policy $policy -Name "Guest" | Select-Object Sddl

# Listing 10-37
function Get-SidNames {
 param(
     [string]$Server,
     [string]$Domain,
     [int]$MinRid = 500,
     [int]$MaxRid = 1499
 )
 if ("" -eq $Domain) {
    $Domain = $Server
 }
 Use-NtObject($policy = Get-LsaPolicy -SystemName $Server -Access LookupNames) {
    $domain_sid = Get-LsaSid $policy "$Domain\"
    $sids = $MinRid..$MaxRid | ForEach-Object {
        Get-NtSid -BaseSid $domain_sid -RelativeIdentifier $_
    }
    Get-LsaName -Policy $policy -Sid $sids | Where-Object NameUse -ne "Unknown"
 }
}
Get-SidNames -Server $env:COMPUTERNAME | Select-Object QualifiedName, Sddl

# Listing 10-38
function Get-UserObject([string]$Server, [string]$User) {
 Use-NtObject($sam = Connect-SamServer -ServerName $Server) {
    Use-NtObject($domain = Get-SamDomain -Server $sam -User) {
        Get-SamUser -Domain $domain -Name $User -Access ForcePasswordChange
    }
 }
}

function Set-UserPassword([string]$Server, [string]$User, [bool]$Expired) {
 Use-NtObject($user_obj = Get-UserObject $Server $User) {
    $pwd = Read-Host -AsSecureString -Prompt "New Password"
    $user_obj.SetPassword($pwd, $Expired)
 }
}

# Listing 10-39
Set-UserPassword -Server $env:COMPUTERNAME "user"