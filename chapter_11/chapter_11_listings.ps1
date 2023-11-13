# Listing 11-1
$cap_name = Get-WindowsCapability -Online | Where-Object Name -Match 'Rsat.ActiveDirectory.DS-LDS.Tools'
Add-WindowsCapability -Name $cap_name.Name -Online

# Listing 11-2
$forest = Get-ADForest
$forest.Domains
$forest.GlobalCatalogs
Get-ADDomain | Format-List PDCEmulator, DomainSID, DNSRoot, NetBIOSName
Get-ADDomainController | Select-Object Name, Domain
Get-ADTrust -Filter * | Select-Object Target, Direction, TrustType

# Listing 11-3
Get-ADUser -Filter * | Select-Object SamAccountName, Enabled, SID

# Listing 11-4
Get-ADGroup -Filter * | Select-Object SamAccountName, SID, GroupScope

# Listing 11-5
Get-ADGroupMember -Identity Administrators | Select Name, objectClass
Get-LocalGroupMember -Name Administrators

# Listing 11-6
Get-ADComputer -Filter * | Select-Object SamAccountName, Enabled, SID

# Listing 11-8
Get-ADRootDSE | Format-List '*NamingContext'# Listing 11-9$root_dn = (Get-ADRootDSE).defaultNamingContext
Get-ADObject -SearchBase $root_dn -SearchScope OneLevel -Filter * | Select-Object DistinguishedName, ObjectClass
Get-ADObject -Identity "CN=Builtin,$root_dn" | Format-List
Get-ADObject -Identity "CN=Builtin,$root_dn" -Properties * | Format-List

# Listing 11-10
Get-ADObject -Identity 'CN=Users,DC=sales,DC=mineral,DC=local'

# Listing 11-11
$dn = 'CN=Users,DC=sales,DC=mineral,DC=local'
$obj_sales = Get-ADObject -Identity $dn -Server SALES -Properties *
$obj_sales.DistinguishedName
$obj_gc = Get-ADObject -Identity $dn -Server :3268 -Properties *
$obj_gc.DistinguishedName
($obj_sales | Get-Member -MemberType Property | Measure-Object).Count
($obj_gc | Get-Member -MemberType Property | Measure-Object).Count

# Listing 11-12
$schema_dn = (Get-ADRootDSE).schemaNamingContext
Get-ADObject -SearchBase $schema_dn -SearchScope OneLevel -Filter * | Sort-Object Name | Select-Object Name, ObjectClass
Get-ADObject -SearchBase $schema_dn -Filter {
 ObjectClass -eq "classSchema"
} -Properties * | Sort-Object Name | Format-List Name, {[guid]$_.schemaIDGUID}, mayContain, mustContain, systemMayContain, systemMustContain, auxiliaryClass, systemAuxiliaryClass, SubClassOf
Get-ADObject -SearchBase $schema_dn -Filter {
 lDAPDisplayName -eq "uid"
} -Properties * | Format-List adminDescription, {[guid]$_.schemaIDGUID}, attributeSyntax, oMSyntax, oMObjectClass

# Listing 11-13
Get-DsSchemaClass | Sort-Object Name

# Listing 11-14
$cls = Get-DsSchemaClass -Name "account"
$cls | Format-List
$cls.Attributes
$cls.Attributes | Get-DsSchemaAttribute
Get-DsSchemaClass -Parent $cls -Recurse

# Listing 11-15
(Get-DsSchemaClass top).Attributes | Where-Object Name -Match nTSecurityDescriptor

# Listing 11-16
$root_dn = (Get-ADRootDSE).defaultNamingContext
$obj = Get-ADObject -Identity $root_dn -Properties "nTSecurityDescriptor"
$obj.nTSecurityDescriptor.Access
Format-Win32SecurityDescriptor -Name $root_dn -Type Ds

# Listing 11-17
$sd = New-NtSecurityDescriptor -Type DirectoryService
Add-NtSecurityDescriptorAce $sd -KnownSid BuiltinAdministrators -Access All
$root_dn = (Get-ADRootDSE).defaultNamingContext
$obj = New-ADObject -Type "container" -Name "SDDEMO" -Path $root_dn -OtherAttributes @{nTSecurityDescriptor=$sd.ToByteArray()} -PassThru
Format-Win32SecurityDescriptor -Name $obj.DistinguishedName -Type Ds

# Listing 11-18
$root_dn = (Get-ADRootDSE).defaultNamingContext
$cls = Get-DsSchemaClass -Name "container"
$parent = Get-Win32SecurityDescriptor $root_dn -Type Ds
$sd = New-NtSecurityDescriptor -Parent $parent -EffectiveToken -ObjectType $cls.SchemaId -Creator $cls.DefaultSecurityDescriptor -Type DirectoryService -AutoInherit DaclAutoInherit, SaclAutoInherit -Container
Format-NtSecurityDescriptor $sd -Summary
$std_sd = Edit-NtSecurityDescriptor $sd -Standardize -PassThru
Compare-NtSecurityDescriptor $std_sd $sd -Report

# Listing 11-19
(Get-DsHeuristics).DontStandardizeSDs

# Listing 11-20
$dn = "CN=SomeObject,DC=mineral,DC=local"
$sd = New-NtSecurityDescriptor "D:(A;;GA;;;WD)"
Set-Win32SecurityDescriptor $dn -Type Ds -SecurityDescriptor $sd -SecurityInformation Dacl

# Listing 11-21
Get-DsSDRightsEffective -DistinguishedName $dn

# Listing 11-22
$root_dn = (Get-ADRootDSE).defaultNamingContext
$user_dn = "CN=Users,$root_dn"
$curr_sd = Get-Win32SecurityDescriptor "CN=Users,$root_dn" -Type Ds
Format-NtSecurityDescriptor $curr_sd -Summary
$new_sd = New-NtSecurityDescriptor "D:(A;;GA;;;WD)"
Edit-NtSecurityDescriptor -SecurityDescriptor $curr_sd -NewSecurityDescriptor $new_sd -SecurityInformation Dacl -Flags DaclAutoInherit, SaclAutoInherit
$cls = Get-DsObjectSchemaClass $user_dn
$parent = Get-Win32SecurityDescriptor $root_dn -Type Ds
$sd = New-NtSecurityDescriptor -Parent $parent -ObjectType $cls.SchemaId -Creator $curr_sd -Container -Type DirectoryService -AutoInherit DaclAutoInherit, SaclAutoInherit, AvoidOwnerCheck, AvoidOwnerRestriction, AvoidPrivilegeCheck -EffectiveToken
Edit-NtSecurityDescriptor $sd -Standardize
Format-NtSecurityDescriptor $sd -Summary

# Listing 11-23
$root_dn = (Get-ADRootDSE).defaultNamingContext
$user_dn = "CN=Users,$root_dn"
$cls = Get-DsObjectSchemaClass -DistinguishedName $user_dn
Search-Win32SecurityDescriptor -Name $user_dn -Type Ds -ObjectType $cls.SchemaId

# Listing 11-24
$sd = New-NtSecurityDescriptor -Type DirectoryService -Owner "SY" -Group "SY"
Add-NtSecurityDescriptorAce $sd -KnownSid World -Type Allowed -Access List
$user = Get-DsSchemaClass -Name "user"
Add-NtSecurityDescriptorAce $sd -KnownSid World -Type AllowedObject -Access CreateChild -ObjectType $user.SchemaId
Format-NtSecurityDescriptor $sd -Summary -SecurityInformation Dacl -ResolveObjectType
Get-NtGrantedAccess $sd -ObjectType $user CreateChild, List
$cont = Get-DsSchemaClass -Name "container"
Get-NtGrantedAccess $sd -ObjectType $cont

# Listing 11-25
Get-DsSchemaClass "user" -Inferior

# Listing 11-26
$sd = New-NtSecurityDescriptor -Type DirectoryService -Owner "DA" -Group "DA"
Add-NtSecurityDescriptorAce $sd -KnownSid World -Type Allowed -Access ReadProp
$attr = Get-DsSchemaAttribute -Name "accountExpires"
Add-NtSecurityDescriptorAce $sd -KnownSid World -Type AllowedObject -Access WriteProp -ObjectType $attr.SchemaId
Get-NtGrantedAccess $sd -ObjectType $attr ReadProp, WriteProp
$pwd = Get-DsSchemaAttribute -Name "pwdLastSet"
Get-NtGrantedAccess $sd -ObjectType $pwd

# Listing 11-27
$user = Get-DsSchemaClass -Name "user"
$obj_tree = New-ObjectTypeTree $user
Add-ObjectTypeTree -Tree $obj_tree $attr
Add-ObjectTypeTree -Tree $obj_tree $pwd
Get-NtGrantedAccess $sd -ObjectType $obj_tree -ResultList -PassResult | Format-Table Status, SpecificGrantedAccess, Name
Get-NtGrantedAccess $sd -ObjectType $obj_tree -ResultList -PassResult -Access WriteProp | Format-Table Status, SpecificGrantedAccess, Name

# Listing 11-28
Add-NtSecurityDescriptorAce $sd -KnownSid World -Type AllowedObject -Access WriteProp -ObjectType $user.SchemaId
Get-NtGrantedAccess $sd -ObjectType $obj_tree -ResultList -PassResult | Format-Table Status, SpecificGrantedAccess, Name

# Listing 11-29
(Get-DsSchemaClass user -Recurse -IncludeAuxiliary | Sort-Object SchemaId -Unique | Select-Object -ExpandProperty Attributes).Count

# Listing 11-30
$config_dn = (Get-ADRootDSE).configurationNamingContext
$extended_dn = "CN=Extended-Rights,$config_dn"
Get-ADObject -SearchBase $extended_dn -SearchScope OneLevel -Filter * -Properties * | Group-Object {
 Get-NtAccessMask $_.validAccesses -AsSpecificAccess DirectoryService
}

# Listing 11-31
$attr = Get-DsSchemaAttribute -Name "accountExpires"
$prop_set = Get-DsExtendedRight -Attribute $attr
$prop_set
$user = Get-DsSchemaClass user
Get-DsExtendedRight -SchemaClass $user

# Listing 11-32
$sd = New-NtSecurityDescriptor -Type DirectoryService -Owner "SY" -Group "SY"
Add-NtSecurityDescriptorAce $sd -KnownSid World -Type AllowedObject -Access ReadProp -ObjectType $prop_set.RightsId
Add-NtSecurityDescriptorAce $sd -KnownSid World -Type AllowedObject -Access WriteProp -ObjectType $attr.SchemaId
$obj_tree = New-ObjectTypeTree -SchemaObject $user
Add-ObjectTypeTree -Tree $obj_tree -SchemaObject $prop_set
Get-NtGrantedAccess $sd -ObjectType $prop_set -ResultList -PassResult | Format-Table SpecificGrantedAccess, Name

# Listing 11-33
$pwd = Get-DsSchemaAttribute -Name "pwdLastSet"
Add-NtSecurityDescriptorAce $sd -KnownSid World -Type DeniedObject -Access ReadProp -ObjectType $pwd.SchemaId
Edit-NtSecurityDescriptor $sd -CanonicalizeDacl
Get-NtGrantedAccess $sd -ObjectType $obj_tree -ResultList -PassResult | Format-Table SpecificGrantedAccess, Name

# Listing 11-34
Get-DsExtendedRight | Where-Object {
 $_.IsControl -and $_.Name -match "password"
} | Select-Object Name, RightsId

# Listing 11-35
$sd = New-NtSecurityDescriptor -Type DirectoryService -Owner "SY" -Group "SY"
$right = Get-DsExtendedRight -Name 'User-Change-Password'
Add-NtSecurityDescriptorAce $sd -KnownSid World -Type AllowedObject -Access ControlAccess -ObjectType $right.RightsId
$user = Get-DsSchemaClass user
$obj_tree = New-ObjectTypeTree -SchemaObject $user
Add-ObjectTypeTree -Tree $obj_tree -SchemaObject $right
$force = Get-DsExtendedRight -Name 'User-Force-Change-Password'
Add-ObjectTypeTree -Tree $obj_tree -SchemaObject $force
Get-NtGrantedAccess $sd -ObjectType $obj_tree -ResultList -PassResult | Format-Table Status, SpecificGrantedAccess, Name

# Listing 11-36
Get-DsExtendedRight | Where-Object IsValidatedWrite

# Listing 11-37
$computer = Get-ADComputer -Identity $env:COMPUTERNAME
$computer.SID.ToString()
Get-DsObjectSid -DistinguishedName $computer.DistinguishedName

# Listing 11-38
$root_dn = (Get-ADRootDSE).defaultNamingContext
$obj = Get-ADObject $root_dn -Properties 'ms-DS-MachineAccountQuota'
$obj['ms-DS-MachineAccountQuota']
Get-ADComputer -Filter * -Properties 'mS-DS-CreatorSID' | ForEach-Object {
    $creator = $_['mS-DS-CreatorSID']
    if ($creator.Count -gt 0) {
        $sid = Get-NtSid -Sddl $creator[0]
        Write-Host $_.Name, " - ", $sid.Name
    }
}

# Listing 11-39
$pwd = ConvertTo-SecureString -String "Passw0rd1!!!" -AsPlainText -Force
$name = "DEMOCOMP"
$dnsname = "$name.$((Get-ADDomain).DNSRoot)"
New-ADComputer -Name $name -SAMAccountName "$name`$" -DNSHostName $dnsname -ServicePrincipalNames "HOST/$name" -AccountPassword $pwd -Enabled $true

# Listing 11-40
$sam = Connect-SamServer -ServerName PRIMARYDC
$domain = Get-SamDomain -Server $sam -User
$user = New-SamUser -Domain $domain -Name 'DEMOCOMP$' -AccountType Workstation
$pwd = ConvertTo-SecureString -String "Passw0rd1!!!" -AsPlainText -Force
$user.SetPassword($pwd, $false)

# Listing 11-41
$conf_nc = (Get-ADRootDSE).configurationNamingContext
Get-ADObject -SearchBase $conf_nc -SearchScope Subtree -Filter * | ForEach-Object {
 $sd = Get-Win32SecurityDescriptor -Name $_.DistinguishedName -Type Ds
 if ($sd.RmControl -eq 1) {
    $_.DistinguishedName
 }
}

# Listing 11-42
Get-ADClaimType -Filter {DisplayName -eq "Country"} | Format-List ID, ValueType, SourceAttribute, AppliesToClasses

# Listing 11-43
$policy = Get-ADCentralAccessPolicy -Identity "Secure Room Policy"
$policy | Format-List PolicyID, Members
$policy.Members | ForEach-Object {Get-ADCentralAccessRule -Identity $_} | Format-List Name, ResourceCondition, CurrentAcl

# Listing 11-44
Get-ADOrganizationalUnit -Filter * -Properties gpLink | Format-List Name, LinkedGroupPolicyObjects
$policy = Get-ADObject -Filter {
 ObjectClass -eq "groupPolicyContainer" 
} -Properties *
$policy | Format-List displayName, gPCFileSysPath
ls $policy[0].gPCFileSysPath
$dc_policy = $policy | Where-Object DisplayName -eq "Default Domain Controllers Policy"
$dc_path = $dc_policy.gPCFileSysPath
Get-Content "$dc_path\MACHINE\Microsoft\Windows NT\SecEdit\GptTmpl.inf" | Select-String "SeEnableDelegationPrivilege", "SeMachineAccountPrivilege"

# Listing 11-45
function Add-Member($Set, $MemberOf) {
    foreach($name in $MemberOf) {
        if ($Set.Add($name)) {
            $group = Get-ADGroup $name -Properties MemberOf
            Add-Member $Set $group.MemberOf
        }
    }
}

function Get-UserGroupMembership($User) {
     $groups = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase
     )
    Add-Member $groups $User.PrimaryGroup
    Add-Member $groups $User.MemberOf
    $auth_users = Get-ADObject -Filter {
        ObjectClass -eq "foreignSecurityPrincipal" -and Name -eq "S-1-5-11"
    } -Properties memberOf
    Add-Member $groups $auth_users.MemberOf
    $groups | ForEach-Object { Get-DsObjectSid $_ }
}

function Get-AuthContext($username) {
    $user = Get-ADUser -Identity $username -Properties memberOf, primaryGroup -ErrorAction Continue
    if ($null -eq $user) {
        $user = Get-ADComputer -Identity $username -Properties memberOf, primaryGroup
    }
    $sids = Get-UserGroupMembership $user
    $rm = New-AuthZResourceManager
    $ctx = New-AuthZContext -ResourceManager $rm -Sid $user.SID.Value -Flags SkipTokenGroups
    Add-AuthZSid $ctx -KnownSid World
    Add-AuthZSid $ctx -KnownSid AuthenticatedUsers
    Add-AuthZSid $ctx -Sid $sids
    $rm.Dispose()
    $ctx
}

$ctx = Get-AuthContext "alice"
$ctx.Groups

# Listing 11-46
function Get-ObjectInformation($Name) {
    $schema_class = Get-DsObjectSchemaClass $Name
    $sid = Get-DsObjectSid $Name
    $all_classes = Get-DsSchemaClass $schema_class.Name -Recurse -IncludeAuxiliary
    $attrs = $all_classes.Attributes | Get-DsSchemaAttribute | Sort Name -Unique
    $infs = Get-DsSchemaClass $schema_class.Name -Inferior
    $rights = $all_classes | ForEach-Object {Get-DsExtendedRight -SchemaClass $_ } | Sort Name -Unique
    [PSCustomObject]@{
        Name=$Name
        SecurityDescriptor=Get-Win32SecurityDescriptor -Name $Name -Type Ds
        SchemaClass=Get-DsObjectSchemaClass $Name
        Principal=$sid
        Attributes=$attrs
        Inferiors=$infs
        PropertySets=$rights | Where-Object IsPropertySet
        ControlRight=$rights | Where-Object IsControl
        ValidatedWrite=$rights | Where-Object IsValidatedWrite
    }
}

# Listing 11-47
$dn_root = (Get-ADRootDSE).defaultNamingContext
Get-ObjectInformation $dn_root

# Listing 11-48
function Test-Access($Ctx, $Obj, $ObjTree, $Access) {
    Get-AuthZGrantedAccess -Context $ctx -ObjectType $ObjTree -SecurityDescriptor $Obj.SecurityDescriptor -Principal $Obj.Principal -Access $Access | Where-Object IsSuccess
}

function Get-PropertyObjTree($Obj) {
    $obj_tree = New-ObjectTypeTree $obj.SchemaClass
    foreach($prop_set in $Obj.PropertySets) {
        Add-ObjectTypeTree $obj_tree $prop_set
    }
    $fake_set = Add-ObjectTypeTree $obj_tree -PassThru -ObjectType "771727b1-31b8-4cdf-ae62-4fe39fadf89e"
    foreach($attr in $Obj.Attributes) {
        if (-not $attr.IsPropertySet) {
            Add-ObjectTypeTree $fake_set $attr
        }
    }
    $obj_tree
}

function Get-AccessCheckResult($Ctx, $Name) {
    try {
        $obj = Get-ObjectInformation $Name
        $access = Test-Access $ctx $obj $obj.SchemaClass "MaximumAllowed" | Select-Object -ExpandProperty SpecificGrantedAccess
        $obj_tree = Get-PropertyObjTree $obj
        $write_attr = Test-Access $ctx $obj $obj_tree "WriteProp"
        $write_sets = $write_attr | Where-Object Level -eq 1 | Select-Object -ExpandProperty Name
        $write_attr = $write_attr | Where-Object Level -eq 2 | Select-Object -ExpandProperty Name
        $obj_tree = New-ObjectTypeTree -ObjectType "771727b1-31b8-4cdf-ae62-4fe39fadf89e"
        $obj.Inferiors | Add-ObjectTypeTree -Tree $obj_tree
        $create_child = Test-Access $ctx $obj $obj_tree "CreateChild" | Where-Object Level -eq 1 | Select-Object -ExpandProperty Name
        $delete_child = Test-Access $ctx $obj $obj_tree "DeleteChild" | Where-Object Level -eq 1 | Select-Object -ExpandProperty Name
        $control = if ($obj.ControlRight.Count -gt 0) {
            $obj_tree = New-ObjectTypeTree -SchemaObject $obj.SchemaClass
            $obj.ControlRight | Add-ObjectTypeTree $obj_tree
            Test-Access $ctx $obj $obj_tree "ControlAccess" | Where-Object Level -eq 1 | Select-Object -ExpandProperty Name
        }

        $write_valid = if ($obj.ValidatedWrite.Count -gt 0) {
            $obj_tree = New-ObjectTypeTree -SchemaObject $obj.SchemaClass
            $obj.ValidatedWrite | Add-ObjectTypeTree $obj_tree
            Test-Access $ctx $obj $obj_tree "Self" | Where-Object Level -eq 1 | Select-Object -ExpandProperty Name
        }
        [PSCustomObject]@{
            Name=$Obj.Name
            Access=$access
            WriteAttributes=$write_attr
            WritePropertySets=$write_sets
            CreateChild=$create_child
            DeleteChild=$delete_child
            Control=$control
            WriteValidated=$write_valid
        }
    } catch {
        Write-Error "Error testing $Name - $_"
    }
}

# Listing 11-49
$dn = "CN=GRAPHITE,CN=Computers,DC=mineral,DC=local"
$ctx = Get-AuthContext 'alice'
Get-AccessCheckResult $ctx $dn
$ctx = Get-AuthContext $dn
Get-AccessCheckResult $ctx $dn

# Listing 11-50
Get-AccessibleDsObject -NamingContext Default -Recurse

