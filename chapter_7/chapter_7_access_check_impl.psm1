Set-StrictMode -Version Latest

Import-Module NtObjectManager

function Test-ProcessTrustLevel {
    param($context)

    $trust_level = Get-NtTokenSid $context.Token -TrustLevel
    if ($null -EQ $trust_level) {
        $trust_level = Get-NtSid -TrustType None -TrustLevel None
    }

    $access = Get-NtAccessMask 0xFFFFFFFF
    $sacl = Get-NtSecurityDescriptorSacl $context.SecurityDescriptor
    foreach($ace in $sacl) {
        if (!$ace.IsProcessTrustLabelAce -or $ace.IsInheritOnly) {
            continue
        }

        if (!(Compare-NtSid $trust_level $ace.Sid -Dominates)) {
            $access = Get-NtAccessMask $ace
        }
        break
    }

    $access = Grant-NtAccessMask $access AccessSystemSecurity
    return Test-NtAccessMask $access $context.RemainingAccess -All
}

function Test-AccessFilter {
    param($context)

    $token = $context.Token
    $access = Get-NtAccessMask 0xFFFFFFFF
    $sacl = Get-NtSecurityDescriptorSacl $context.SecurityDescriptor
    foreach($ace in $sacl) {
        if (!$ace.IsAccessFilterAce -or $ace.IsInheritOnly) {
            continue
        }
        if (!(Test-NtAceCondition $ace -Token $token)) {
            $access = $access -band $ace.Mask
        }
    }

    $access = Grant-NtAccessMask $access AccessSystemSecurity
    return Test-NtAccessMask $access $context.RemainingAccess -All
}

function Test-MandatoryIntegrityLevel {
    param($context)

    $token = $context.Token
    $sd = $context.SecurityDescriptor
    $mapping = $context.GenericMapping

    $policy = Get-NtTokenMandatoryPolicy -Token $token
    if (($policy -band "NoWriteUp") -eq 0) {
        return $true
    }

    if ($sd.HasMandatoryLabelAce) {
        $ace = $sd.GetMandatoryLabel()
        $sd_il_sid = $ace.Sid
        $access = Get-NtAccessMask $ace.Mask -GenericMapping $mapping
    } else {
        $sd_il_sid = Get-NtSid -IntegrityLevel Medium
        $access = Get-NtAccessMask -ManadatoryLabelPolicy NoWriteUp -GenericMapping $mapping
    }

    if (Test-NtTokenPrivilege -Token $token SeRelabelPrivilege) {
        $access = Grant-NtAccessMask $access WriteOwner
    }

    $il_sid = Get-NtTokenSid -Token $token -Integrity
    if (Compare-NtSid $il_sid $sd_il_sid -Dominates) {
        return $true
    }

    return Test-NtAccessMask $access $context.RemainingAccess -All
}

# Mandatory Acccess Implementation
function Test-MandatoryAccess {
    param($context)

    if (!(Test-ProcessTrustLevel $context)) {
        return $false
    }

    if (!(Test-AccessFilter $context)) {
        return $false
    }

    if (!(Test-MandatoryIntegrityLevel $context)) {
        if (!$context.Token.AppContainer -or `
            $context.SecurityDescriptor.IntegrityLevel -le "Medium") {
            return $false    
        }
    }

    return $true
}

function Resolve-TokenPrivilegeAccess {
    param($context)

    $token = $context.Token
    $access = $context.RemainingAccess

    if ((Test-NtAccessMask $access AccessSystemSecurity) -and
        (Test-NtTokenPrivilege -Token $token SeSecurityPrivilege)) {
        $access = Revoke-NtAccessMask $access AccessSystemSecurity
        $context.Privileges += "SeSecurityPrivilege"
    }

    if ((Test-NtAccessMask $access WriteOwner) -and
        (Test-NtTokenPrivilege -Token $token SeTakeOwnershipPrivilege)) {
        $access = Revoke-NtAccessMask $access WriteOwner
        $context.Privileges += "SeTakeOwnershipPrivilege"
    }

    if ((Test-NtAccessMask $access WriteOwner) -and
        (Test-NtTokenPrivilege -Token $token SeRelabelPrivilege)) {
        $access = Revoke-NtAccessMask $access WriteOwner
        $context.Privileges += "SeRelabelPrivilege"
    }

    $context.RemainingAccess = $access
}

function Resolve-TokenOwnerAccess {
    param($context)

    $token = $context.Token
    $sd = $context.SecurityDescriptor
    $sd_owner = Get-NtSecurityDescriptorOwner $sd
    if (!(Test-NtTokenGroup -Token $token -Sid $sd_owner.Sid)) {
        return
    }

    if ($token.Restricted -and `
      !(Test-NtTokenGroup -Token $token -Sid $sd_owner.Sid -Restricted)) {
        return
    }

    $sids = Select-NtSecurityDescriptorAce $sd -KnownSid OwnerRights -First -AclType Dacl
    if ($sids -ne $null -and $sids.Count -gt 0) {
        return
    }

    $access = $context.RemainingAccess
    $context.RemainingAccess = Revoke-NtAccessMask $access ReadControl, WriteDac
}

function Resolve-TokenAccess {
    param($context)

    Resolve-TokenPrivilegeAccess $context
    if (Test-NtAccessMask $context.RemainingAccess -Empty) {
        return
    }
    Resolve-TokenOwnerAccess $context
}

function Get-AceSid {
    param(
        $Sid,
        $Owner,
        $Principal
    )

    if (Compare-NtSid $sid -KnownSid OwnerRights) {
        $sid = $Owner.Sid
    }

    if ((Compare-NtSid $Sid -KnownSid Self) -and ($Principal -NE $null)) {
        $sid = $Principal
    }

    return $sid
}

function Get-DiscretionaryAccess {
    param(
        $context,
        [switch]$Restricted
    )

    $token = $context.Token
    $sd = $context.SecurityDescriptor
    $access = $context.RemainingAccess
    $ac_access = $context.DesiredAccess
    if (!$token.AppContainer) {
        $ac_access = Get-NtAccessMask 0
    }
    $effective_access = Get-NtAccessMask 0
    $resource_attrs = $null
    if ($sd.ResourceAttributes.Count -gt 0) {
        $resource_attrs = $sd.ResourceAttributes.ResourceAttribute
    }

    if (!$token.AppContainer) {
        if (!(Test-NtSecurityDescriptor $sd -DaclPresent) `
            -or (Test-NtSecurityDescriptor $sd -DaclNull)) {
            $context.RemainingAccess = Get-NtAccessMask 0
            return
        }
    }

    $owner = Get-NtSecurityDescriptorOwner $sd
    $dacl = Get-NtSecurityDescriptorDacl $sd

    foreach($ace in $dacl) {
        if ($ace.IsInheritOnly) {
            continue
        }
        $sid = Get-AceSid -Sid $ace.Sid -Owner $owner -Principal $context.Principal
        $continue_check = $true
        switch($ace.Type) {
            "Allowed" {
                if (Test-NtTokenGroup -Token $token $sid -Restricted:$Restricted) {
                    $access = Revoke-NtAccessMask $access $ace.Mask
                } else {
                    if ($Restricted) {
                        break
                    }

                    if (Test-NtTokenGroup -Token $token $sid -Capability) {
                        $ac_access = Revoke-NtAccessMask $ac_access $ace.Mask
                    }
                }
            }
            "Denied" {
                if (Test-NtTokenGroup -Token $token $sid -DenyOnly -Restricted:$Restricted) {
                    if (Test-NtAccessMask $access $ace.Mask) {
                        $continue_check = $false
                    }
                }
            }
            "AllowedCompound" {
                $server_sid = Get-AceSid -Sid $ace.ServerSid -Owner $owner -Principal $context.Principal
                if ((Test-NtTokenGroup -Token $Token $sid -Restricted:$Restricted) -and (Test-NtTokenGroup -Sid $server_sid -Restricted:$Restricted)) {
                    $access = Revoke-NtAccessMask $access $ace.Mask
                }
            }
            "AllowedCallback" {
                if (!(Test-NtAceCondition $ace -Token $token -ResourceAttribute $resource_attrs)) {
                    break
                }

                if (Test-NtTokenGroup -Token $token $sid -Restricted:$Restricted) {
                    $access = Revoke-NtAccessMask $access $ace.Mask
                } else {
                    if ($Restricted) {
                        break
                    }

                    if (Test-NtTokenGroup -Token $token $sid -Capability) {
                        $ac_access = Revoke-NtAccessMask $ac_access $ace.Mask
                    }
                }
            }
            "AllowedObject" {
                if (!(Test-NtTokenGroup -Token $token $sid -Restricted:$Restricted)) {
                    break
                }

                if ($null -EQ $context.ObjectTypes -or $null -EQ $ace.ObjectType) {
                    break
                }

                $object_type = Select-ObjectTypeTree $context.ObjectTypes
                if ($null -EQ $object_type) {
                    break
                }

                Revoke-ObjectTypeTreeAccess $object_type $ace.Mask
                $access = Revoke-NtAccessMask $access $ace.Mask
            }
            "DeniedObject" {
                if (!(Test-NtTokenGroup -Token $token $sid -DenyOnly -Restricted:$Restricted)) {
                    break
                }

                if ($null -NE $context.ObjectTypes) {
                    if ($null -EQ $ace.ObjectType) {
                        break;
                    }

                    $object_type = Select-ObjectTypeTree $context.ObjectTypes $ace.ObjectType
                    if ($null -EQ $object_type) {
                        break
                    }

                    if (Test-NtAccessMask $object_type.RemainingAccess $ace.Mask) {
                        $continue_check = $false
                        break
                    } 
                }
                if (Test-NtAccessMask $access $ace.Mask) {
                    $continue_check = $false
                }
            }
        }

        $effective_access = $access -bor $ac_access

        if (!$continue_check -or (Test-NtAccessMask $effective_access -Empty)) {
            break
        }
    }

    $context.RemainingAccess = $effective_access
}

function Get-AccessResult {
    param(
        $Status,
        $Privileges = @(),
        $GrantedAccess = 0
    )

    $props = @{
      Status = Get-NtStatus -Name $Status -PassStatus
      GrantedAccess = $GrantedAccess
      Privileges = $Privileges
    }
    return New-Object –TypeName PSObject -Prop $props
}

function Get-PSGrantedAccess {
    param(
        $Token,
		[parameter(Mandatory)]
        $SecurityDescriptor,
		[parameter(Mandatory)]
        $GenericMapping,
		[parameter(Mandatory)]
        $DesiredAccess,
        $Principal,
        $ObjectTypes
    )

    if ($null -EQ $Token) {
        $Token = Get-NtToken -Effective -Pseudo
    }

    $context = @{
        Token = $Token
        SecurityDescriptor = $SecurityDescriptor
        GenericMapping = $GenericMapping
        RemainingAccess = Get-NtAccessMask $DesiredAccess
        DesiredAccess = $DesiredAccess
        Privileges = @()
        Principal = $Principal
        ObjectTypes = $ObjectTypes
    }

    if (!(Test-MandatoryAccess $context)) {
        return Get-AccessResult STATUS_ACCESS_DENIED
    }

    Resolve-TokenAccess $context
    if ((Test-NtAccessMask $context.RemainingAccess -Empty) -and !$Token.AppContainer) {
        return Get-AccessResult STATUS_SUCCESS $context.Privileges $DesiredAccess
    }

    # The only way to get AccessSystemSecurity is from the privilege check.
    if (Test-NtAccessMask $context.RemainingAccess AccessSystemSecurity) {
        return Get-AccessResult STATUS_PRIVILEGE_NOT_HELD
    }

    $RemainingAccess = $context.RemainingAccess
    Get-DiscretionaryAccess $context
    $success = Test-NtAccessMask $context.RemainingAccess -Empty
    
    $write = $Token.WriteRestricted -and (Test-NtAccessMask $RemainingAccess -WriteRestricted $GenericMapping)

    if ($success -and $Token.Restricted) {
        if (!$Token.WriteRestricted -OR (Test-NtAccessMask $RemainingAccess -WriteRestricted $GenericMapping)) {
            $context.RemainingAccess = $RemainingAccess
            Get-DiscretionaryAccess $context -Restricted
            $success = Test-NtAccessMask $context.RemainingAccess -Empty
        }
    }

    if (!$success) {
        return Get-AccessResult STATUS_ACCESS_DENIED
    }
    
    $capid = $SecurityDescriptor.ScopedPolicyId
    if ($null -EQ $capid) {
        return Get-AccessResult STATUS_SUCCESS $context.Privileges $DesiredAccess
    }

    $policy = Get-CentralAccessPolicy -CapId $capid.Sid
    if ($null -EQ $policy){
        return Get-AccessResult STATUS_SUCCESS $context.Privileges $DesiredAccess
    }

    foreach($rule in $policy.Rules) {
        if ($rule.AppliesTo -NE "") {
            $resource_attrs = $null
            if ($sd.ResourceAttributes.Count -gt 0) {
                $resource_attrs = $sd.ResourceAttributes.ResourceAttribute
            }
            if (!(Test-NtAceCondition -Token $Token -Condition $rule.AppliesTo -ResourceAttribute $resource_attrs)) {
                continue
            }
        }
        $new_sd = Copy-NtSecurityDescriptor $SecurityDescriptor
        Set-NtSecurityDescriptorDacl -SecurityDescriptor $new_sd -Ace $rule.SecurityDescriptor.Dacl

        $context.SecurityDescriptor = $new_sd
        $context.RemainingAccess = $DesiredAccess

        Get-DiscretionaryAccess $context
        if (!(Test-NtAccessMask $context.RemainingAccess -Empty)) {
          return Get-AccessResult STATUS_ACCESS_DENIED
        }
    }

    return Get-AccessResult STATUS_SUCCESS $context.Privileges $DesiredAccess
}

Export-ModuleMember -Function Get-PSGrantedAccess
