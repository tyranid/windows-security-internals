#Requires -RunAsAdministrator

# Listing 10-21
Enable-NtTokenPrivilege SeBackupPrivilege
New-PSDrive -PSProvider NtObjectManager -Name SEC -Root ntkey:MACHINE
ls -Depth 1 -Recurse SEC:\SAM\SAM

# Listing 10-22
$rid = 500
$key = Get-Item ("SEC:\SAM\SAM\Domains\Account\Users\{0:X08}" -f $rid)
$key.Values
function Get-VariableAttribute($key, [int]$Index) {
 $MaxAttr = 0x11
 $V = $key["V"].Data
 $base_ofs = $Index * 12
 $curr_ofs = [System.BitConverter]::ToInt32($V, $base_ofs) + ($MaxAttr * 12)
 $len = [System.BitConverter]::ToInt32($V, $base_ofs + 4)
 if ($len -gt 0) {
    $V[$curr_ofs..($curr_ofs+$len-1)]
 } else {
    @()
 }
}
$sd = Get-VariableAttribute $key -Index 0
New-NtSecurityDescriptor -Byte $sd
Get-VariableAttribute $key -Index 1 | Out-HexDump -ShowAll 

$sd = Get-VariableAttribute $key -Index 0
New-NtSecurityDescriptor -Byte $sd
$lm = Get-VariableAttribute $key -Index 13
$lm | Out-HexDump -ShowAddress
$nt = Get-VariableAttribute $key -Index 14
$nt | Out-HexDump -ShowAddress

# Listing 10-23
function Get-LsaSystemKey {
    $names = "JD", "Skew1", "GBG", "Data"
    $keybase = "NtKey:\MACHINE\SYSTEM\CurrentControlSet\Control\Lsa\"
    $key = $names | ForEach-Object {
    $key = Get-Item "$keybase\$_"
    $key.ClassName | ConvertFrom-HexDump
}
    8, 5, 4, 2, 11, 9, 13, 3, 0, 6, 1, 12, 14, 10, 15, 7 |
    ForEach-Object {
        $key[$_]
    }
}
Get-LsaSystemKey | Out-HexDump

# Listing 10-24
function Unprotect-PasswordEncryptionKey {
    $key = Get-Item SEC:\SAM\SAM\Domains\Account
    $fval = $key["F"].Data
    $enctype = [BitConverter]::ToInt32($fval, 0x68)
    $endofs = [BitConverter]::ToInt32($fval, 0x6C) + 0x68
    $data = $fval[0x70..($endofs-1)]
    switch($enctype) {
        1   { Unprotect-PasswordEncryptionKeyRC4 -Data $data }
        2   { Unprotect-PasswordEncryptionKeyAES -Data $data }
        default { throw "Unknown password encryption format" }
    }
}

# Listing 10-25
function Get-MD5Hash([byte[]]$Data) {
 $md5 = [System.Security.Cryptography.MD5]::Create()
 $md5.ComputeHash($Data)
}

function Get-StringBytes([string]$String) {
 [System.Text.Encoding]::ASCII.GetBytes($String + "`0")
}

function Compare-Bytes([byte[]]$Left, [byte[]]$Right) {
 [Convert]::ToBase64String($Left) -eq [Convert]::ToBase64String($Right)
}

function Unprotect-PasswordEncryptionKeyRC4([byte[]]$Data) {
    $syskey = Get-LsaSystemKey
    $qiv = Get-StringBytes '!@#$%^&*()qwertyUIOPAzxcvbnmQQQQQQQQQQQQ)(*@&%'
    $niv = Get-StringBytes '0123456789012345678901234567890123456789'
    $rc4_key = Get-MD5Hash -Data ($Data[0..15] + $qiv + $syskey + $niv)
    $decbuf = Unprotect-RC4 -Data $data -Offset 0x10 -Length 32 -Key $rc4_key
    $pek = $decbuf[0..15]
    $hash = $decbuf[16..31]
    $pek_hash = Get-MD5Hash -Data ($pek + $niv + $pek + $qiv)
    if (!(Compare-Bytes $hash $pek_hash)) {
        throw "Invalid password key for RC4."
    }
    $pek
}

function Unprotect-AES([byte[]]$Data, [byte[]]$IV, [byte[]]$Key) {
 $aes = [System.Security.Cryptography.Aes]::Create()
 $aes.Mode = "CBC"
 $aes.Padding = "PKCS7"
 $aes.Key = $Key
 $aes.IV = $IV
 $aes.CreateDecryptor().TransformFinalBlock($Data, 0, $Data.Length)
}

# Listing 10-26
function Unprotect-PasswordEncryptionKeyAES([byte[]]$Data) {
 $syskey = Get-LsaSystemKey
 $hash_len = [System.BitConverter]::ToInt32($Data, 0)
 $enc_len = [System.BitConverter]::ToInt32($Data, 4)
 $iv = $Data[0x8..0x17]
 $pek = Unprotect-AES -Key $syskey -IV $iv -Data $Data[0x18..(0x18+$enc_len-1)]
 $hash_ofs = 0x18+$enc_len
 $hash_data = $Data[$hash_ofs..($hash_ofs+$hash_len-1)]
 $hash = Unprotect-AES -Key $syskey -IV $iv -Data $hash_data
 $sha256 = [System.Security.Cryptography.SHA256]::Create()
 $pek_hash = $sha256.ComputeHash($pek)
 if (!(Compare-Bytes $hash $pek_hash)) {
    throw "Invalid password key for AES."
 }
 $pek
}

# Listing 10-27
Unprotect-PasswordEncryptionKey | Out-HexDump

# Listing 10-28
function Unprotect-PasswordHash([byte[]]$Key, [byte[]]$Data, [int]$Rid, [int]$Type) {
 $enc_type = [BitConverter]::ToInt16($Data, 2)
 switch($enc_type) {
     1 { Unprotect-PasswordHashRC4 -Key $Key -Data $Data -Rid $Rid -Type $Type }
     2 { Unprotect-PasswordHashAES -Key $Key -Data $Data }
     default { throw "Unknown hash encryption format" }
 }
}

# Listing 10-29
function Unprotect-PasswordHashRC4([byte[]]$Key, [byte[]]$Data, [int]$Rid, [int]$Type) {
    if ($Data.Length -lt 0x14) {
        return @()
    }
    $iv = switch($Type) {
     1 { "LMPASSWORD" }
     2 { "NTPASSWORD" }
     3 { "LMPASSWORDHISTORY" }
     4 { "NTPASSWORDHISTORY" }
     5 { "MISCCREDDATA" }
    }
    $key_data = $Key + [BitConverter]::GetBytes($Rid) + (Get-StringBytes $iv)
    $rc4_key = Get-MD5Hash -Data $key_data
    Unprotect-RC4 -Key $rc4_key -Data $Data -Offset 4 -Length 16
}

# Listing 10-30
function Unprotect-PasswordHashAES([byte[]]$Key, [byte[]]$Data) {
    $length = [BitConverter]::ToInt32($Data, 4)
    if ($length -eq 0) {
        return @()
    }
    $IV = $Data[8..0x17]
    $value = $Data[0x18..($Data.Length-1)]
    Unprotect-AES -Key $Key -IV $IV -Data $value
}

# Listing 10-31
$pek = Unprotect-PasswordEncryptionKey
$lm_dec = Unprotect-PasswordHash -Key $pek -Data $lm -Rid $rid -Type 1
$lm_dec | Out-HexDump

$nt_dec = Unprotect-PasswordHash -Key $pek -Data $nt -Rid $rid -Type 2
$nt_dec | Out-HexDump

# Listing 10-32
function Get-UserDESKey([uint32]$Rid) {
    $ba = [System.BitConverter]::GetBytes($Rid)
    $key1 = ConvertTo-DESKey $ba[2], $ba[1], $ba[0], $ba[3], $ba[2], $ba[1], $ba[0]
    $key2 = ConvertTo-DESKey $ba[1], $ba[0], $ba[3], $ba[2], $ba[1], $ba[0], $ba[3]
    $key1, $key2
}

function ConvertTo-DESKey([byte[]]$Key) {
 $k = [System.BitConverter]::ToUInt64($Key + 0, 0)
 for($i = 7; $i -ge 0; $i--) {
     $curr = ($k -shr ($i * 7)) -band 0x7F
     $b = $curr
     $b = $b -bxor ($b -shr 4)
     $b = $b -bxor ($b -shr 2)
     $b = $b -bxor ($b -shr 1)
     ($curr -shl 1) -bxor ($b -band 0x1) -bxor 1
 }
}

# Listing 10-33
function Unprotect-DES([byte[]]$Key, [byte[]]$Data, [int]$Offset) {
 $des = [Security.Cryptography.DES]::Create()
 $des.Key = $Key
 $des.Mode = "ECB"
 $des.Padding = "None"
 $des.CreateDecryptor().TransformFinalBlock($Data, $Offset, 8)
}

function Unprotect-PasswordHashDES([byte[]]$Hash, [uint32]$Rid) {
 $keys = Get-UserDESKey -Rid $Rid
 (Unprotect-DES -Key $keys[0] -Data $Hash -Offset 0) +
 (Unprotect-DES -Key $keys[1] -Data $Hash -Offset 8)
}

# Listing 10-34
Unprotect-PasswordHashDES -Hash $nt_dec -Rid $rid | Out-HexDump
Get-MD4Hash -String "adminpwd" | Out-HexDump