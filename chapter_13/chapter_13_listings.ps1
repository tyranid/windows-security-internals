# Listing 13-1
$credout = New-LsaCredentialHandle -Package "NTLM" -UseFlag Outbound -UserName $env:USERNAME -Domain $env:USERDOMAIN
$client = New-LsaClientContext -CredHandle $credout
$negToken = $client.Token
Format-LsaAuthToken -Token $negToken

# Listing 13-2
Format-LsaAuthToken -Token $client.Token -AsBytes

# Listing 13-3
$credin = New-LsaCredentialHandle -Package "NTLM" -UseFlag Inbound
$server = New-LsaServerContext -CredHandle $credin
Update-LsaServerContext -Server $server -Token $client.Token
$challengeToken = $server.Token
Format-LsaAuthToken -Token $server.Token

# Listing 13-4
Update-LsaClientContext -Client $client -Token $server.Token
$authToken = $client.Token
Format-LsaAuthToken -Token $client.Token

# Listing 13-5
Update-LsaServerContext -Server $server -Token $client.Token
if ((Test-LsaContext $client) -and (Test-LsaContext $server)) {
    Use-NtObject($token = Get-LsaAccessToken $server) {
    Get-NtLogonSession -Token $token
 }
}

# Listing 13-6
function Get-Md5Hmac {
    Param(
        $Key,
        $Data
    )
    $algo = [System.Security.Cryptography.HMACMD5]::new($Key)
    if ($Data -is [string]) {
        $Data = [System.Text.Encoding]::Unicode.GetBytes($Data)
    }
    $algo.ComputeHash($Data)
}

# Listing 13-7
function Get-NtOwfv2 {
    Param(
        $Password,
        $UserName,
        $Domain
    )
    $key = Get-MD4Hash -String $Password
    Get-Md5Hmac -Key $key -Data ($UserName.ToUpperInvariant() + $Domain)
}

$key = Get-NtOwfv2 -Password "pwd" -UserName $authToken.UserName -Domain $authToken.Domain
$key | Out-HexDump

# Listing 13-8
function Get-NtProofStr {
    Param(
        $Key,
        $ChallengeToken,
        $AuthToken
    )
    $data = $ChallengeToken.ServerChallenge
    $last_index = $AuthToken.NtChallengeResponse.Length - 1
    $data += $AuthToken.NtChallengeResponse[16..$last_index]
    Get-Md5Hmac -Key $Key -Data $data
}

$proof = Get-NtProofStr -Key $key -ChallengeToken $ChallengeToken -AuthToken $AuthToken
$proof | Out-HexDump

# Listing 13-9
function Get-Mic {
    Param(
        $Key,
        $Proof,
        $NegToken,
        $ChallengeToken,
        $AuthToken
    )
    $session_key = Get-Md5Hmac -Key $Key -Data $Proof
    $auth_data = $AuthToken.ToArray()
    [array]::Clear($auth_data, $AuthToken.MessageIntegrityCodeOffset, 16)
    $data = $NegToken.ToArray() + $ChallengeToken.ToArray() + $auth_data
    Get-Md5Hmac -Key $session_key -Data $data
}
$mic = Get-Mic -Key $key -Proof $proof -NegToken $NegToken -ChallengeToken $ChallengeToken -AuthToken $AuthToken
$mic | Out-HexDump

# Listing 13-10
$credout = New-LsaCredentialHandle -Package "NTLM" -UseFlag Outbound
$client = New-LsaClientContext -CredHandle $credout
Format-LsaAuthToken $client

$credin = New-LsaCredentialHandle -Package "NTLM" -UseFlag Inbound
$server = New-LsaServerContext -CredHandle $credin
Update-LsaServerContext -Server $server -Client $client
Format-LsaAuthToken $server

Update-LsaClientContext -Client $client -Server $server
Format-LsaAuthToken $client

Update-LsaServerContext -Server $server -Client $client
if ((Test-LsaContext $client) -and (Test-LsaContext $server)) {
    Use-NtObject($token = Get-LsaAccessToken $server) {
    Get-NtLogonSession -Token $token
 }
}
Get-NtTokenId -Authentication

# Listing 13-11
$cout = New-LsaCredentialHandle -Package NTLM -UseFlag Outbound -ReadCredential

# Listing 13-13
$password = Read-Host -AsSecureString -Prompt "Password"
$new_token = Get-NtToken -Logon -LogonType NewCredentials -User "Administrator" -Domain "GRAPHITE" -SecurePassword $password
$credout = Invoke-NtToken $new_token {
    New-LsaCredentialHandle -Package "NTLM" -UseFlag Outbound
}

# Listing 13-14
$client = New-LsaClientContext -CredHandle $credout -RequestAttribute Integrity

# Listing 13-15
function Get-Mic {
    Param(
        $Key,
        $Proof,
        $NegToken,
        $ChallengeToken,
        $AuthToken
    )
    $session_key = Get-Md5Hmac -Key $Key -Data $Proof
    if ($authToken.EncryptedSessionKey.Count -gt 0) {
        $session_key = Unprotect-RC4 -Key $session_key -Data $AuthToken.EncryptedSessionKey
    }
    $auth_data = $AuthToken.ToArray()
    [array]::Clear($auth_data, $AuthToken.MessageIntegrityCodeOffset, 16)
    $data = $NegToken.ToArray() + $ChallengeToken.ToArray() + $auth_data
    Get-Md5Hmac -Key $session_key -Data $data
}

# Listing 13-16
$server = New-LsaServerContext -CredHandle $credin
Update-LsaServerContext $server $client
Update-LsaClientContext $client $server
Update-LsaServerContext $server $client
$msg = $(0, 1, 2, 3)
$sig = Get-LsaContextSignature -Context $client -Message $msg
$sig | Out-HexDump
Test-LsaContextSignature -Context $server -Message $msg -Signature $sig
Test-LsaContextSignature -Context $server -Message $msg -Signature $sig

# Listing 13-17
$server.SessionKey | Out-HexDump
$client.SessionKey | Out-HexDump

# Listing 13-18
function Get-BindingHash {
    Param(
    [byte[]]$ChannelBinding
    )
    $stm = [System.IO.MemoryStream]::new()
    $writer = [System.IO.BinaryWriter]::new($stm)
    $writer.Write(0) # dwInitiatorAddrType
    $writer.Write(0) # cbInitiatorLength
    $writer.Write(0) # dwAcceptorAddrType
    $writer.Write(0) # cbAcceptorLength
    $writer.Write($ChannelBinding.Count) # cbApplicationDataLength
    $writer.Write($ChannelBinding) # Application Data
    [System.Security.Cryptography.MD5Cng]::new().ComputeHash($stm.ToArray())
}
Get-BindingHash -ChannelBinding @(1, 2, 3) | Out-HexDump