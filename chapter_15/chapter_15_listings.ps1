# Listing 15-1
$in_buf = New-LsaSecurityBuffer -Type PkgParams -String "AuthParam"
$out_buf = New-LsaSecurityBuffer -Type Data -Size 100
Update-LsaClientContext -Client $client -Token $token -InputBuffer $in_buf -OutputBuffer $out_buf
$out_buf.Type
ConvertFrom-LsaSecurityBuffer $out_buf | Out-HexDump

# Listing 15-2
$header = New-LsaSecurityBuffer -Type Data -Byte @(0, 1, 3, 4) -ReadOnlyWithChecksum
$data = New-LsaSecurityBuffer -Type Data -String "HELLO"
$sig = Protect-LsaContextMessage -Context $client -Buffer $header, $data
ConvertFrom-LsaSecurityBuffer -Buffer $header | Out-HexDump
ConvertFrom-LsaSecurityBuffer -Buffer $data | Out-HexDump
Unprotect-LsaContextMessage -Context $server -Buffer $header, $data -Signature $sig
ConvertFrom-LsaSecurityBuffer -Buffer $data -AsString

# Listing 15-3
$credout = New-LsaCredentialHandle -Package "Negotiate" -UseFlag Outbound
$client = New-LsaClientContext -CredHandle $credout
Format-LsaAuthToken -Token $client.Token

# Listing 15-4
$credin = New-LsaCredentialHandle -Package "Negotiate" -UseFlag Inbound
$server = New-LsaServerContext -CredHandle $credin
Update-LsaServerContext -Server $server -Token $client.Token
Format-LsaAuthToken -Token $server.Token

# Listing 15-5
Update-LsaClientContext -Client $client -Token $server.Token
Format-LsaAuthToken -Token $client.Token
Update-LsaServerContext -Server $server -Token $client.Token
Format-LsaAuthToken -Token $server.Token
Update-LsaClientContext -Client $client -Token $server.Token
$client.PackageName

# Listing 15-6
$credout = New-LsaCredentialHandle -Package "Schannel" -UseFlag Outbound
$name = "NotReallyReal.com"
$client = New-LsaClientContext -CredHandle $credout -Target $name -RequestAttribute ManualCredValidation
Format-LsaAuthToken -Token $client.Token

# Listing 15-7
$store = "Cert:\CurrentUser\My"
$cert = Get-ChildItem $store | Where-Object Subject -Match $name
if ($null -eq $cert) {
    $cert = New-SelfSignedCertificate -DnsName $name -CertStoreLocation $store
}
$server_cred = Get-LsaSchannelCredential -Certificate $cert
$credin = New-LsaCredentialHandle -Package "Schannel" -UseFlag Inbound -Credential $server_cred
$server = New-LsaServerContext -CredHandle $credin
while(!(Test-LsaContext $client) -and !(Test-LsaContext $server)) {
    Update-LsaServerContext -Server $server -Client $client
    Update-LsaClientContext -Client $client -Server $server
}

# Listing 15-8
$client.ConnectionInfo
$client.RemoteCertificate
$server.ConnectionInfo

# Listing 15-9
$header = New-LsaSecurityBuffer -Type StreamHeader -Size $client.StreamHeaderSize
$data = New-LsaSecurityBuffer -Type Data -Byte 0, 1, 2, 3
$trailer = New-LsaSecurityBuffer -Type StreamTrailer -Size $client.StreamTrailerSize
$empty = New-LsaSecurityBuffer -Empty
$bufs = $header, $data, $trailer, $empty
Protect-LsaContextMessage -Context $client -Buffer $bufs -NoSignature
$msg = $header, $data, $trailer | ConvertFrom-LsaSecurityBuffer
$msg_token = Get-LsaAuthToken -Context $client -Token $msg
Format-LsaAuthToken $msg_token
$header = New-LsaSecurityBuffer -Type Data -Byte $msg
$data = New-LsaSecurityBuffer -Empty
$trailer = New-LsaSecurityBuffer -Empty
$empty = New-LsaSecurityBuffer -Empty
$bufs = $header, $data, $trailer, $empty
Unprotect-LsaContextMessage -Context $server -Buffer $bufs -NoSignature
ConvertFrom-LsaSecurityBuffer $data | Out-HexDump

# Listing 15-10
Get-Win32Credential "TERMSRV/primarydc.domain.local" DomainPassword | Format-Table UserName, Password

# Listing 15-11
ls "$env:LOCALAPPDATA\Microsoft\Credentials" -Hidden

# Listing 15-12
Add-Type -AssemblyName "System.Security"
ls "$env:LOCALAPPDATA\Microsoft\Credentials" -h | ForEach-Object {
    $ba = Get-Content -Path $_.FullName -Encoding Byte
    [Security.Cryptography.ProtectedData]::Unprotect($ba,$null,"CurrentUser")
}

# Listing 15-14
$client = New-LsaClientContext -CredHandle $credout -RequestAttribute NullSession

# Listing 15-20
$cred = New-LsaCredentialHandle -Package "Negotiate" -UseFlag Outbound
$sid = Get-NtSid -PackageName "network_auth_test"
Use-NtObject($token = Get-NtToken -LowBox -PackageSid $sid) {
    Invoke-NtToken $token { New-LsaClientContext -CredHandle $cred }
}

$cap = Get-NtSid -KnownSid CapabilityEnterpriseAuthentication
Use-NtObject($token = Get-NtToken -LowBox -PackageSid $sid -CapabilitySid $cap) {
    $auth = Invoke-NtToken $token { New-LsaClientContext -CredHandle $cred }
    Format-LsaAuthToken $auth
}

# Listing 15-21
$cred = New-LsaCredentialHandle -Package "NTLM" -UseFlag Outbound
$client = New-Object System.Net.WebClient
$proxy = $client.Proxy.GetProxy("http://www.microsoft.com").Authority
$target = "HTTP/$proxy"
$target | Write-Output
$sid = Get-NtSid -PackageName "network_auth_test"
Use-NtObject($token = Get-NtToken -LowBox -PackageSid $sid) {
    $client = Invoke-NtToken $token {
        New-LsaClientContext -CredHandle $cred -Target $target
    }
    Format-LsaAuthToken $client
}

# Listing 15-22
$cred = New-LsaCredentialHandle -Package "Negotiate" -UseFlag Outbound -ReadCredential
$sid = Get-NtSid -PackageName "network_auth_test"
Use-NtObject($token = Get-NtToken -LowBox -PackageSid $sid) {
    Invoke-NtToken $token {
        $c = New-LsaClientContext -CredHandle $cred -Target "CIFS/localhost"
        Format-LsaAuthToken $c
    }
}

# Listing 15-31
$cert = .\get_server_cert.ps1 -Hostname www.microsoft.com
$cert
$cert | Export-Certificate -FilePath output.cer