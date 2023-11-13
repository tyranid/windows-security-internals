param(
    [switch]$Global,
    [int]$Port = 6543
)

Import-Module "$PSScriptRoot\network_protocol_common.psm1"

$socket = $null
$listener = $null
$context = $null
$credin = $null

try {
    $Address = if ($Global) { 
        [ipaddress]::Any
    } else {
        [ipaddress]::Loopback
    }
    
    $listener = [System.Net.Sockets.TcpListener]::new($Address, $port)
    $listener.Start()
    $socket = $listener.AcceptTcpClient()
    $client = Get-SocketClient -Socket $socket

    Write-Host "Connection received from $($socket.Client.RemoteEndPoint)"

    $credin = New-LsaCredentialHandle -Package "NTLM" -UseFlag Inbound 
    $context = New-LsaServerContext -CredHandle $credin -RequestAttribute Confidentiality

    $neg_token = Receive-Message -Client $client
    Update-LsaServerContext -Server $context -Token $neg_token
    Send-Message -Client $client -Message $context.Token.ToArray()
    $auth_token = Receive-Message -Client $client
    Update-LsaServerContext -Server $context -Token $auth_token

    if (!(Test-LsaContext -Context $context)) {
        throw "Authentication didn't complete as expected."
    }

    $target = "BOOK/$($socket.Client.LocalEndPoint.Address)"
    if ($context.ClientTargetName -ne $target) {
        throw "Incorrect target name specified: $($context.ClientTargetName)."
    }

    $user = Use-NtObject($token = Get-LsaAccessToken -Server $context) {
        $token.User
    }
    Write-Host "User $user has authenticated."
    Send-TextMessage -Client $client -Message "OK" -Context $context

    $msg = Receive-TextMessage -Client $client -Context $context
    while($msg -ne "") {
        Write-Host "> $msg"
        $reply = "User {0} said: {1}" -f $user, $msg.ToUpper()
        Send-TextMessage -Client $client -Message $reply -Context $context
        $msg = Receive-TextMessage -Client $client -Context $context
    }
} catch {
    Write-Error $_
} finally {
    if ($null -ne $socket) {
        $socket.Close()
    }
    if ($null -ne $listener) {
        $listener.Stop()
    }
    if ($null -ne $context) {
        $context.Dispose()
    }
    if ($null -ne $credin) {
        $credin.Dispose()
    }
}
