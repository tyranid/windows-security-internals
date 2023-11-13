param(
    [ipaddress]$Address = [ipaddress]::Loopback,
    [int]$Port = 6543
)

Import-Module "$PSScriptRoot\network_protocol_common.psm1"

$socket = $null
$context = $null
$credout = $null

try {
    $socket = [System.Net.Sockets.TcpClient]::new()
    $socket.Connect($Address, $port)
    $client = Get-SocketClient -Socket $socket
    Write-Host "Connected to server $($socket.Client.RemoteEndPoint)"

    $credout = New-LsaCredentialHandle -Package "NTLM" -UseFlag Outbound
    $context = New-LsaClientContext -CredHandle $credout -RequestAttribute Confidentiality -Target "BOOK/$Address"
    Send-Message -Client $client -Message $context.Token.ToArray()
    $chal_token = Receive-Message -Client $client
    Update-LsaClientContext -Client $context -Token $chal_token
    Send-Message -Client $client -Message $context.Token.ToArray()

    if (!(Test-LsaContext -Context $context)) {
        throw "Authentication didn't complete as expected."
    }

    $ok_msg = Receive-TextMessage -Client $client -Context $context
    if ($ok_msg -ne "OK") {
        throw "Failed to authenticate."
    }

    $msg = Read-Host -Prompt "MSG"
    while($msg -ne "") {
        Send-TextMessage -Client $client -Context $context -Message $msg
        $recv_msg = Receive-TextMessage -Client $client -Context $context
        Write-Host "> $recv_msg"
        $msg = Read-Host -Prompt "MSG"
    }
    
} catch {
    Write-Error $_
} finally {
    if ($null -ne $socket) {
        $socket.Close()
    }
    if ($null -ne $context) {
        $context.Dispose()
    }
    if ($null -ne $credout) {
        $credout.Dispose()
    }
}
