param(
    [Parameter(Mandatory, Position = 0)]
    [string]$Hostname,
    [int]$Port = 443
)

Import-Module NtObjectManager
$ErrorActionPreference = "Stop"

function Get-SocketClient {
    param(
        [Parameter(Mandatory)]
        $Socket
    )

    $Socket.ReceiveTimeout = 1000
    $Socket.Client.NoDelay = $true
    $stream = $Socket.GetStream()
    return @{
        Reader = [System.IO.BinaryReader]::new($stream)
        Writer = [System.IO.BinaryWriter]::new($stream)
    }
}

function Read-TlsRecordToken {
    param(
        [Parameter(Mandatory)]
        $Client
    )
    $reader = $Client.Reader
    $header = $reader.ReadBytes(5)
    $length = ([int]$header[3] -shl 8) -bor ($header[4])
    $data = @()
    while($length -gt 0) {
        $next = $reader.ReadBytes($length)
        if ($next.Length -eq 0) {
            throw "End of stream."
        }
        $data += $next
        $length -= $next.Length
    }

    Get-LsaAuthToken -Token ($header+$data)
}

Use-NtObject($socket = [System.Net.Sockets.TcpClient]::new($Hostname, 443)) {
    $tcp_client = Get-SocketClient $socket

    $credout = New-LsaCredentialHandle -Package "SChannel" -UseFlag Outbound
    $client = New-LsaClientContext -CredHandle $credout -Target $Hostname -RequestAttribute ManualCredValidation

    while(!(Test-LsaContext -Context $client)) {
        if ($client.Token.Length -gt 0) {
            $tcp_client.Writer.Write($client.Token.ToArray())
        }

        $record = Read-TlsRecordToken -Client $tcp_client
        Update-LsaClientContext -Client $client -Token $record
    }

    $client.RemoteCertificate
}