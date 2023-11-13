#Requires -RunAsAdministrator

# Listing 14-32
$sess = Get-NtLogonSession
$tickets = Invoke-NtToken -System { Get-KerberosTicket -LogonSession $sess }
$tickets | Select-Object ServiceName, { Format-HexDump $_.SessionKey.Key }