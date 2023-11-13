#Requires -RunAsAdministrator

# Listing 11-7
Get-LsaPrivateData '$MACHINE.ACC' | Out-HexDump -ShowAll