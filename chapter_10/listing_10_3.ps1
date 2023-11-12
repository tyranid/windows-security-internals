#Requires -RunAsAdministrator

# Listing 10-3
$password = Read-Host -AsSecureString -Prompt "Password"
$name = "Test"
New-LocalUser -Name $name -Password $password -Description "Test User"
Get-NtSid -Name "$env:COMPUTERNAME\$name"

Remove-LocalUser -Name $name