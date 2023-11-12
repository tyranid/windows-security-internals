#Requires -RunAsAdministrator$name = "TestGroup"New-LocalGroup -Name $name -Description "Test Group"
Get-NtSid -Name "$env:COMPUTERNAME\$name"
Add-LocalGroupMember -Name $name -Member "$env:USERDOMAIN\$env:USERNAME"
Get-LocalGroupMember -Name $name

Remove-LocalGroup -Name $name