#Requires -RunAsAdministrator

# Listing 15-23
Get-WinEvent -FilterHashtable @{logname='Security';id=@(4624)} |
Select-Object -ExpandProperty Message

# Listing 15-25
Get-WinEvent -FilterHashtable @{logname='Security';id=@(4625)} |
Select-Object -ExpandProperty Message

# Listing 15-26
Get-WinEvent -FilterHashtable @{logname='Security';id=@(4634)} |
Select-Object -ExpandProperty Message