#Requires -RunAsAdministrator

# Listing 12-9
Get-NtToken -Logon -LogonType Service -Domain 'NT AUTHORITY' -User SYSTEM -WithTcb
Get-NtToken -Service System -WithTcb