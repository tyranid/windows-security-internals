#Requires -RunAsAdministrator

# Listing 4-35
$token = Get-NtToken -Filtered -Flags LuaToken
Set-NtTokenIntegrityLevel Medium -Token $token
$token.Elevated
"Admin" > "$env:windir\admin.txt"
Invoke-NtToken $token { 
    "User" > "$env:windir\user.txt" 
}
$token.Close()