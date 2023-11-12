# Listing 3-1
$lib = Import-Win32Module -Path "kernel32.dll"
$lib
Get-Win32ModuleExport -Module $lib
"{0:X}" -f (Get-Win32ModuleExport -Module $lib -ProcAddress "AllocConsole")

# Listing 3-2
Get-Win32ModuleImport -Path "kernel32.dll"
Get-Win32ModuleImport -Path "kernel32.dll" -DllName "ntdll.dll" | Where-Object Name -Match "^Nt"

# Listing 3-3
ls NtObject:\KnownDlls

# Listing 3-4
Get-NtType WindowStation,Desktop

# Listing 3-5
Get-NtWindowStationName
Get-NtWindowStationName -Current
Get-NtDesktopName
Get-NtDesktopName -Current

# Listing 3-6
$desktop = Get-NtDesktop -Current
Get-NtWindow -Desktop $desktop

# Listing 3-7
$ws = Get-NtWindow
$char_count = 2048
$buf = New-Win32MemoryBuffer -Length ($char_count*2)
foreach($w in $ws) {
    $len = Send-NtWindowMessage -Window $w -Message 0xD -LParam $buf.DangerousGetHandle() -WParam $char_count -Wait
    $txt = $buf.ReadUnicodeString($len.ToInt32())
    if ($txt.Length -eq 0) {
        continue
    }
    "PID: $($w.ProcessId) - $txt"
}
$buf.Dispose()

# Listing 3-8
Get-NtProcess -InfoOnly | Group-Object SessionId

# Listing 3-9
ls NtObjectSession:\ | Group-Object TypeName

# Listing 3-12
Get-Win32Error 5

# Listing 3-13
$m = New-NtMutant ABC -Win32Path
$m.FullPath
$m.Close()

# Listing 3-15
Get-Win32ModuleExport "kernel32.dll" -ProcAddress CreateMutexEx

# Listing 3-16
Get-Win32ModuleExport "kernel32.dll" | Where-Object Name -Match CreateMutexEx

# Listing 3-17
Use-NtObject($key = Get-NtKey \REGISTRY\MACHINE\SOFTWARE) {
 $key.Win32Path
}

Use-NtObject($key = Get-NtKey -Win32Path "HKCU\SOFTWARE") {
 $key.FullPath
}

# Listing 3-18
$key = New-NtKey -Win32Path "HKCU\ABC`0XYZ"
Get-Item "NtKeyUser:\ABC`0XYZ"
Get-Item "HKCU:\ABC`0XYZ"
Remove-NtKey $key
$key.Close()

# Listing 3-19
Use-NtObject($cdrive = Get-NtSymbolicLink "\??\C:") {
 $cdrive | Select-Object FullPath, Target
}

Add-DosDevice Z: C:\Windows
Use-NtObject($zdrive = Get-NtSymbolicLink "\??\Z:") {
 $zdrive | Select-Object FullPath, Target
}
Remove-DosDevice Z:

# Listing 3-20
Set-Location $env:SystemRoot
Get-NtFilePathType "."
Get-NtFilePath "."
Get-NtFilePath "..\"
Get-NtFilePathType "C:ABC"
Get-NtFilePath "C:ABC"
Get-NtFilePathType "\\?\C:\abc/..\xyz"
Get-NtFilePath "\\?\C:\abc/..\xyz"

# Listing 3-21
$path = "C:\$('A'*256)"
$path.Length
Get-NtFilePath -Path $path
$path += "A"
$path.Length
Get-NtFilePath -Path $path
$path = "\\?\" + $path
$path.Length
Get-NtFilePath -Path $path

# Listing 3-22
$path = "HKLM\SYSTEM\CurrentControlSet\Control\FileSystem"
Get-NtKeyValue -Win32Path $path -Name "LongPathsEnabled"
(Get-Process -Id $pid).Path | Get-Win32ModuleManifest | Select-Object LongPathAware
$path = "C:\$('A'*300)"
$path.Length
Get-NtFilePath -Path $path

# Listing 3-23
$base_key = "NtKey:\MACHINE\SOFTWARE\Classes"
Get-Item "$base_key\.txt" | Select-Object -ExpandProperty Values
Get-ChildItem "$base_key\txtfile\Shell" | Format-Table
Get-Item "$base_key\txtfile\Shell\open\Command" |
Select-Object -ExpandProperty Values | Format-Table

# Listing 3-24
Get-Win32Service

# Listing 3-25
$imps = ls "$env:WinDir\*.exe" | ForEach-Object {
 Get-Win32ModuleImport -Path $_.FullName
}
$imps | Where-Object Names -Contains "CreateProcessW" | Select-Object ModulePath

# Listing 3-26
$key = New-NtKey -Win32Path "HKCU\SOFTWARE\`0HIDDENKEY"
ls NtKeyUser:\SOFTWARE -Recurse | Where-Object Name -Match "`0"
Remove-NtKey $key
$key.Close()

# Listing 3-27
$key = New-NtKey -Win32Path "HKCU\SOFTWARE\ABC"
Set-NtKeyValue -Key $key -Name "`0HIDDEN" -String "HELLO"
function Select-HiddenValue {
  [CmdletBinding()]
  param(
   [parameter(ValueFromPipeline)]
   $Key
  )
  Process {
    foreach($val in $Key.Values) {
        if ($val.Name -match "`0") {
            [PSCustomObject]@{
                RelativePath = $Key.RelativePath
                Name = $val.Name
                Value = $val.DataObject
            }
        }
    }
 }
}
ls -Recurse NtKeyUser:\SOFTWARE | Select-HiddenValue | Format-Table
Remove-NtKey $key
$key.Close()