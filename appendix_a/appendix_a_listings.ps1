# Listing A-1
New-VMSwitch -Name "Domain Network" -SwitchType Internal
$index = (Get-NetAdapter | Where-Object Name -Match "Domain Network").ifIndex
New-NetIPAddress -IPAddress 192.168.99.1 -PrefixLength 24 -InterfaceIndex $index
New-NetNat -Name DomNAT -InternalIPInterfaceAddressPrefix 192.168.99.0/24

# Listing A-2
function New-TestVM {
    param(
        [Parameter(Mandatory)]
        [string]$VmName,
        [Parameter(Mandatory)]
        [string]$InstallerImage,
        [Parameter(Mandatory)]
        [string]$VmDirectory
    )
    New-VM -Name $VmName -MemoryStartupBytes 2GB -Generation 2 -NewVHDPath "$VmDirectory\$VmName\$VmName.vhdx" -NewVHDSizeBytes 80GB -Path "$VmDirectory" -SwitchName "Domain Network"
    Set-VM -Name $VmName -ProcessorCount 2 -DynamicMemory
    Add-VMScsiController -VMName $VmName
    Add-VMDvdDrive -VMName $VmName -ControllerNumber 1 -ControllerLocation 0 -Path $InstallerImage
    $dvd = Get-VMDvdDrive -VMName $VmName
    Set-VMFirmware -VMName $VmName -FirstBootDevice $dvd
}

# Listing A-3
New-TestVM -VmName "PRIMARYDC" -InstallerImage "C:\iso\server.iso" -VmDirectory "C:\vms"
vmconnect localhost PRIMARYDC
Start-VM -VmName "PRIMARYDC"

# Listing A-4
$index = (Get-NetAdapter).ifIndex
New-NetIPAddress -InterfaceIndex $index -IPAddress 192.168.99.10 -PrefixLength 24 -DefaultGateway 192.168.99.1
Set-DnsClientServerAddress -InterfaceIndex $index -ServerAddresses 8.8.8.8

# Listing A-5
Rename-Computer -NewName "PRIMARYDC" -Restart

# Listing A-6
Install-WindowsFeature AD-Domain-Services
Install-ADDSForest -DomainName mineral.local -DomainNetbiosName MINERAL -InstallDns -Force

# Listing A-7
Set-ADDefaultDomainPasswordPolicy -Identity mineral.local -MaxPasswordAge 0
$pwd = ConvertTo-SecureString -String "Passw0rd1" -AsPlainText -Force
New-ADUser -Name alice -Country USA -AccountPassword $pwd -GivenName "Alice Bombas" -Enabled $PS> $pwd = ConvertTo-SecureString -String "Passw0rd2" -AsPlainText -Force
New-ADUser -Name bob -Country JP -AccountPassword $pwd -GivenName "Bob Cordite" -Enabled $true
New-ADGroup -Name 'Local Resource' -GroupScope DomainLocal
Add-ADGroupMember -Identity 'Local Resource' -Members 'alice'
New-ADGroup -Name 'Universal Group' -GroupScope Universal
Add-ADGroupMember -Identity 'Universal Group' -Members 'bob'
New-ADGroup -Name 'Global Group' -GroupScope Global
Add-ADGroupMember -Identity 'Global Group' -Members 'alice','bob'

# Listing A-8
New-TestVM -VmName "GRAPHITE" -InstallerImage "C:\iso\client.iso" -VmDirectory "C:\vms"
vmconnect localhost GRAPHITE
Start-VM -VmName "GRAPHITE"# Listing A-9$index = (Get-NetAdapter).ifIndex
New-NetIPAddress -InterfaceIndex $index -IPAddress 192.168.99.50 -PrefixLength 24 -DefaultGateway 192.168.99.1
Set-DnsClientServerAddress -InterfaceIndex $index -ServerAddresses 192.168.99.10
Resolve-DnsName primarydc.mineral.local
Rename-Computer -NewName "GRAPHITE" -Restart

# Listing A-10
$creds = Get-Credential
Add-Computer -DomainName MINERAL -Credential $creds
Add-LocalGroupMember -Group 'Administrators' -Member 'MINERAL\alice'
Restart-Computer

# Listing A-11
New-TestVM -VmName "SALESDC" -InstallerImage "C:\iso\server.iso" -VmDirectory "C:\vms"
vmconnect localhost SALESDC
Start-VM -VmName "SALESDC"

# Listing A-12
$index = (Get-NetAdapter).ifIndex
New-NetIPAddress -InterfaceIndex $index -IPAddress 192.168.99.110 -PrefixLength 24 -DefaultGateway 192.168.99.1
Set-DnsClientServerAddress -InterfaceIndex $index -ServerAddresses 192.168.99.10
Rename-Computer -NewName "SALESDC" -Restart

# Listing A-13
Install-WindowsFeature AD-Domain-Services
Install-ADDSDomain -NewDomainName sales -ParentDomainName mineral.local -NewDomainNetbiosName SALES -InstallDns -Credential (Get-Credential) -Force

# Listing A-14
Get-ADTrust -Filter * | Select Target, Direction

