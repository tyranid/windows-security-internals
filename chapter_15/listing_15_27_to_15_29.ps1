#Requires -RunAsAdministrator

# Listing 15-27
$record = Get-WinEvent -FilterHashtable @{logname='Security';id=@(4634)} | Select -First 1
$record.Properties

# Listing 15-28
function Get-EventLogProperty {
    [CmdletBinding()]
    param(
        [parameter(Mandatory, Position = 0, ValueFromPipeLine)]
        [System.Diagnostics.Eventing.Reader.EventRecord]$Record
    )
    PROCESS {
        $xml = [xml]$Record.ToXml()
        $ht = @{
            TimeCreated = $Record.TimeCreated
            Id = $Record.Id
        }
        foreach($ent in $xml.Event.EventData.data) {
            $ht.Add($ent.Name, $ent."#text")
        }
        [PSCustomObject]$ht
    }
}
Get-EventLogProperty $record

# Listing 15-29
function Get-AuthFailureStatus {
    [CmdletBinding()]
    param(
        [parameter(Mandatory, Position = 0, ValueFromPipeLine)]
        $Record
    )
    PROCESS {
        [PSCustomObject]@{
            TimeCreated = $Record.TimeCreated
            UserName = $Record.TargetUserName
            DomainName = $Record.TargetDomainName
            SubStatus = (Get-NtStatus -Status $Record.SubStatus).StatusName
        }
    }
}
Get-NtToken -Logon -User $env:USERNAME -Domain $env:USERDOMAIN -Password "InvalidPassword"
Get-NtToken -Logon -User "NotARealUser" -Domain $env:USERDOMAIN -Password "pwd"
Get-WinEvent -FilterHashtable @{logname='Security';id=@(4625)} |
Select-Object -First 2 | Get-EventLogProperty | Get-AuthFailureStatus