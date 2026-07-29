[CmdletBinding()]
param(
    [Parameter(Mandatory, Position = 0)]
    [ValidateSet("add", "status", "remove")]
    [string]$Action,
    [string]$RelayAddress = "10.99.0.1",
    [string]$MiniPcAddress = "10.99.0.2"
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$RuleGroup = "OCI Relay Dashboard"
$TcpRuleName = "OCI Relay to MiniPC TCP"
$UdpRuleName = "OCI Relay to MiniPC UDP"

function Assert-Administrator {
    $Identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $Principal = New-Object Security.Principal.WindowsPrincipal($Identity)
    if (-not $Principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "管理者として起動したPowerShellで実行してください。"
    }
}

switch ($Action) {
    "add" {
        Assert-Administrator
        Get-NetFirewallRule -Group $RuleGroup -ErrorAction SilentlyContinue |
            Remove-NetFirewallRule

        New-NetFirewallRule `
            -DisplayName $TcpRuleName `
            -Group $RuleGroup `
            -Direction Inbound `
            -Action Allow `
            -Protocol TCP `
            -LocalAddress $MiniPcAddress `
            -RemoteAddress $RelayAddress `
            -Profile Any | Out-Null

        New-NetFirewallRule `
            -DisplayName $UdpRuleName `
            -Group $RuleGroup `
            -Direction Inbound `
            -Action Allow `
            -Protocol UDP `
            -LocalAddress $MiniPcAddress `
            -RemoteAddress $RelayAddress `
            -Profile Any | Out-Null

        Write-Host "WireGuard上の $RelayAddress から $MiniPcAddress へのTCP/UDP受信を許可しました。"
    }
    "status" {
        $Rules = Get-NetFirewallRule -Group $RuleGroup -ErrorAction SilentlyContinue
        if (-not $Rules) {
            Write-Host "管理対象のWindows Firewallルールはありません。"
            exit 1
        }
        $Rules |
            Get-NetFirewallAddressFilter |
            Select-Object InstanceID, LocalAddress, RemoteAddress |
            Format-Table -AutoSize
        $Rules |
            Select-Object DisplayName, Enabled, Direction, Action, Profile |
            Format-Table -AutoSize
    }
    "remove" {
        Assert-Administrator
        Get-NetFirewallRule -Group $RuleGroup -ErrorAction SilentlyContinue |
            Remove-NetFirewallRule
        Write-Host "管理対象のWindows Firewallルールを削除しました。"
    }
}
