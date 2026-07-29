[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [ValidateSet("set", "remove", "list")]
    [string]$Command = "list",

    [Parameter(Position = 1)]
    [string]$Hostname,

    [Parameter(Position = 2)]
    [string]$Backend,

    [string]$RoutesFile = (Join-Path $PSScriptRoot "../gateway/mc-router/routes.json")
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function New-EmptyRouteConfig {
    return [pscustomobject][ordered]@{
        mappings = [pscustomobject][ordered]@{}
    }
}

function Read-RouteConfig {
    param([string]$Path)

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        return (New-EmptyRouteConfig)
    }

    try {
        $config = Get-Content -LiteralPath $Path -Raw -Encoding UTF8 | ConvertFrom-Json
    }
    catch {
        throw "ルート設定をJSONとして読み込めません: $Path`n$($_.Exception.Message)"
    }

    if ($null -eq $config -or $config -is [System.Array]) {
        throw "ルート設定のルート要素はJSONオブジェクトである必要があります: $Path"
    }

    $mappingsProperty = $config.PSObject.Properties["mappings"]
    if ($null -eq $mappingsProperty) {
        $config | Add-Member -MemberType NoteProperty -Name mappings -Value ([pscustomobject][ordered]@{})
    }
    elseif ($null -eq $config.mappings -or $config.mappings -isnot [pscustomobject]) {
        throw "ルート設定のmappingsはJSONオブジェクトである必要があります: $Path"
    }

    return $config
}

function Write-RouteConfig {
    param(
        [object]$Config,
        [string]$Path
    )

    $directory = Split-Path -Parent $Path
    if (-not (Test-Path -LiteralPath $directory -PathType Container)) {
        New-Item -ItemType Directory -Path $directory -Force | Out-Null
    }

    $temporaryPath = Join-Path $directory (".routes.{0}.tmp" -f [Guid]::NewGuid().ToString("N"))
    $utf8WithoutBom = New-Object System.Text.UTF8Encoding($false)
    $json = $Config | ConvertTo-Json -Depth 10

    try {
        [System.IO.File]::WriteAllText($temporaryPath, $json + [Environment]::NewLine, $utf8WithoutBom)
        Move-Item -LiteralPath $temporaryPath -Destination $Path -Force
    }
    finally {
        if (Test-Path -LiteralPath $temporaryPath) {
            Remove-Item -LiteralPath $temporaryPath -Force
        }
    }
}

function Normalize-Hostname {
    param([string]$Value)

    if ([string]::IsNullOrWhiteSpace($Value)) {
        throw "ホスト名を指定してください。"
    }

    $normalized = $Value.Trim().TrimEnd([char]'.').ToLowerInvariant()
    if ($normalized.Length -gt 253) {
        throw "ホスト名は253文字以内で指定してください: $Value"
    }

    foreach ($label in $normalized.Split(".")) {
        if ($label.Length -lt 1 -or $label.Length -gt 63 -or
            $label -notmatch '^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$') {
            throw "無効なホスト名です。英数字とハイフンを使用してください: $Value"
        }
    }

    return $normalized
}

function Assert-Backend {
    param([string]$Value)

    if ([string]::IsNullOrWhiteSpace($Value)) {
        throw "転送先をHOST:PORT形式で指定してください。"
    }

    $match = [regex]::Match($Value, '^(?<host>\[[^\]]+\]|[^:\s]+):(?<port>[0-9]{1,5})$')
    if (-not $match.Success) {
        throw "転送先をHOST:PORT形式で指定してください: $Value"
    }

    $port = [int]$match.Groups["port"].Value
    if ($port -lt 1 -or $port -gt 65535) {
        throw "転送先ポートは1から65535の範囲で指定してください: $Value"
    }
}

$RoutesFile = [System.IO.Path]::GetFullPath($RoutesFile)
$config = Read-RouteConfig -Path $RoutesFile

switch ($Command) {
    "set" {
        if ([string]::IsNullOrWhiteSpace($Hostname) -or [string]::IsNullOrWhiteSpace($Backend)) {
            throw "使用方法: .\scripts\mc-route.ps1 set HOSTNAME HOST:PORT"
        }

        $normalizedHostname = Normalize-Hostname -Value $Hostname
        Assert-Backend -Value $Backend
        $existing = $config.mappings.PSObject.Properties[$normalizedHostname]
        $action = if ($null -eq $existing) { "追加" } else { "更新" }

        $config.mappings | Add-Member `
            -MemberType NoteProperty `
            -Name $normalizedHostname `
            -Value $Backend `
            -Force
        Write-RouteConfig -Config $config -Path $RoutesFile
        Write-Host "${action}しました: $normalizedHostname -> $Backend"
    }

    "remove" {
        if ([string]::IsNullOrWhiteSpace($Hostname) -or -not [string]::IsNullOrWhiteSpace($Backend)) {
            throw "使用方法: .\scripts\mc-route.ps1 remove HOSTNAME"
        }

        $normalizedHostname = Normalize-Hostname -Value $Hostname
        $existing = $config.mappings.PSObject.Properties[$normalizedHostname]
        if ($null -eq $existing) {
            throw "ルートが見つかりません: $normalizedHostname"
        }

        $config.mappings.PSObject.Properties.Remove($existing.Name)
        Write-RouteConfig -Config $config -Path $RoutesFile
        Write-Host "削除しました: $normalizedHostname"
    }

    "list" {
        if (-not [string]::IsNullOrWhiteSpace($Hostname) -or -not [string]::IsNullOrWhiteSpace($Backend)) {
            throw "使用方法: .\scripts\mc-route.ps1 list"
        }

        $routes = @($config.mappings.PSObject.Properties | Sort-Object Name)
        if ($routes.Count -eq 0) {
            Write-Host "ルートは登録されていません。"
            exit 0
        }

        $routes | ForEach-Object {
            [pscustomobject]@{
                Hostname = $_.Name
                Backend  = [string]$_.Value
            }
        } | Format-Table -AutoSize
    }
}
