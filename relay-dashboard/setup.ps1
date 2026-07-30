[CmdletBinding()]
param(
    [string]$OciConfigPath = (Join-Path $env:USERPROFILE ".oci\config"),
    [string]$OciPrivateKeyPath = "",
    [string]$SshPrivateKeyPath = (Join-Path $env:USERPROFILE ".ssh\oci-relay"),
    [string]$RelayAddress = "10.99.0.1",
    [string]$ExpectedHostFingerprint = "SHA256:dmxqq9wGzc2J0FMdI5wDrN9sgfxQPI5sgl6Mz2hmLg0"
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$DashboardRoot = $PSScriptRoot
$SecretsRoot = Join-Path $DashboardRoot "secrets"
$OciDestination = Join-Path $SecretsRoot "oci"
$SshDestination = Join-Path $SecretsRoot "ssh"
$EnvironmentFile = Join-Path $DashboardRoot ".env"

function Write-Utf8NoBom {
    param(
        [Parameter(Mandatory)]
        [string]$Path,
        [Parameter(Mandatory)]
        [string]$Content
    )

    $Encoding = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($Path, $Content, $Encoding)
}

function Resolve-KeyPathFromConfig {
    param([string]$ConfigPath)

    foreach ($Line in Get-Content -LiteralPath $ConfigPath) {
        if ($Line -match "^\s*key_file\s*=\s*(.+?)\s*$") {
            $Value = $Matches[1].Trim().Trim('"').Trim("'")
            $Value = [Environment]::ExpandEnvironmentVariables($Value)
            if ($Value.StartsWith("~/") -or $Value.StartsWith("~\")) {
                return Join-Path $env:USERPROFILE $Value.Substring(2)
            }
            if (-not [System.IO.Path]::IsPathRooted($Value)) {
                return Join-Path (Split-Path -Parent $ConfigPath) $Value
            }
            return $Value
        }
    }
    throw "OCI configにkey_fileが見つかりません。-OciPrivateKeyPathで秘密鍵を指定してください。"
}

foreach ($Command in @("ssh-keyscan", "ssh-keygen")) {
    if (-not (Get-Command $Command -ErrorAction SilentlyContinue)) {
        throw "$Command が見つかりません。WindowsのOpenSSHクライアントを有効にしてください。"
    }
}

if (-not (Test-Path -LiteralPath $OciConfigPath -PathType Leaf)) {
    throw "OCI configが見つかりません: $OciConfigPath"
}
if ([string]::IsNullOrWhiteSpace($OciPrivateKeyPath)) {
    $OciPrivateKeyPath = Resolve-KeyPathFromConfig -ConfigPath $OciConfigPath
}
if (-not (Test-Path -LiteralPath $OciPrivateKeyPath -PathType Leaf)) {
    throw "OCI API秘密鍵が見つかりません: $OciPrivateKeyPath"
}
if (-not (Test-Path -LiteralPath $SshPrivateKeyPath -PathType Leaf)) {
    throw "OCI SSH秘密鍵が見つかりません: $SshPrivateKeyPath"
}

New-Item -ItemType Directory -Force -Path $OciDestination, $SshDestination | Out-Null

$OciConfig = (Get-Content -LiteralPath $OciConfigPath -Raw) `
    -replace "(?m)^\s*key_file\s*=.*$", "key_file=/run/relay-home/.oci/oci_api_key.pem"
Write-Utf8NoBom -Path (Join-Path $OciDestination "config") -Content $OciConfig
Copy-Item -LiteralPath $OciPrivateKeyPath `
    -Destination (Join-Path $OciDestination "oci_api_key.pem") -Force
Copy-Item -LiteralPath $SshPrivateKeyPath `
    -Destination (Join-Path $SshDestination "oci-relay") -Force

$SshConfig = @"
Host oci-relay
    HostName $RelayAddress
    User ubuntu
    IdentityFile /run/relay-home/.ssh/oci-relay
    IdentitiesOnly yes
    StrictHostKeyChecking yes
    UserKnownHostsFile /run/relay-home/.ssh/known_hosts
    ConnectTimeout 10
"@
Write-Utf8NoBom -Path (Join-Path $SshDestination "config") -Content $SshConfig

$KnownHostsTemporary = Join-Path ([System.IO.Path]::GetTempPath()) `
    "relay-dashboard-known-hosts-$([guid]::NewGuid().ToString('N'))"
try {
    $PreviousErrorActionPreference = $ErrorActionPreference
    try {
        # Windows PowerShell 5.1 converts ssh-keyscan's normal stderr banner
        # into a NativeCommandError when ErrorActionPreference is Stop.
        $ErrorActionPreference = "Continue"
        $ScannedKeys = & ssh-keyscan -T 8 -t ed25519 $RelayAddress 2>$null
        $SshKeyscanExitCode = $LASTEXITCODE
    }
    finally {
        $ErrorActionPreference = $PreviousErrorActionPreference
    }
    if ($SshKeyscanExitCode -ne 0 -or -not $ScannedKeys) {
        throw "OCIのSSHホスト鍵を取得できません。WindowsのWireGuardを有効にしてping $RelayAddressを確認してください。"
    }
    Write-Utf8NoBom -Path $KnownHostsTemporary -Content (($ScannedKeys -join "`n") + "`n")
    $FingerprintOutput = & ssh-keygen -lf $KnownHostsTemporary -E sha256
    if ($LASTEXITCODE -ne 0) {
        throw "SSHホスト鍵のフィンガープリントを確認できません。"
    }
    if ($FingerprintOutput -notmatch [regex]::Escape($ExpectedHostFingerprint)) {
        throw "SSHホスト鍵が既知の値と一致しません。取得値: $FingerprintOutput"
    }
    Copy-Item -LiteralPath $KnownHostsTemporary `
        -Destination (Join-Path $SshDestination "known_hosts") -Force
}
finally {
    Remove-Item -LiteralPath $KnownHostsTemporary -Force -ErrorAction SilentlyContinue
}

if (-not (Test-Path -LiteralPath $EnvironmentFile -PathType Leaf)) {
    $RandomBytes = New-Object byte[] 24
    $RandomGenerator = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try {
        $RandomGenerator.GetBytes($RandomBytes)
    }
    finally {
        $RandomGenerator.Dispose()
    }
    $Password = -join ($RandomBytes | ForEach-Object { $_.ToString("x2") })
    $Environment = @"
DASHBOARD_USERNAME=admin
DASHBOARD_PASSWORD=$Password
RELAY_DASHBOARD_BIND_IP=127.0.0.1
RELAY_DASHBOARD_PORT=41800
RELAY_SSH_HOST=oci-relay
RELAY_NETWORK=10.99.0.0/24
RELAY_ADDRESS=10.99.0.1
"@
    Write-Utf8NoBom -Path $EnvironmentFile -Content $Environment
    Write-Host ""
    Write-Host "管理画面ログイン"
    Write-Host "  ユーザー名: admin"
    Write-Host "  パスワード: $Password"
    Write-Host "パスワードは relay-dashboard\.env に保存しました。"
}
else {
    Write-Host "既存の relay-dashboard\.env は変更していません。"
}

Write-Host ""
Write-Host "OCI・SSH資格情報の準備が完了しました。"
Write-Host "次に terraform.tfvars がMiniPC側リポジトリに存在することを確認してください。"
