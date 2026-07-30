Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$projectDir = Split-Path -Parent $PSScriptRoot
$exitCode = 0

Push-Location $projectDir
try {
    & docker compose --env-file relay-dashboard/.env -f relay-dashboard/compose.yaml up -d --build --force-recreate
    $exitCode = $LASTEXITCODE
}
finally {
    Pop-Location
}

exit $exitCode
