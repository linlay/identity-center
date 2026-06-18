param(
    [string]$Db = '',
    [string]$Issuer = '',
    [string]$Username = '',
    [string]$DeviceName = 'WeChat Bridge',
    [string]$DeviceId = ''
)

$ErrorActionPreference = 'Stop'

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RootDir = Split-Path -Parent $ScriptDir

if (-not $Db) { $Db = if ($env:AUTH_DB_PATH) { $env:AUTH_DB_PATH } else { Join-Path $RootDir 'data/auth.db' } }
if (-not $Issuer) { $Issuer = if ($env:AUTH_ISSUER) { $env:AUTH_ISSUER } else { 'http://localhost:8080' } }
if (-not $Username) { $Username = if ($env:AUTH_APP_USERNAME) { $env:AUTH_APP_USERNAME } else { 'app' } }
if (-not $DeviceId -and $env:DESKTOP_DEVICE_ID) { $DeviceId = $env:DESKTOP_DEVICE_ID }

$BackendBin = Join-Path (Join-Path $RootDir 'backend') 'identity-center.exe'
if (-not (Test-Path -LiteralPath $BackendBin -PathType Leaf)) {
    Write-Error "Backend binary not found at $BackendBin. Please build the backend first."
    exit 1
}

$CommandArgs = @('issue-bridge-access-token', '--db', $Db, '--issuer', $Issuer, '--username', $Username, '--device-name', $DeviceName)
if ($DeviceId) {
    $CommandArgs += @('--device-id', $DeviceId)
}

& $BackendBin @CommandArgs
exit $LASTEXITCODE
