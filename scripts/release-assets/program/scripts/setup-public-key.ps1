param(
    [ValidateSet('bootstrap', 'rotate')]
    [string]$Mode = 'bootstrap',
    [string]$Db = '',
    [string]$Out = '',
    [string]$PublicOut = '',
    [string]$KeyId = ''
)

$ErrorActionPreference = 'Stop'

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RootDir = Split-Path -Parent $ScriptDir

if (-not $Db) { $Db = if ($env:AUTH_DB_PATH) { $env:AUTH_DB_PATH } else { Join-Path $RootDir 'data/auth.db' } }
if (-not $Out) { $Out = if ($env:KEY_OUTPUT_DIR) { $env:KEY_OUTPUT_DIR } else { Join-Path $RootDir 'data/keys' } }
if (-not $PublicOut) { $PublicOut = Join-Path $Out 'publicKey.pem' }
if (-not $KeyId) { $KeyId = $env:JWK_KEY_ID }

$BackendBin = Join-Path (Join-Path $RootDir 'backend') 'identity-center.exe'
if (-not (Test-Path -LiteralPath $BackendBin -PathType Leaf)) {
    Write-Error "Backend binary not found at $BackendBin. Please build the backend first."
    exit 1
}

$goArgs = @('setup-public-key', '--mode', $Mode, '--db', $Db, '--out', $Out, '--public-out', $PublicOut)
if ($KeyId) { $goArgs += @('--key-id', $KeyId) }
& $BackendBin @goArgs
exit $LASTEXITCODE
