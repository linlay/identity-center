$ErrorActionPreference = 'Stop'

$TestRoot = Join-Path $env:TEMP "identity-center-e2e-$(Get-Random)"
Write-Host "[e2e] Test root: $TestRoot"

$DbPath = Join-Path $TestRoot 'auth.db'
$KeysDir = Join-Path $TestRoot 'keys'
$PublicKeyPath = Join-Path $KeysDir 'publicKey.pem'
$ScriptDir = $PSScriptRoot

try {
    # -----------------------------------------------------------------------
    # 1) setup-public-key — bootstrap (first run, generates new key)
    # -----------------------------------------------------------------------
    Write-Host ""
    Write-Host "=== TEST 1: setup-public-key.ps1 (bootstrap, new key) ==="
    & (Join-Path $ScriptDir 'setup-public-key.ps1') `
        -Mode bootstrap -Db $DbPath -Out $KeysDir -PublicOut $PublicKeyPath

    if (-not (Test-Path $PublicKeyPath)) { throw "publicKey.pem not created" }
    if (-not (Test-Path (Join-Path $KeysDir 'jwk-public.pem'))) { throw "jwk-public.pem not created" }
    if (-not (Test-Path (Join-Path $KeysDir 'jwk-private.pem'))) { throw "jwk-private.pem not created" }
    if (-not (Test-Path $DbPath)) { throw "auth.db not created" }

    $pubPem = Get-Content -Raw (Join-Path $KeysDir 'jwk-public.pem')
    if ($pubPem -notmatch '-----BEGIN PUBLIC KEY-----') { throw "Invalid public PEM format" }
    $privPem = Get-Content -Raw (Join-Path $KeysDir 'jwk-private.pem')
    if ($privPem -notmatch '-----BEGIN PRIVATE KEY-----') { throw "Invalid private PEM format" }

    Write-Host "[e2e] PASSED: PEM files created with correct headers"

    # -----------------------------------------------------------------------
    # 2) setup-public-key — bootstrap (second run, reuses existing key)
    # -----------------------------------------------------------------------
    Write-Host ""
    Write-Host "=== TEST 2: setup-public-key.ps1 (bootstrap, existing key) ==="
    & (Join-Path $ScriptDir 'setup-public-key.ps1') `
        -Mode bootstrap -Db $DbPath -Out $KeysDir -PublicOut $PublicKeyPath

    $pubPem2 = Get-Content -Raw (Join-Path $KeysDir 'jwk-public.pem')
    if ($pubPem -ne $pubPem2) { throw "Bootstrap should reuse existing key, but PEM changed" }
    Write-Host "[e2e] PASSED: Bootstrap reuses existing key"

    # -----------------------------------------------------------------------
    # 3) setup-public-key — rotate (generates new key)
    # -----------------------------------------------------------------------
    Write-Host ""
    Write-Host "=== TEST 3: setup-public-key.ps1 (rotate) ==="
    & (Join-Path $ScriptDir 'setup-public-key.ps1') `
        -Mode rotate -Db $DbPath -Out $KeysDir -PublicOut $PublicKeyPath

    $pubPem3 = Get-Content -Raw (Join-Path $KeysDir 'jwk-public.pem')
    if ($pubPem -eq $pubPem3) { throw "Rotate should generate a new key, but PEM is the same" }
    Write-Host "[e2e] PASSED: Rotate generates new key"

    # -----------------------------------------------------------------------
    # 4) issue-bridge-access-token
    # -----------------------------------------------------------------------
    Write-Host ""
    Write-Host "=== TEST 4: issue-bridge-access-token.ps1 ==="
    $tokenOutput = & (Join-Path $ScriptDir 'issue-bridge-access-token.ps1') `
        -Db $DbPath -Issuer 'http://test:8080' -Username 'testuser' -DeviceName 'TestDevice'

    $token = ($tokenOutput | Where-Object { $_ -match '\S' } | Select-Object -Last 1).Trim()
    if (-not $token) { throw "No token output" }
    $parts = $token.Split('.')
    if ($parts.Count -ne 3) { throw "Token is not a valid JWT (expected 3 parts, got $($parts.Count))" }

    # Decode and verify JWT payload
    $payloadJson = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($parts[1] + '=='))
    $payload = $payloadJson | ConvertFrom-Json
    if ($payload.iss -ne 'http://test:8080') { throw "JWT issuer mismatch" }
    if ($payload.sub -ne 'testuser') { throw "JWT subject mismatch" }
    if ($payload.scope -ne 'app') { throw "JWT scope mismatch" }
    Write-Host ("[e2e] JWT payload: iss={0}, sub={1}, scope={2}, device_id={3}" -f $payload.iss, $payload.sub, $payload.scope, $payload.device_id)

    # -----------------------------------------------------------------------
    # 5) issue-bridge-runner-token
    # -----------------------------------------------------------------------
    Write-Host ""
    Write-Host "=== TEST 5: issue-bridge-runner-token.ps1 ==="
    $runnerOutput = & (Join-Path $ScriptDir 'issue-bridge-runner-token.ps1') `
        -Db $DbPath -Issuer 'http://test:8080' -Username 'runner' -DeviceName 'TestRunner' -TtlSeconds '3600'

    $runnerTokenLine = $runnerOutput | Where-Object { $_ -match '^RUNNER_BEARER_TOKEN=' }
    if (-not $runnerTokenLine) { throw "No RUNNER_BEARER_TOKEN output" }
    $runnerToken = ($runnerTokenLine -split '=', 2)[1]
    $rParts = $runnerToken.Split('.')
    if ($rParts.Count -ne 3) { throw "Runner token is not a valid JWT" }
    Write-Host "[e2e] PASSED: Runner token is a valid JWT"

    $expiresLine = $runnerOutput | Where-Object { $_ -match '^RUNNER_BEARER_EXPIRES_AT=' }
    if (-not $expiresLine) { throw "No RUNNER_BEARER_EXPIRES_AT output" }
    Write-Host "[e2e] PASSED: Runner token has expiry"

    # -----------------------------------------------------------------------
    Write-Host ""
    Write-Host "======================================="
    Write-Host "=== ALL END-TO-END TESTS PASSED!!! ==="
    Write-Host "======================================="

} finally {
    Remove-Item -Recurse -Force $TestRoot -ErrorAction SilentlyContinue
}
