$ErrorActionPreference = 'Stop'

$Script:ProgramCommonDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$Script:BundleRoot = Split-Path -Parent $Script:ProgramCommonDir
$Script:AppName = 'identity-center'
$Script:ManifestFile = Join-Path $Script:BundleRoot 'manifest.json'
$Script:EnvExampleFile = Join-Path $Script:BundleRoot '.env.example'
$Script:BackendBin = Join-Path (Join-Path $Script:BundleRoot 'backend') 'identity-center.exe'
$Script:FrontendDir = Join-Path $Script:BundleRoot 'frontend'
$Script:DistDir = Join-Path $Script:FrontendDir 'dist'
$Script:ConfigDir = $Script:BundleRoot
$Script:DataDir = Join-Path $Script:BundleRoot 'data'
$Script:RunDir = Join-Path $Script:BundleRoot 'run'
$Script:LogDir = $Script:RunDir
$Script:ProgramPort = ''
$Script:EnvFile = ''
$Script:PidFile = ''
$Script:LogFile = ''
$Script:ErrorLogFile = ''

function Update-ProgramLayoutPaths {
  $Script:EnvFile = Join-Path $Script:ConfigDir '.env'
  $Script:PidFile = Join-Path (Join-Path $Script:BundleRoot 'run') 'identity-center.pid'
  $Script:LogFile = Join-Path $Script:LogDir 'identity-center.log'
  $Script:ErrorLogFile = Join-Path $Script:LogDir 'identity-center.stderr.log'
}

function Set-ProgramLayoutArgs {
  param([string[]]$Arguments)

  for ($i = 0; $i -lt $Arguments.Count; $i++) {
    $arg = $Arguments[$i]
    switch ($arg) {
      '--config-dir' {
        if ($i + 1 -ge $Arguments.Count) { Fail-Program 'missing value for --config-dir' }
        $i++
        $Script:ConfigDir = $Arguments[$i]
        continue
      }
      '--data-dir' {
        if ($i + 1 -ge $Arguments.Count) { Fail-Program 'missing value for --data-dir' }
        $i++
        $Script:DataDir = $Arguments[$i]
        continue
      }
      '--state-dir' {
        if ($i + 1 -ge $Arguments.Count) { Fail-Program 'missing value for --state-dir' }
        $previousDefaultLogDir = Join-Path $Script:BundleRoot 'run'
        $i++
        $Script:RunDir = $Arguments[$i]
        if ($Script:LogDir -eq $previousDefaultLogDir) {
          $Script:LogDir = $Script:RunDir
        }
        continue
      }
      '--log-dir' {
        if ($i + 1 -ge $Arguments.Count) { Fail-Program 'missing value for --log-dir' }
        $i++
        $Script:LogDir = $Arguments[$i]
        continue
      }
      '--port' {
        if ($i + 1 -ge $Arguments.Count) { Fail-Program 'missing value for --port' }
        $i++
        $Script:ProgramPort = $Arguments[$i]
        continue
      }
      default {
        Fail-Program "unsupported argument: $arg"
      }
    }
  }
  Update-ProgramLayoutPaths
}

Update-ProgramLayoutPaths

function Resolve-ProgramFrontendDistDir {
  $frontendDistDir = if ($env:FRONTEND_DIST_DIR) { $env:FRONTEND_DIST_DIR } else { '.\frontend\dist' }
  if ([System.IO.Path]::IsPathRooted($frontendDistDir)) {
    $Script:DistDir = $frontendDistDir
    return
  }

  $relativeDistDir = $frontendDistDir.TrimStart('.', '\', '/')
  if ([string]::IsNullOrWhiteSpace($relativeDistDir)) {
    $relativeDistDir = 'frontend\dist'
  }
  $Script:DistDir = Join-Path $Script:BundleRoot $relativeDistDir
}

function Initialize-ProgramConfig {
  New-Item -ItemType Directory -Force -Path (Split-Path -Parent $Script:EnvFile) | Out-Null
  if (-not (Test-Path -LiteralPath $Script:EnvFile -PathType Leaf)) {
    Copy-Item -LiteralPath $Script:EnvExampleFile -Destination $Script:EnvFile
  }
}

function Set-ProgramEnvValue {
  param(
    [string]$Key,
    [string]$Value
  )

  $found = $false
  $lines = Get-Content -LiteralPath $Script:EnvFile
  $updated = foreach ($line in $lines) {
    if ($line.StartsWith("$Key=")) {
      $found = $true
      "$Key=$Value"
    } else {
      $line
    }
  }
  if (-not $found) {
    $updated += "$Key=$Value"
  }
  Set-Content -LiteralPath $Script:EnvFile -Value $updated
}

function Fail-Program([string]$Message) {
  throw "[program] $Message"
}

function Test-ProgramBundle {
  Resolve-ProgramFrontendDistDir
  if (-not (Test-Path -LiteralPath $Script:ManifestFile -PathType Leaf)) {
    Fail-Program "required file not found: $Script:ManifestFile"
  }
  if (-not (Test-Path -LiteralPath $Script:EnvExampleFile -PathType Leaf)) {
    Fail-Program "required file not found: $Script:EnvExampleFile"
  }
  if (-not (Test-Path -LiteralPath $Script:BackendBin -PathType Leaf)) {
    Fail-Program "required file not found: $Script:BackendBin"
  }
  if (-not (Test-Path -LiteralPath $Script:DistDir -PathType Container)) {
    Fail-Program "required directory not found: $Script:DistDir"
  }
  $indexPath = Join-Path $Script:DistDir 'index.html'
  if (-not (Test-Path -LiteralPath $indexPath -PathType Leaf)) {
    Fail-Program "required file not found: $indexPath"
  }
}

function Import-ProgramEnv {
  param([switch]$Optional)

  if (-not (Test-Path -LiteralPath $Script:EnvFile -PathType Leaf)) {
    if ($Optional) {
      if (-not $env:SERVER_PORT) {
        $env:SERVER_PORT = '18080'
      }
      if ($Script:ProgramPort) {
        $env:SERVER_PORT = $Script:ProgramPort
      }
      if (-not $env:AUTH_DB_PATH) {
        $env:AUTH_DB_PATH = Join-Path $Script:DataDir 'auth.db'
      }
      if (-not $env:FRONTEND_DIST_DIR) {
        $env:FRONTEND_DIST_DIR = '.\frontend\dist'
      }
      Resolve-ProgramFrontendDistDir
      return
    }
    Fail-Program 'missing .env (copy from .env.example first)'
  }

  foreach ($rawLine in Get-Content -LiteralPath $Script:EnvFile) {
    $line = $rawLine.Trim()
    if ([string]::IsNullOrWhiteSpace($line) -or $line.StartsWith('#')) {
      continue
    }
    $index = $line.IndexOf('=')
    if ($index -lt 1) {
      continue
    }
    $name = $line.Substring(0, $index).Trim()
    $value = $line.Substring($index + 1).Trim()
    if (($value.StartsWith("'") -and $value.EndsWith("'")) -or ($value.StartsWith('"') -and $value.EndsWith('"'))) {
      $value = $value.Substring(1, $value.Length - 2)
    }
    [Environment]::SetEnvironmentVariable($name, $value, 'Process')
  }

  if (-not $env:SERVER_PORT) {
    $env:SERVER_PORT = '18080'
  }
  if ($Script:ProgramPort) {
    $env:SERVER_PORT = $Script:ProgramPort
  }
  if (-not $env:AUTH_DB_PATH) {
    $env:AUTH_DB_PATH = Join-Path $Script:DataDir 'auth.db'
  }
  if (-not $env:FRONTEND_DIST_DIR) {
    $env:FRONTEND_DIST_DIR = '.\frontend\dist'
  }
  Resolve-ProgramFrontendDistDir
}

function Initialize-ProgramRuntime {
  New-Item -ItemType Directory -Force -Path $Script:DataDir, $Script:RunDir, $Script:LogDir, (Split-Path -Parent $Script:PidFile) | Out-Null
}

function Clear-StaleProgramPid {
  if (-not (Test-Path -LiteralPath $Script:PidFile -PathType Leaf)) {
    return
  }

  $pidValue = (Get-Content -LiteralPath $Script:PidFile -Raw).Trim()
  if (-not [string]::IsNullOrWhiteSpace($pidValue)) {
    try {
      $null = Get-Process -Id ([int]$pidValue) -ErrorAction Stop
      Fail-Program "$Script:AppName is already running with pid $pidValue"
    } catch [Microsoft.PowerShell.Commands.ProcessCommandException] {
      Remove-Item -LiteralPath $Script:PidFile -Force -ErrorAction SilentlyContinue
      return
    }
  }

  Remove-Item -LiteralPath $Script:PidFile -Force -ErrorAction SilentlyContinue
}

function Start-ProgramBackend {
  param(
    [switch]$Daemon
  )

  $backendArgs = @('--config-dir', $Script:ConfigDir, '--data-dir', $Script:DataDir, '--state-dir', $Script:RunDir, '--log-dir', $Script:LogDir)
  if ($Script:ProgramPort) {
    $backendArgs += @('--port', $Script:ProgramPort)
  } elseif ($env:SERVER_PORT) {
    $backendArgs += @('--port', $env:SERVER_PORT)
  }

  if ($Daemon) {
    Clear-StaleProgramPid
    if (Test-Path -LiteralPath $Script:LogFile) {
      Clear-Content -LiteralPath $Script:LogFile
    } else {
      New-Item -ItemType File -Path $Script:LogFile -Force | Out-Null
    }
    if (Test-Path -LiteralPath $Script:ErrorLogFile) {
      Clear-Content -LiteralPath $Script:ErrorLogFile
    } else {
      New-Item -ItemType File -Path $Script:ErrorLogFile -Force | Out-Null
    }

    $proc = Start-Process -FilePath $Script:BackendBin -ArgumentList $backendArgs -WorkingDirectory $Script:BundleRoot -WindowStyle Hidden -RedirectStandardOutput $Script:LogFile -RedirectStandardError $Script:ErrorLogFile -PassThru
    $proc.Id | Set-Content -LiteralPath $Script:PidFile
    Start-Sleep -Seconds 1
    if ($proc.HasExited) {
      Remove-Item -LiteralPath $Script:PidFile -Force -ErrorAction SilentlyContinue
      Fail-Program "backend failed to start; see $Script:LogFile and $Script:ErrorLogFile"
    }
    Write-Host "[program-start] started $Script:AppName in daemon mode (pid=$($proc.Id))"
    Write-Host "[program-start] log file: $Script:LogFile"
    Write-Host "[program-start] stderr file: $Script:ErrorLogFile"
    return
  }

  & $Script:BackendBin @backendArgs
}

function Stop-ProgramBackend {
  if (-not (Test-Path -LiteralPath $Script:PidFile -PathType Leaf)) {
    Write-Host "[program-stop] pid file not found: $Script:PidFile"
    return
  }

  $pidValue = (Get-Content -LiteralPath $Script:PidFile -Raw).Trim()
  if ([string]::IsNullOrWhiteSpace($pidValue)) {
    Fail-Program "pid file is empty: $Script:PidFile"
  }

  try {
    $proc = Get-Process -Id ([int]$pidValue) -ErrorAction Stop
  } catch [Microsoft.PowerShell.Commands.ProcessCommandException] {
    Remove-Item -LiteralPath $Script:PidFile -Force -ErrorAction SilentlyContinue
    Write-Host "[program-stop] process $pidValue is not running; removed stale pid file"
    return
  }

  Stop-Process -Id $proc.Id -ErrorAction Stop
  for ($i = 0; $i -lt 30; $i++) {
    Start-Sleep -Seconds 1
    if ($proc.HasExited) {
      Remove-Item -LiteralPath $Script:PidFile -Force -ErrorAction SilentlyContinue
      Write-Host "[program-stop] stopped $Script:AppName (pid=$($proc.Id))"
      return
    }
    $proc.Refresh()
  }

  Fail-Program "process $($proc.Id) did not stop within 30s"
}
