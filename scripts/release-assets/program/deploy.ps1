$ErrorActionPreference = 'Stop'

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
. (Join-Path $ScriptDir 'scripts/program-common.ps1')

$AuthIssuer = ''
$OutputDir = ''
for ($i = 0; $i -lt $args.Count; $i++) {
  $arg = $args[$i]
  switch ($arg) {
    '--auth-issuer' {
      if ($i + 1 -ge $args.Count) { Fail-Program 'missing value for --auth-issuer' }
      $i++
      $AuthIssuer = $args[$i]
      continue
    }
    '--output-dir' {
      if ($i + 1 -ge $args.Count) { Fail-Program 'missing value for --output-dir' }
      $i++
      $OutputDir = $args[$i]
      continue
    }
    { $_ -in @('--config-dir', '--data-dir', '--state-dir', '--log-dir', '--port', '--daemon') } {
      Fail-Program "$arg is a start/runtime argument; pass it to start.ps1 instead of deploy.ps1"
    }
    default { Fail-Program "unsupported deploy argument: $arg" }
  }
}

Set-Location $ScriptDir
if ($OutputDir) {
  $Script:ConfigDir = $OutputDir
  Update-ProgramLayoutPaths
}
Initialize-ProgramConfig
if ($AuthIssuer) {
  Set-ProgramEnvValue 'AUTH_ISSUER' $AuthIssuer
}

Write-Host ("[program-deploy] config initialized: {0}" -f $script:EnvFile)
if ($AuthIssuer) {
  Write-Host ("[program-deploy] AUTH_ISSUER={0}" -f $AuthIssuer)
}
