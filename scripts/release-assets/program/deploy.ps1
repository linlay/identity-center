$ErrorActionPreference = 'Stop'

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
. (Join-Path $ScriptDir 'scripts/program-common.ps1')

$AuthIssuer = ''
for ($i = 0; $i -lt $args.Count; $i++) {
  $arg = $args[$i]
  switch ($arg) {
    '--auth-issuer' {
      if ($i + 1 -ge $args.Count) { Fail-Program 'missing value for --auth-issuer' }
      $i++
      $AuthIssuer = $args[$i]
      continue
    }
    default { Fail-Program "unsupported argument: $arg" }
  }
}

Set-Location $ScriptDir
Initialize-ProgramConfig
if ($AuthIssuer) {
  Set-ProgramEnvValue 'AUTH_ISSUER' $AuthIssuer
}

Write-Host ("[program-deploy] config initialized: {0}" -f $script:EnvFile)
if ($AuthIssuer) {
  Write-Host ("[program-deploy] AUTH_ISSUER={0}" -f $AuthIssuer)
}
