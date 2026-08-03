$ErrorActionPreference = 'Stop'

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
. (Join-Path $ScriptDir 'scripts/program-common.ps1')

$AuthIssuer = ''
$OutputDir = ''
$DesktopConfigReset = $false
$DesktopConfigBackupDir = ''
$DesktopVersionFrom = ''
$DesktopVersionTo = ''
for ($i = 0; $i -lt $args.Count; $i++) {
  $arg = $args[$i]
  switch ($arg) {
    '--auth-issuer' {
      if ($i + 1 -ge $args.Count) { Fail-Program 'missing value for --auth-issuer' }
      $i++
      $AuthIssuer = $args[$i]
      continue
    }
    '--desktop-config-reset' {
      $DesktopConfigReset = $true
      continue
    }
    '--desktop-config-backup-dir' {
      if ($i + 1 -ge $args.Count) { Fail-Program 'missing value for --desktop-config-backup-dir' }
      $i++
      $DesktopConfigBackupDir = $args[$i]
      continue
    }
    '--desktop-version-from' {
      if ($i + 1 -ge $args.Count) { Fail-Program 'missing value for --desktop-version-from' }
      $i++
      $DesktopVersionFrom = $args[$i]
      continue
    }
    '--desktop-version-to' {
      if ($i + 1 -ge $args.Count) { Fail-Program 'missing value for --desktop-version-to' }
      $i++
      $DesktopVersionTo = $args[$i]
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
$AdminPasswordBcrypt = $null
if ($DesktopConfigReset) {
  Assert-DesktopConfigResetArgs $DesktopConfigBackupDir $DesktopVersionFrom $DesktopVersionTo
  Reset-DesktopProgramConfig $DesktopConfigBackupDir
  $AdminPasswordBcrypt = Get-ProgramEnvLiteralValue (Join-Path $DesktopConfigBackupDir '.env') 'AUTH_ADMIN_PASSWORD_BCRYPT'
}
Initialize-ProgramConfig
if ($DesktopConfigReset -and -not [string]::IsNullOrWhiteSpace($AdminPasswordBcrypt)) {
  Set-ProgramEnvValue 'AUTH_ADMIN_PASSWORD_BCRYPT' $AdminPasswordBcrypt
}
if ($AuthIssuer) {
  Set-ProgramEnvValue 'AUTH_ISSUER' $AuthIssuer
}
if ($DesktopConfigReset) {
  Protect-ProgramConfigTree $Script:ConfigDir
}

Write-Host ("[program-deploy] config initialized: {0}" -f $script:EnvFile)
if ($AuthIssuer) {
  Write-Host ("[program-deploy] AUTH_ISSUER={0}" -f $AuthIssuer)
}
if ($DesktopConfigReset) {
  Write-Host "[program-deploy] Desktop config rebuilt: $DesktopVersionFrom -> $DesktopVersionTo"
}
