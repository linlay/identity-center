$ErrorActionPreference = 'Stop'

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
. (Join-Path $ScriptDir 'scripts/program-common.ps1')

$Daemon = $false
$layoutArgs = @()
for ($i = 0; $i -lt $args.Count; $i++) {
  $arg = $args[$i]
  switch ($arg) {
    '--daemon' { $Daemon = $true }
    '-Daemon' { $Daemon = $true }
    { $_ -in @('--config-dir', '--data-dir', '--state-dir', '--log-dir', '--port') } {
      if ($i + 1 -ge $args.Count) { Fail-Program "missing value for $arg" }
      $layoutArgs += @($arg, $args[$i + 1])
      $i++
    }
    default { Fail-Program "unsupported argument: $arg" }
  }
}
Set-ProgramLayoutArgs $layoutArgs

Set-Location $ScriptDir
Import-ProgramEnv
Test-ProgramBundle
Initialize-ProgramRuntime
Start-ProgramBackend -Daemon:$Daemon
