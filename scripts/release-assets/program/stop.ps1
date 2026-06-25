$ErrorActionPreference = 'Stop'

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
. (Join-Path $ScriptDir 'scripts/program-common.ps1')
if ($args.Count -gt 0) {
  Fail-Program "unsupported argument: $($args[0])"
}

Set-Location $ScriptDir
Stop-ProgramBackend
