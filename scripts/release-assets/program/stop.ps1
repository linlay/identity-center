$ErrorActionPreference = 'Stop'

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
. (Join-Path $ScriptDir 'scripts/program-common.ps1')
Set-ProgramStopArgs $args

Set-Location $ScriptDir
Stop-ProgramBackend
