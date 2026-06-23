$ErrorActionPreference = 'Stop'

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
. (Join-Path $ScriptDir 'scripts/program-common.ps1')
Set-ProgramLayoutArgs $args

Set-Location $ScriptDir
Test-ProgramBundle
Initialize-ProgramConfig
Initialize-ProgramRuntime

Write-Host '[program-deploy] bundle validated'
Write-Host ("[program-deploy] backend binary: {0}" -f $script:BackendBin)
Write-Host ("[program-deploy] runtime directories prepared under {0} and {1}" -f $script:DataDir, $script:RunDir)
