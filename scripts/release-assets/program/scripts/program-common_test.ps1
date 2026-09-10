#Requires -Version 5.1
$ErrorActionPreference = 'Stop'

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
. (Join-Path $ScriptDir 'program-common.ps1')

function Assert-ProgramAcl([string]$Path, [string[]]$RequiredSids, [bool]$RequireProtected = $true) {
  $acl = Get-Acl -LiteralPath $Path
  if ($RequireProtected -and -not $acl.AreAccessRulesProtected) { throw "expected protected ACL: $Path" }
  foreach ($requiredSid in $RequiredSids) {
    $rule = $acl.Access | Where-Object {
      $_.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value -eq $requiredSid -and
        $_.AccessControlType -eq [System.Security.AccessControl.AccessControlType]::Allow -and
        ($_.FileSystemRights -band [System.Security.AccessControl.FileSystemRights]::FullControl) -eq
          [System.Security.AccessControl.FileSystemRights]::FullControl
    } | Select-Object -First 1
    if ($null -eq $rule) { throw "expected FullControl for $requiredSid on $Path" }
  }
}

$testRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("identity-center acl test {0}" -f [Guid]::NewGuid().ToString('N'))
$nestedDir = Join-Path $testRoot 'configs\nested'
$envFile = Join-Path $testRoot '.env'
$nestedFile = Join-Path $nestedDir 'config.yml'
$futureFile = Join-Path $nestedDir 'runtime-created.yml'
$currentSid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$requiredSids = @($currentSid, 'S-1-5-18')

try {
  New-Item -ItemType Directory -Force -Path $nestedDir | Out-Null
  [System.IO.File]::WriteAllText($envFile, "SERVER_PORT=17001`n")
  [System.IO.File]::WriteAllText($nestedFile, "enabled: true`n")
  Protect-ProgramConfigTree $testRoot
  [System.IO.File]::ReadAllText($envFile) | Out-Null
  [System.IO.File]::ReadAllText($nestedFile) | Out-Null
  foreach ($item in @((Get-Item -LiteralPath $testRoot)) + @(Get-ChildItem -LiteralPath $testRoot -Recurse -Force)) {
    Assert-ProgramAcl $item.FullName $requiredSids
  }
  [System.IO.File]::WriteAllText($futureFile, "created: true`n")
  [System.IO.File]::ReadAllText($futureFile) | Out-Null
  Assert-ProgramAcl $futureFile $requiredSids $false
  Write-Host '[test] identity-center config ACLs remain readable'
} finally {
  if (Test-Path -LiteralPath $testRoot) {
    & icacls.exe $testRoot '/grant' ("*{0}:F" -f $currentSid) '/T' '/C' | Out-Null
    Remove-Item -LiteralPath $testRoot -Recurse -Force -ErrorAction SilentlyContinue
  }
}
