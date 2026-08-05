#Requires -Version 5.1
param(
    [string]$Version,
    [string]$Arch,
    [string]$ProgramTargets = $env:PROGRAM_TARGETS,
    [string]$ProgramTargetMatrix = $env:PROGRAM_TARGET_MATRIX,
    [switch]$DryRun
)

$ErrorActionPreference = "Stop"
$AppName = "identity-center"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = Split-Path -Parent $ScriptDir
$AssetsDir = Join-Path $ScriptDir "release-assets/program"
$ProgramCommonTestPath = Join-Path $AssetsDir "scripts/program-common_test.ps1"
$TemplatePath = Join-Path $AssetsDir "manifest.template.json"
$ReleaseDir = Join-Path $RepoRoot "dist/release"
$Utf8NoBom = New-Object Text.UTF8Encoding($false)

function Get-HostArch {
    if ($env:PROCESSOR_ARCHITECTURE -in @("AMD64", "x86")) { return "amd64" }
    throw "This release entry supports Windows AMD64 only"
}

function Get-Targets {
    $resolved = @()
    if ($ProgramTargetMatrix) {
        foreach ($entry in $ProgramTargetMatrix.Split(',')) {
            $parts = $entry.Trim().Split('/')
            if ($parts.Count -ne 2) { throw "PROGRAM_TARGET_MATRIX entries must be os/arch (got: $entry)" }
            $resolved += [PSCustomObject]@{ OS = $parts[0]; Arch = $parts[1] }
        }
    } elseif ($ProgramTargets) {
        foreach ($targetOS in $ProgramTargets.Split(',')) {
            $resolved += [PSCustomObject]@{ OS = $targetOS.Trim(); Arch = $Arch }
        }
    } else {
        $resolved += [PSCustomObject]@{ OS = "windows"; Arch = $Arch }
    }
    foreach ($pair in $resolved) {
        if ($pair.OS -ne "windows" -or $pair.Arch -ne "amd64") {
            throw "Native PowerShell Program Bundle supports windows/amd64 only (got: $($pair.OS)/$($pair.Arch))"
        }
    }
    return $resolved
}

function Get-BuildSetting {
    param([string]$Name, [string]$Default)
    $environmentValue = [Environment]::GetEnvironmentVariable($Name)
    if ($environmentValue) { return $environmentValue }
    $source = if (Test-Path -LiteralPath (Join-Path $RepoRoot ".env") -PathType Leaf) {
        Join-Path $RepoRoot ".env"
    } else {
        Join-Path $RepoRoot ".env.example"
    }
    $pattern = "^\s*" + [Regex]::Escape($Name) + "\s*=(.*)$"
    foreach ($line in Get-Content -LiteralPath $source -Encoding UTF8) {
        if ($line -match $pattern) {
            $value = $Matches[1].Trim()
            if (($value.StartsWith('"') -and $value.EndsWith('"')) -or ($value.StartsWith("'") -and $value.EndsWith("'"))) {
                $value = $value.Substring(1, $value.Length - 2)
            }
            if ($value) { return $value }
        }
    }
    return $Default
}

function Write-Manifest {
    param([string]$Destination, [string]$BackendEntry, [string]$ArchiveName)
    Push-Location (Join-Path $RepoRoot "backend")
    try {
        & go run ./cmd/render-program-manifest --template $TemplatePath --output $Destination --version $Version --os windows --arch amd64 --backend $BackendEntry --asset $ArchiveName
        if ($LASTEXITCODE -ne 0) { throw "Manifest renderer failed" }
    } finally { Pop-Location }
}

function Test-Bundle {
    param([string]$BundleRoot, [string]$Archive)
    $manifest = Get-Content -LiteralPath (Join-Path $BundleRoot "manifest.json") -Raw -Encoding UTF8 | ConvertFrom-Json
    foreach ($relative in @($manifest.runtime.requiredPaths)) {
        $path = $BundleRoot
        foreach ($segment in ([string]$relative).Split('/')) { $path = Join-Path $path $segment }
        if (-not (Test-Path -LiteralPath $path)) { throw "Bundle required path is missing: $relative" }
    }
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $zip = [IO.Compression.ZipFile]::OpenRead($Archive)
    try {
        foreach ($entry in $zip.Entries) {
            $entryPath = $entry.FullName.Replace("\", "/")
            if (-not $entryPath.StartsWith("$AppName/")) { throw "ZIP contains an entry outside $AppName/: $($entry.FullName)" }
        }
    } finally { $zip.Dispose() }
}

if (-not $Version) { $Version = if ($env:VERSION) { $env:VERSION } else { (Get-Content -LiteralPath (Join-Path $RepoRoot "VERSION") -Raw).Trim() } }
if ($Version -notmatch '^v[0-9]+\.[0-9]+\.[0-9]+$') { throw "VERSION must match vX.Y.Z (got: $Version)" }
if (-not $Arch) { $Arch = if ($env:ARCH) { $env:ARCH } else { Get-HostArch } }
$Targets = @(Get-Targets)
$ViteBasePath = Get-BuildSetting -Name "VITE_BASE_PATH" -Default "/admin/"
$GoProxy = Get-BuildSetting -Name "GOPROXY" -Default "https://goproxy.cn,direct"
$NpmRegistry = Get-BuildSetting -Name "NPM_REGISTRY" -Default "https://registry.npmmirror.com"
if ($DryRun -or $env:RELEASE_DRY_RUN -eq "1") {
    Write-Host "[release] dry-run targets=$($Targets | ForEach-Object { $_.OS + '/' + $_.Arch })"
    exit 0
}
foreach ($command in @("go", "npm", "robocopy")) {
    if (-not (Get-Command $command -ErrorAction SilentlyContinue)) { throw "$command is required" }
}
foreach ($path in @(
    $TemplatePath,
    (Join-Path $RepoRoot ".env.example"),
    (Join-Path $RepoRoot "backend/go.mod"),
    (Join-Path $RepoRoot "frontend/package.json"),
    (Join-Path $AssetsDir "deploy.ps1"),
    (Join-Path $AssetsDir "start.ps1"),
    (Join-Path $AssetsDir "stop.ps1"),
    (Join-Path $AssetsDir "scripts/program-common.ps1"),
    $ProgramCommonTestPath,
    (Join-Path $AssetsDir "scripts/setup-public-key.ps1"),
    (Join-Path $AssetsDir "scripts/issue-bridge-access-token.ps1"),
    (Join-Path $AssetsDir "scripts/issue-bridge-runner-token.ps1")
)) {
    if (-not (Test-Path -LiteralPath $path)) { throw "Required release input is missing: $path" }
}

& $ProgramCommonTestPath

$Temporary = Join-Path ([IO.Path]::GetTempPath()) "$AppName-release.$([Guid]::NewGuid().ToString('N'))"
$FrontendWork = Join-Path $Temporary "frontend"
$FrontendDist = Join-Path $FrontendWork "dist"
$oldRegistry = $env:npm_config_registry
$oldViteBase = $env:VITE_BASE_PATH
$oldGoProxy = $env:GOPROXY
try {
    New-Item -ItemType Directory -Path $FrontendWork -Force | Out-Null
    & robocopy (Join-Path $RepoRoot "frontend") $FrontendWork /E /XD node_modules dist /XF .DS_Store /NFL /NDL /NJH /NJS /NP
    if ($LASTEXITCODE -ge 8) { throw "robocopy failed for frontend with exit code $LASTEXITCODE" }
    $env:npm_config_registry = $NpmRegistry
    $env:VITE_BASE_PATH = $ViteBasePath
    Push-Location $FrontendWork
    try {
        & npm install
        if ($LASTEXITCODE -ne 0) { throw "npm install failed" }
        & npm run build
        if ($LASTEXITCODE -ne 0) { throw "npm build failed" }
    } finally { Pop-Location }
    if (-not (Test-Path -LiteralPath (Join-Path $FrontendDist "index.html") -PathType Leaf)) {
        throw "Frontend build did not produce dist/index.html"
    }

    foreach ($pair in $Targets) {
        $archiveName = "$AppName-$Version-$($pair.OS)-$($pair.Arch).zip"
        $archive = Join-Path $ReleaseDir $archiveName
        $stageRoot = Join-Path $Temporary "stage-$($pair.OS)-$($pair.Arch)"
        $bundleRoot = Join-Path $stageRoot $AppName
        $backendDir = Join-Path $bundleRoot "backend"
        $frontendDir = Join-Path $bundleRoot "frontend/dist"
        $scriptsDir = Join-Path $bundleRoot "scripts"
        $backendPath = Join-Path $backendDir "$AppName.exe"
        New-Item -ItemType Directory -Path $backendDir -Force | Out-Null
        New-Item -ItemType Directory -Path $frontendDir -Force | Out-Null
        New-Item -ItemType Directory -Path $scriptsDir -Force | Out-Null
        New-Item -ItemType Directory -Path $ReleaseDir -Force | Out-Null

        $oldCGO = $env:CGO_ENABLED
        $oldGOOS = $env:GOOS
        $oldGOARCH = $env:GOARCH
        try {
            $env:GOPROXY = $GoProxy
            $env:CGO_ENABLED = "0"
            $env:GOOS = $pair.OS
            $env:GOARCH = $pair.Arch
            Push-Location (Join-Path $RepoRoot "backend")
            try {
                & go build -trimpath -ldflags "-s -w -buildid=" -o $backendPath ./cmd/server
                if ($LASTEXITCODE -ne 0) { throw "go build failed for $($pair.OS)/$($pair.Arch)" }
            } finally { Pop-Location }
        } finally {
            if ($null -eq $oldCGO) { Remove-Item Env:CGO_ENABLED -ErrorAction SilentlyContinue } else { $env:CGO_ENABLED = $oldCGO }
            if ($null -eq $oldGOOS) { Remove-Item Env:GOOS -ErrorAction SilentlyContinue } else { $env:GOOS = $oldGOOS }
            if ($null -eq $oldGOARCH) { Remove-Item Env:GOARCH -ErrorAction SilentlyContinue } else { $env:GOARCH = $oldGOARCH }
        }

        Copy-Item (Join-Path $FrontendDist "*") $frontendDir -Recurse -Force
        Copy-Item (Join-Path $RepoRoot ".env.example") (Join-Path $bundleRoot ".env.example")
        Copy-Item (Join-Path $AssetsDir "deploy.ps1") $bundleRoot
        Copy-Item (Join-Path $AssetsDir "start.ps1") $bundleRoot
        Copy-Item (Join-Path $AssetsDir "stop.ps1") $bundleRoot
        foreach ($name in @("program-common.ps1", "setup-public-key.ps1", "issue-bridge-access-token.ps1", "issue-bridge-runner-token.ps1")) {
            Copy-Item (Join-Path $AssetsDir "scripts/$name") $scriptsDir
        }
        Write-Manifest -Destination (Join-Path $bundleRoot "manifest.json") -BackendEntry "backend/$AppName.exe" -ArchiveName $archiveName

        Add-Type -AssemblyName System.IO.Compression.FileSystem
        Remove-Item -LiteralPath $archive -Force -ErrorAction SilentlyContinue
        [IO.Compression.ZipFile]::CreateFromDirectory($stageRoot, $archive, [IO.Compression.CompressionLevel]::Optimal, $false)
        Test-Bundle -BundleRoot $bundleRoot -Archive $archive
        $hash = (Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLowerInvariant()
        [IO.File]::WriteAllText("$archive.sha256", "$hash  $archiveName`n", $Utf8NoBom)
        Write-Host "[release] done: $archive"
    }
} finally {
    if ($null -eq $oldRegistry) { Remove-Item Env:npm_config_registry -ErrorAction SilentlyContinue } else { $env:npm_config_registry = $oldRegistry }
    if ($null -eq $oldViteBase) { Remove-Item Env:VITE_BASE_PATH -ErrorAction SilentlyContinue } else { $env:VITE_BASE_PATH = $oldViteBase }
    if ($null -eq $oldGoProxy) { Remove-Item Env:GOPROXY -ErrorAction SilentlyContinue } else { $env:GOPROXY = $oldGoProxy }
    Remove-Item -LiteralPath $Temporary -Recurse -Force -ErrorAction SilentlyContinue
}
