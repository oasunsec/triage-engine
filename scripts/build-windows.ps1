[CmdletBinding()]
param(
    [string]$Python = "",
    [string]$OutputRoot = "",
    [switch]$Clean,
    [switch]$BuildInstaller
)

$ErrorActionPreference = "Stop"
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot ".." )).Path
$specPath = Join-Path $repoRoot "packaging\triage-engine.spec"
if (-not $OutputRoot) { $OutputRoot = Join-Path $repoRoot "dist-windows" }
$OutputRoot = [IO.Path]::GetFullPath($OutputRoot)

if ($Clean) {
    if ([StringComparer]::OrdinalIgnoreCase.Equals($OutputRoot.TrimEnd("\"), $repoRoot.TrimEnd("\")) -or
        $repoRoot.StartsWith($OutputRoot.TrimEnd("\") + "\", [StringComparison]::OrdinalIgnoreCase)) {
        throw "Refusing -Clean because OutputRoot would remove the repository or one of its parents: $OutputRoot"
    }
}

function Resolve-Python {
    if ($Python) {
        if (-not (Test-Path -LiteralPath $Python)) { throw "Python executable not found: $Python" }
        return $Python
    }
    if ($env:TRIAGE_PYTHON -and (Test-Path -LiteralPath $env:TRIAGE_PYTHON)) { return $env:TRIAGE_PYTHON }
    $venv = Join-Path $repoRoot ".venv\Scripts\python.exe"
    if (Test-Path -LiteralPath $venv) { return $venv }
    $command = Get-Command python -ErrorAction SilentlyContinue
    if ($command) { return $command.Source }
    throw "No Python runtime found. Set -Python or TRIAGE_PYTHON."
}

$pythonExe = Resolve-Python
if (-not (Test-Path -LiteralPath $specPath)) { throw "Missing PyInstaller spec: $specPath" }
if ($Clean -and (Test-Path -LiteralPath $OutputRoot)) {
    Remove-Item -LiteralPath $OutputRoot -Recurse -Force
}
New-Item -ItemType Directory -Path $OutputRoot -Force | Out-Null
$workPath = Join-Path $OutputRoot "build"
$distPath = Join-Path $OutputRoot "portable"
New-Item -ItemType Directory -Path $workPath,$distPath -Force | Out-Null

& $pythonExe -m PyInstaller --version
if ($LASTEXITCODE -ne 0) { throw "PyInstaller is unavailable. Install the build extras before building; this script never installs dependencies." }
& $pythonExe -m PyInstaller --noconfirm --clean --distpath $distPath --workpath $workPath $specPath
if ($LASTEXITCODE -ne 0) { throw "PyInstaller failed with exit code $LASTEXITCODE." }

$launcher = Join-Path $repoRoot "scripts\launch-triage.ps1"
$payloadPath = Join-Path $distPath "TriageEngine"
if (-not (Test-Path -LiteralPath (Join-Path $payloadPath "TriageEngine.exe"))) {
    throw "PyInstaller completed but did not produce the expected payload: $payloadPath\TriageEngine.exe"
}
Copy-Item -LiteralPath $launcher -Destination (Join-Path $payloadPath "launch-triage.ps1") -Force
Copy-Item -LiteralPath (Join-Path $repoRoot "LICENSE") -Destination (Join-Path $payloadPath "LICENSE") -Force
Write-Host "Portable build: $payloadPath"

if ($BuildInstaller) {
    $isccPath = $null
    $isccCommand = Get-Command ISCC.exe -ErrorAction SilentlyContinue
    if ($isccCommand) {
        $isccPath = $isccCommand.Source
    }
    if (-not $isccPath) {
        $perUserIscc = Join-Path ${env:LOCALAPPDATA} "Programs\Inno Setup 6\ISCC.exe"
        if (Test-Path -LiteralPath $perUserIscc) {
            $isccPath = $perUserIscc
        }
    }
    if (-not $isccPath) {
        $machineCandidates = @(
            "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe",
            "${env:ProgramFiles}\Inno Setup 6\ISCC.exe"
        ) | Where-Object { $_ -and (Test-Path -LiteralPath $_) }
        if ($machineCandidates) { $isccPath = $machineCandidates[0] }
    }
    if (-not $isccPath) { throw "Inno Setup compiler (ISCC.exe) was not found. Omit -BuildInstaller for a portable build." }
    $installerOut = Join-Path $OutputRoot "installer"
    New-Item -ItemType Directory -Path $installerOut -Force | Out-Null
    & $isccPath "/DSourceDir=$payloadPath" "/DOutputDir=$installerOut" (Join-Path $repoRoot "packaging\triage-engine.iss")
    if ($LASTEXITCODE -ne 0) { throw "Inno Setup failed with exit code $LASTEXITCODE." }
    Write-Host "Installer output: $installerOut"
}
