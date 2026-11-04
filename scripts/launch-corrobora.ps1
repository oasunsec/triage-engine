[CmdletBinding()]
param(
    [int]$Port = 8000,
    [switch]$NoBrowser,
    [switch]$Wait,
    [switch]$Elevated,
    [string]$DataRoot = "",
    [string]$CasesRoot = ""
)

$ErrorActionPreference = "Stop"

function Test-TriageAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function ConvertTo-TriageProcessArgument {
    param([Parameter(Mandatory)][string]$Value)

    # Start-Process joins ArgumentList into one command line. Quote values here
    # so payloads and durable roots continue to work when their paths contain
    # spaces (for example, a checkout under a user's profile).
    if ($Value -notmatch '[\s"]') { return $Value }
    # Double trailing backslashes so the closing quote is not escaped by the
    # Windows command-line parser (a common case for user-selected folders).
    $trailingSlashes = $Value.Length - $Value.TrimEnd("\").Length
    $escaped = $Value + ("\" * $trailingSlashes)
    return '"' + $escaped + '"'
}

if ($Elevated -and -not (Test-TriageAdministrator)) {
    $arguments = @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", (ConvertTo-TriageProcessArgument $PSCommandPath), "-Port", $Port, "-Elevated")
    if ($NoBrowser) { $arguments += "-NoBrowser" }
    if ($Wait) { $arguments += "-Wait" }
    if ($DataRoot) { $arguments += @("-DataRoot", (ConvertTo-TriageProcessArgument $DataRoot)) }
    if ($CasesRoot) { $arguments += @("-CasesRoot", (ConvertTo-TriageProcessArgument $CasesRoot)) }
    Start-Process -FilePath "powershell.exe" -ArgumentList $arguments -Verb RunAs | Out-Null
    Write-Host "Windows is requesting administrator permission for Corrobora."
    return
}

$installRoot = if (Test-Path -LiteralPath (Join-Path $PSScriptRoot "Corrobora.exe")) {
    (Resolve-Path $PSScriptRoot).Path
} else {
    (Resolve-Path (Join-Path $PSScriptRoot ".." )).Path
}
$serverExe = Join-Path $installRoot "Corrobora.exe"
$repoRoot = $installRoot
$programFiles = [Environment]::GetFolderPath("ProgramFiles")
$isInstalled = $programFiles -and $installRoot.StartsWith($programFiles.TrimEnd("\") + "\", [StringComparison]::OrdinalIgnoreCase)
$defaultDataParent = if ($isInstalled) { [Environment]::GetFolderPath("CommonApplicationData") } else { [Environment]::GetFolderPath("LocalApplicationData") }
$dataRoot = if ($DataRoot) { $DataRoot } elseif ($env:CORROBORA_DATA_DIR) { $env:CORROBORA_DATA_DIR } else { Join-Path $defaultDataParent "Corrobora\data" }
$casesRoot = if ($CasesRoot) { $CasesRoot } elseif ($env:CORROBORA_CASES_DIR) { $env:CORROBORA_CASES_DIR } else { Join-Path $defaultDataParent "Corrobora\cases" }
# Installs from before the rename keep their accounts and cases under TriageEngine.
function Resolve-LegacyRoot([string]$Path) {
    $legacy = $Path -replace '\\Corrobora\\', '\TriageEngine\'
    if ($legacy -ne $Path -and -not (Test-Path -LiteralPath $Path) -and (Test-Path -LiteralPath $legacy)) {
        Write-Host "Using existing data from before the rename: $legacy"
        return $legacy
    }
    return $Path
}
$dataRoot = Resolve-LegacyRoot $dataRoot
$casesRoot = Resolve-LegacyRoot $casesRoot
New-Item -ItemType Directory -Path $dataRoot,$casesRoot -Force | Out-Null
$env:CORROBORA_HOST = "127.0.0.1"
$env:CORROBORA_PORT = $Port.ToString()
$env:CORROBORA_DATA_DIR = $dataRoot
$env:CORROBORA_CASES_DIR = $casesRoot
$env:CORROBORA_RUNTIME_MODE = "local"

if (Test-Path -LiteralPath $serverExe) {
    $command = $serverExe
    $arguments = @()
} else {
    $python = if ($env:CORROBORA_PYTHON) { $env:CORROBORA_PYTHON } else { (Get-Command python -ErrorAction Stop).Source }
    $command = $python
    $arguments = @(Join-Path $repoRoot "server.py")
}

if (-not (Test-Path -LiteralPath $serverExe) -and -not (Test-Path -LiteralPath $arguments[0])) {
    throw "Corrobora executable or source server was not found under: $installRoot"
}

$startParams = @{ FilePath = $command; WorkingDirectory = $installRoot; PassThru = $true }
if ($arguments.Count -gt 0) { $startParams.ArgumentList = @($arguments | ForEach-Object { ConvertTo-TriageProcessArgument ([string]$_) }) }
$process = Start-Process @startParams
if (-not $NoBrowser) {
    Start-Process "http://127.0.0.1:$Port"
}
if ($Wait) {
    Wait-Process -Id $process.Id
} else {
    Write-Host "Corrobora is starting at http://127.0.0.1:$Port (PID $($process.Id))."
    Write-Host "Data: $dataRoot"
    Write-Host "Cases: $casesRoot"
}
