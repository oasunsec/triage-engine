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
    Write-Host "Windows is requesting administrator permission for Triage Engine."
    return
}

$installRoot = if (Test-Path -LiteralPath (Join-Path $PSScriptRoot "TriageEngine.exe")) {
    (Resolve-Path $PSScriptRoot).Path
} else {
    (Resolve-Path (Join-Path $PSScriptRoot ".." )).Path
}
$serverExe = Join-Path $installRoot "TriageEngine.exe"
$repoRoot = $installRoot
$programFiles = [Environment]::GetFolderPath("ProgramFiles")
$isInstalled = $programFiles -and $installRoot.StartsWith($programFiles.TrimEnd("\") + "\", [StringComparison]::OrdinalIgnoreCase)
$defaultDataParent = if ($isInstalled) { [Environment]::GetFolderPath("CommonApplicationData") } else { [Environment]::GetFolderPath("LocalApplicationData") }
$dataRoot = if ($DataRoot) { $DataRoot } elseif ($env:TRIAGE_DATA_DIR) { $env:TRIAGE_DATA_DIR } else { Join-Path $defaultDataParent "TriageEngine\data" }
$casesRoot = if ($CasesRoot) { $CasesRoot } elseif ($env:TRIAGE_CASES_DIR) { $env:TRIAGE_CASES_DIR } else { Join-Path $defaultDataParent "TriageEngine\cases" }
New-Item -ItemType Directory -Path $dataRoot,$casesRoot -Force | Out-Null
$env:TRIAGE_HOST = "127.0.0.1"
$env:TRIAGE_PORT = $Port.ToString()
$env:TRIAGE_DATA_DIR = $dataRoot
$env:TRIAGE_CASES_DIR = $casesRoot
$env:TRIAGE_RUNTIME_MODE = "local"

if (Test-Path -LiteralPath $serverExe) {
    $command = $serverExe
    $arguments = @()
} else {
    $python = if ($env:TRIAGE_PYTHON) { $env:TRIAGE_PYTHON } else { (Get-Command python -ErrorAction Stop).Source }
    $command = $python
    $arguments = @(Join-Path $repoRoot "server.py")
}

if (-not (Test-Path -LiteralPath $serverExe) -and -not (Test-Path -LiteralPath $arguments[0])) {
    throw "Triage Engine executable or source server was not found under: $installRoot"
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
    Write-Host "Triage Engine is starting at http://127.0.0.1:$Port (PID $($process.Id))."
    Write-Host "Data: $dataRoot"
    Write-Host "Cases: $casesRoot"
}
