[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$OutputDirectory,
    [string]$Volume = 'C:',
    [int]$UsnCapMiB = 1024,
    [switch]$SkipNtfs,
    [string]$Python = 'python'
)

# Read-only collection of this machine's triage evidence into one folder, then a
# verified bundle. Requires an elevated prompt. Nothing on the system is changed:
# logs are exported, locked hives are copied through a temporary shadow copy
# (esentutl removes it), and $MFT/$J are read from the raw volume.

$ErrorActionPreference = 'Stop'
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) { throw 'Run this from an elevated (Administrator) PowerShell.' }
if ($Volume -notmatch '^[A-Za-z]:$') { throw 'Volume must be a drive letter such as C:' }

$repoRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..')).TrimEnd('\')
$out = [IO.Path]::GetFullPath($OutputDirectory).TrimEnd('\')
if ([StringComparer]::OrdinalIgnoreCase.Equals($out, [IO.Path]::GetPathRoot($out).TrimEnd('\'))) {
    throw "Refusing to use a volume root as OutputDirectory: $out"
}
if ($out.StartsWith($repoRoot, [StringComparison]::OrdinalIgnoreCase) -and
    $out.Substring($repoRoot.Length).TrimStart('\') -notmatch '^runtime([\\/]|$)') {
    throw "OutputDirectory inside the repository must be under runtime\: $out"
}
if (Test-Path -LiteralPath $out) { throw "OutputDirectory already exists; choose a new folder: $out" }
New-Item -ItemType Directory -Path $out | Out-Null

$collected = Get-Date
$steps = New-Object 'System.Collections.Generic.List[object]'
function Step {
    param([string]$Name, [scriptblock]$Action)
    try { & $Action; $steps.Add([ordered]@{ step = $Name; status = 'ok' }) }
    catch { $steps.Add([ordered]@{ step = $Name; status = 'failed'; error = $_.Exception.Message }); Write-Warning "$Name failed: $($_.Exception.Message)" }
}

# Event logs: the channels the engine's detections and links read.
$logs = Join-Path $out 'logs'
New-Item -ItemType Directory -Path $logs | Out-Null
$channels = @('Security', 'System', 'Application', 'Microsoft-Windows-PowerShell/Operational',
              'Windows PowerShell', 'Microsoft-Windows-TaskScheduler/Operational',
              'Microsoft-Windows-Windows Defender/Operational', 'Microsoft-Windows-Sysmon/Operational',
              'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational')
foreach ($channel in $channels) {
    $file = Join-Path $logs (($channel -replace '[\\/ ]', '_') + '.evtx')
    Step "log:$channel" {
        & wevtutil.exe gl $channel 2>$null | Out-Null
        if ($LASTEXITCODE -ne 0) { throw 'channel not present on this host' }
        & wevtutil.exe epl $channel $file
        if ($LASTEXITCODE -ne 0) { throw "wevtutil exited $LASTEXITCODE" }
    }
}

# Prefetch (absent when Prefetch is disabled, e.g. on some servers and SSD-tuned builds).
$prefetch = Join-Path $out 'prefetch'
Step 'prefetch' {
    New-Item -ItemType Directory -Path $prefetch | Out-Null
    Get-ChildItem "$env:SystemRoot\Prefetch" -Filter *.pf -ErrorAction Stop | Copy-Item -Destination $prefetch
}

# Hives with their transaction logs, so changes not yet flushed can be replayed.
$hives = Join-Path $out 'hives'
New-Item -ItemType Directory -Path $hives | Out-Null
$userProfile = [Environment]::GetFolderPath('UserProfile')
$hiveSources = [ordered]@{
    'SYSTEM'      = "$env:SystemRoot\System32\config\SYSTEM"
    'SOFTWARE'    = "$env:SystemRoot\System32\config\SOFTWARE"
    'Amcache.hve' = "$env:SystemRoot\appcompat\Programs\Amcache.hve"
    'NTUSER.DAT'  = Join-Path $userProfile 'NTUSER.DAT'
}
foreach ($name in $hiveSources.Keys) {
    foreach ($suffix in @('', '.LOG1', '.LOG2')) {
        $source = $hiveSources[$name] + $suffix
        if ($suffix -and -not (Test-Path -LiteralPath $source)) { continue }
        Step "hive:$name$suffix" {
            & esentutl.exe /y $source /vss /d (Join-Path $hives ($name + $suffix)) | Out-Null
            if ($LASTEXITCODE -ne 0) { throw "esentutl exited $LASTEXITCODE" }
        }
    }
}

# Raw scheduled-task definitions.
Step 'tasks' { Copy-Item "$env:SystemRoot\System32\Tasks" (Join-Path $out 'tasks') -Recurse }

# $MFT and the newest allocated $UsnJrnl:$J bytes, read from the raw volume.
$ntfs = Join-Path $out 'ntfs'
if (-not $SkipNtfs) {
    Step 'ntfs' {
        Push-Location $repoRoot
        try { & $Python -m triage_engine.raw_ntfs $Volume $ntfs --usn-cap-mib $UsnCapMiB | Out-Null }
        finally { Pop-Location }
        if ($LASTEXITCODE -ne 0) { throw "raw NTFS extraction exited $LASTEXITCODE" }
    }
}

# Hash everything collected, then record what succeeded and what did not.
$files = Get-ChildItem $out -Recurse -File | ForEach-Object {
    [ordered]@{ path = $_.FullName.Substring($out.Length + 1); size_bytes = $_.Length
                sha256 = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant() }
}
$manifest = [ordered]@{
    schema_version = '1.0'; kind = 'windows_evidence_collection'; host = $env:COMPUTERNAME
    collected_at = $collected.ToUniversalTime().ToString('o'); volume = $Volume.ToUpperInvariant()
    collector = 'scripts/collect-windows-evidence.ps1'; steps = $steps; files = @($files)
}
$manifest | ConvertTo-Json -Depth 6 | Set-Content -Encoding utf8 (Join-Path $out 'collection_manifest.json')

# Package the artifacts as a verified bundle for `triage investigate --artifacts`.
$bundle = Join-Path $out 'bundle'
$pack = @('-m', 'triage_engine.cli', 'pack-artifacts', '--output-dir', $bundle, '--host', $env:COMPUTERNAME,
          '--observed-at', $collected.ToUniversalTime().ToString('o'), '--task-xml', (Join-Path $out 'tasks'))
if ((Get-ChildItem $prefetch -Filter *.pf -ErrorAction SilentlyContinue | Measure-Object).Count) { $pack += @('--prefetch-source', $prefetch) }
foreach ($pair in @(@('SYSTEM', 'system'), @('SOFTWARE', 'software'), @('Amcache.hve', 'amcache'), @('NTUSER.DAT', 'ntuser'))) {
    $hive = Join-Path $hives $pair[0]
    if (Test-Path -LiteralPath $hive) { $pack += @('--registry-hive', $hive, '--hive-type', $pair[1]) }
}
if (Test-Path -LiteralPath (Join-Path $ntfs 'MFT.bin')) {
    $pack += @('--ntfs-mft', (Join-Path $ntfs 'MFT.bin'), '--ntfs-volume', $Volume.ToUpperInvariant(), '--allow-large-ntfs')
    if (Test-Path -LiteralPath (Join-Path $ntfs 'UsnJrnl_J.bin')) { $pack += @('--ntfs-usn-journal', (Join-Path $ntfs 'UsnJrnl_J.bin')) }
}
Push-Location $repoRoot
try { & $Python @pack } finally { Pop-Location }

$failed = @($steps | Where-Object { $_.status -eq 'failed' })
Write-Output "Collected $($files.Count) files into $out ($($failed.Count) step(s) failed; see collection_manifest.json)."
Write-Output "Investigate with:"
Write-Output "  python -m triage_engine.cli investigate --evtx `"$logs`" --artifacts `"$bundle`" --allow-large-ntfs"
