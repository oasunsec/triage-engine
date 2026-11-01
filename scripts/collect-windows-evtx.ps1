[CmdletBinding()]
param(
    [string]$OutputDirectory = "",
    [string[]]$Channel = @("Security", "System", "Microsoft-Windows-PowerShell/Operational", "Microsoft-Windows-Sysmon/Operational")
)

$ErrorActionPreference = "Stop"
if (-not $OutputDirectory) { $OutputDirectory = Join-Path (Get-Location) ("triage-collector-" + (Get-Date -Format "yyyyMMdd-HHmmss")) }
$OutputDirectory = [IO.Path]::GetFullPath($OutputDirectory)
New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
$failures = @()
$files = @()
foreach ($name in $Channel) {
    $safe = ($name -replace '[^A-Za-z0-9._-]+', '_') + '.evtx'
    $target = Join-Path $OutputDirectory $safe
    try {
        & wevtutil.exe epl $name $target /ow:true 2>$null
        if ($LASTEXITCODE -ne 0) { throw "wevtutil exit code $LASTEXITCODE" }
        $hash = Get-FileHash -LiteralPath $target -Algorithm SHA256
        $files += [ordered]@{ path = $safe; size = (Get-Item $target).Length; sha256 = $hash.Hash.ToLowerInvariant() }
    } catch {
        $failures += [ordered]@{ channel = $name; error = $_.Exception.Message }
    }
}
$manifest = [ordered]@{
    schema_version = '1.0'; method = 'portable_collector'; source_host = $env:COMPUTERNAME
    collected_at = (Get-Date).ToUniversalTime().ToString('o'); timezone = [TimeZoneInfo]::Local.Id
    channels = @($Channel); failures = @($failures); tool_version = 'corrobora'; files = @($files)
}
$manifest | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Join-Path $OutputDirectory 'collection_manifest.json') -Encoding UTF8
Write-Host "Collected $($files.Count) channel(s) to $OutputDirectory; failures: $($failures.Count)"
