[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$ComputerName,
    [string]$OutputDirectory = "",
    [string[]]$Channel = @("Security", "System", "Microsoft-Windows-PowerShell/Operational", "Microsoft-Windows-Sysmon/Operational")
)

$ErrorActionPreference = "Stop"
if (-not $OutputDirectory) { $OutputDirectory = Join-Path (Get-Location) ("triage-remote-" + ($ComputerName -replace '[^A-Za-z0-9.-]', '_')) }
$OutputDirectory = [IO.Path]::GetFullPath($OutputDirectory)
New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
$credential = Get-Credential -Message "Credentials for $ComputerName (not stored by Triage Engine)"
$failures = @(); $files = @()
foreach ($name in $Channel) {
    $safe = ($name -replace '[^A-Za-z0-9._-]+', '_') + '.evtx'
    $target = Join-Path $OutputDirectory $safe
    try {
        $bytes = Invoke-Command -ComputerName $ComputerName -Credential $credential -ScriptBlock {
            param($channelName)
            $tmp = Join-Path $env:TEMP (([guid]::NewGuid()).ToString() + '.evtx')
            try { & wevtutil.exe epl $channelName $tmp /ow:true; if ($LASTEXITCODE -ne 0) { throw "wevtutil exit code $LASTEXITCODE" }; [Convert]::ToBase64String([IO.File]::ReadAllBytes($tmp)) }
            finally { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue }
        } -ArgumentList $name
        [IO.File]::WriteAllBytes($target, [Convert]::FromBase64String([string]$bytes))
        $hash = Get-FileHash -LiteralPath $target -Algorithm SHA256
        $files += [ordered]@{ path = $safe; size = (Get-Item $target).Length; sha256 = $hash.Hash.ToLowerInvariant() }
    } catch { $failures += [ordered]@{ channel = $name; error = $_.Exception.Message } }
}
[ordered]@{ schema_version='1.0'; method='remote_collection'; source_host=$ComputerName; collected_at=(Get-Date).ToUniversalTime().ToString('o'); timezone=[TimeZoneInfo]::Local.Id; channels=@($Channel); failures=@($failures); tool_version='triage-engine'; files=@($files) } |
    ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Join-Path $OutputDirectory 'collection_manifest.json') -Encoding UTF8
Write-Host "Collected $($files.Count) channel(s) from $ComputerName; failures: $($failures.Count)"
