[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$OutputDirectory
)

$ErrorActionPreference = 'Stop'
$script:Records = New-Object 'System.Collections.Generic.List[object]'
$script:Warnings = New-Object 'System.Collections.Generic.List[string]'
$script:SuccessfulQueries = 0

function Add-CollectionWarning {
    param([string]$Message)
    $script:Warnings.Add($Message)
}

function Add-RunKeyRecords {
    param(
        [Microsoft.Win32.RegistryHive]$Hive,
        [Microsoft.Win32.RegistryView]$View,
        [string]$ViewName,
        [string]$SubKey
    )

    $baseKey = $null
    $runKey = $null
    $location = "$Hive\$ViewName\$SubKey"
    try {
        $baseKey = [Microsoft.Win32.RegistryKey]::OpenBaseKey($Hive, $View)
        $runKey = $baseKey.OpenSubKey($SubKey, $false)
        # A missing autorun key is a successful query with no entries.
        $script:SuccessfulQueries++
        if ($null -eq $runKey) { return }
        foreach ($valueName in $runKey.GetValueNames()) {
            $value = $runKey.GetValue($valueName, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
            $script:Records.Add([ordered]@{
                kind = 'registry_run'
                name = if ([string]::IsNullOrEmpty([string]$valueName)) { '(Default)' } else { [string]$valueName }
                location = $location
                command = [string]$value
                user = if ($Hive -eq [Microsoft.Win32.RegistryHive]::CurrentUser) { [string]$env:USERNAME } else { '' }
            })
        }
    }
    catch {
        Add-CollectionWarning "Registry query failed at ${location}: $($_.Exception.Message)"
    }
    finally {
        if ($null -ne $runKey) { $runKey.Dispose() }
        if ($null -ne $baseKey) { $baseKey.Dispose() }
    }
}

function Assert-OutputDirectory {
    param([string]$Path)

    $fullPath = [IO.Path]::GetFullPath($Path)
    $volumeRoot = [IO.Path]::GetPathRoot($fullPath)
    if ([StringComparer]::OrdinalIgnoreCase.Equals($fullPath.TrimEnd('\'), $volumeRoot.TrimEnd('\'))) {
        throw "Refusing to use a volume root as OutputDirectory: $fullPath"
    }

    $repoRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..')).TrimEnd('\')
    $normalized = $fullPath.TrimEnd('\')
    if ([StringComparer]::OrdinalIgnoreCase.Equals($normalized, $repoRoot)) {
        throw "Refusing to write collector output to the repository root: $fullPath"
    }
    if ($normalized.StartsWith($repoRoot + '\', [StringComparison]::OrdinalIgnoreCase)) {
        $relative = $normalized.Substring($repoRoot.Length).TrimStart('\')
        $allowed = $relative -match '^(runtime|artifacts[\\/]reports)([\\/]|$)'
        if (-not $allowed) {
            throw "OutputDirectory inside the repository must be under runtime\ or artifacts\reports\: $fullPath"
        }
    }

    foreach ($fileName in @('manifest.json', 'persistence.json')) {
        $target = Join-Path $fullPath $fileName
        if (Test-Path -LiteralPath $target) {
            throw "Refusing to overwrite existing collector artifact: $target"
        }
    }
    return $fullPath
}

$OutputDirectory = Assert-OutputDirectory -Path $OutputDirectory
New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null

# Collect machine-wide native and WOW autoruns plus this process user's HKCU.
# Other users' hives may be unloaded or inaccessible and are intentionally not loaded.
$runLocations = @(
    @{ Hive = [Microsoft.Win32.RegistryHive]::LocalMachine; View = [Microsoft.Win32.RegistryView]::Registry64; ViewName = 'native'; Path = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Run' },
    @{ Hive = [Microsoft.Win32.RegistryHive]::LocalMachine; View = [Microsoft.Win32.RegistryView]::Registry64; ViewName = 'native'; Path = 'SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce' },
    @{ Hive = [Microsoft.Win32.RegistryHive]::CurrentUser; View = [Microsoft.Win32.RegistryView]::Registry64; ViewName = 'current_user'; Path = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Run' },
    @{ Hive = [Microsoft.Win32.RegistryHive]::CurrentUser; View = [Microsoft.Win32.RegistryView]::Registry64; ViewName = 'current_user'; Path = 'SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce' }
)
if ([Environment]::Is64BitOperatingSystem) {
    $runLocations += @(
        @{ Hive = [Microsoft.Win32.RegistryHive]::LocalMachine; View = [Microsoft.Win32.RegistryView]::Registry32; ViewName = 'wow32'; Path = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Run' },
        @{ Hive = [Microsoft.Win32.RegistryHive]::LocalMachine; View = [Microsoft.Win32.RegistryView]::Registry32; ViewName = 'wow32'; Path = 'SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce' }
    )
}
foreach ($location in $runLocations) {
    Add-RunKeyRecords -Hive $location.Hive -View $location.View -ViewName $location.ViewName -SubKey $location.Path
}
Add-CollectionWarning 'Registry scope includes machine autoruns and the current user only; other users'' hives are not loaded or covered.'

try {
    $tasks = @(Get-ScheduledTask -ErrorAction Stop)
    $script:SuccessfulQueries++
    foreach ($task in $tasks) {
        $actions = @($task.Actions)
        if ($actions.Count -eq 0) { $actions = @($null) }
        for ($i = 0; $i -lt $actions.Count; $i++) {
            $action = $actions[$i]
            $command = ''
            if ($null -ne $action) {
                $command = [string]$action.Execute
                if ($action.Arguments) { $command = ($command + ' ' + [string]$action.Arguments).Trim() }
            }
            $script:Records.Add([ordered]@{
                kind = 'scheduled_task'
                name = [string]$task.TaskName
                location = [string]$task.TaskPath
                command = $command
                user = [string]$task.Principal.UserId
                enabled = ([string]$task.State -ne 'Disabled')
                state = [string]$task.State
            })
        }
    }
}
catch {
    Add-CollectionWarning "Scheduled task query failed: $($_.Exception.Message)"
}

try {
    $services = @(Get-CimInstance -ClassName Win32_Service -ErrorAction Stop)
    $script:SuccessfulQueries++
    foreach ($service in $services) {
        $script:Records.Add([ordered]@{
            kind = 'service'
            name = [string]$service.Name
            location = 'Win32_Service'
            command = [string]$service.PathName
            user = [string]$service.StartName
            enabled = ([string]$service.StartMode -ne 'Disabled')
            state = [string]$service.State
        })
    }
}
catch {
    Add-CollectionWarning "Service query failed: $($_.Exception.Message)"
}

if ($script:SuccessfulQueries -eq 0) {
    throw 'Every persistence query failed; refusing to write an empty snapshot.'
}
$utf8 = [System.Text.UTF8Encoding]::new($false)
$persistence = [ordered]@{
    schema_version = '1.0'
    records = @($script:Records.ToArray())
}
$persistenceJson = ConvertTo-Json -InputObject $persistence -Depth 8
$persistencePath = Join-Path $OutputDirectory 'persistence.json'
[IO.File]::WriteAllText($persistencePath, $persistenceJson, $utf8)
$persistenceBytes = [IO.File]::ReadAllBytes($persistencePath)
$sha256 = [Security.Cryptography.SHA256]::Create()
try {
    $hash = ([BitConverter]::ToString($sha256.ComputeHash($persistenceBytes))).Replace('-', '').ToLowerInvariant()
}
finally {
    $sha256.Dispose()
}

$manifest = [ordered]@{
    schema_version = '1.0'
    kind = 'windows_persistence_snapshot'
    host = [string]$env:COMPUTERNAME
    observed_at = [DateTime]::UtcNow.ToString('o')
    collector = [ordered]@{ name = 'triage-windows-persistence'; version = '1.0' }
    completeness = if ($script:Warnings.Count -gt 0) { 'partial' } else { 'complete' }
    warnings = @($script:Warnings.ToArray())
    limitations = @('Configuration describes current local state and does not prove that any command or task executed.')
    files = @([ordered]@{
        path = 'persistence.json'
        kind = 'persistence_records'
        sha256 = $hash
        size_bytes = [long]$persistenceBytes.Length
    })
}
$manifestJson = ConvertTo-Json -InputObject $manifest -Depth 8
[IO.File]::WriteAllText((Join-Path $OutputDirectory 'manifest.json'), $manifestJson, $utf8)
Write-Host "Wrote $($script:Records.Count) persistence record(s) to $OutputDirectory; warnings: $($script:Warnings.Count)"
