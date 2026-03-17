[CmdletBinding()]
param(
    [string]$SysmonConfigPath = (Join-Path $PSScriptRoot "..\\config\\sysmon\\triage-sysmon-minimal.xml"),
    [switch]$SkipSysmon,
    [switch]$SkipPowerShellLogging
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

function Test-IsAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Enable-PowerShellTelemetry {
    Write-Host "[1/3] Enabling PowerShell Operational log..." -ForegroundColor Cyan
    & wevtutil sl "Microsoft-Windows-PowerShell/Operational" /e:true | Out-Null

    Write-Host "[2/3] Enabling Script Block and Module logging..." -ForegroundColor Cyan
    $scriptBlockKey = "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging"
    $moduleKey = "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ModuleLogging"
    $moduleNamesKey = Join-Path $moduleKey "ModuleNames"

    New-Item -Path $scriptBlockKey -Force | Out-Null
    New-ItemProperty -Path $scriptBlockKey -Name EnableScriptBlockLogging -Value 1 -PropertyType DWord -Force | Out-Null

    New-Item -Path $moduleKey -Force | Out-Null
    New-ItemProperty -Path $moduleKey -Name EnableModuleLogging -Value 1 -PropertyType DWord -Force | Out-Null
    New-Item -Path $moduleNamesKey -Force | Out-Null
    New-ItemProperty -Path $moduleNamesKey -Name "*" -Value "*" -PropertyType String -Force | Out-Null
}

function Ensure-SysmonInstalled {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ConfigPath
    )

    if (-not (Test-Path -LiteralPath $ConfigPath)) {
        throw "Sysmon config not found: $ConfigPath"
    }

    $resolvedConfig = (Resolve-Path -LiteralPath $ConfigPath).Path
    $sysmonService = Get-Service -Name Sysmon64 -ErrorAction SilentlyContinue
    if (-not $sysmonService) {
        $sysmonService = Get-Service -Name Sysmon -ErrorAction SilentlyContinue
    }

    if (-not $sysmonService) {
        Write-Host "[3/3] Installing built-in Sysmon optional feature..." -ForegroundColor Cyan
        Enable-WindowsOptionalFeature -Online -FeatureName Sysmon -All -NoRestart | Out-Null
        $sysmonService = Get-Service -Name Sysmon64 -ErrorAction SilentlyContinue
        if (-not $sysmonService) {
            $sysmonService = Get-Service -Name Sysmon -ErrorAction SilentlyContinue
        }
    } else {
        Write-Host "[3/3] Sysmon service already present; updating config..." -ForegroundColor Cyan
    }

    $sysmonCmd = Get-Command sysmon -ErrorAction SilentlyContinue
    if (-not $sysmonCmd) {
        throw "The 'sysmon' command was not found after enabling the optional feature. Reopen the elevated shell and run again."
    }

    if ($sysmonService) {
        & $sysmonCmd.Source -c $resolvedConfig | Out-Null
    } else {
        & $sysmonCmd.Source -accepteula -i $resolvedConfig | Out-Null
    }
}

function Get-TelemetryStatus {
    $psOperationalEnabled = $false
    $psOperationalLine = & wevtutil gl "Microsoft-Windows-PowerShell/Operational" 2>$null | Select-String '^enabled:'
    if ($psOperationalLine) {
        $psOperationalEnabled = $psOperationalLine.Line -match "true"
    }

    $sysmonService = Get-Service -Name Sysmon64 -ErrorAction SilentlyContinue
    if (-not $sysmonService) {
        $sysmonService = Get-Service -Name Sysmon -ErrorAction SilentlyContinue
    }

    [ordered]@{
        powerShellOperationalEnabled = $psOperationalEnabled
        scriptBlockLoggingEnabled = (Get-ItemProperty -Path "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging" -ErrorAction SilentlyContinue).EnableScriptBlockLogging -eq 1
        moduleLoggingEnabled = (Get-ItemProperty -Path "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ModuleLogging" -ErrorAction SilentlyContinue).EnableModuleLogging -eq 1
        sysmonInstalled = [bool]$sysmonService
        sysmonStatus = if ($sysmonService) { $sysmonService.Status.ToString() } else { "NotInstalled" }
        sysmonConfigPath = $ConfigPath
    }
}

if (-not (Test-IsAdministrator)) {
    throw "Run this script from an elevated PowerShell session (Run as Administrator)."
}

$ConfigPath = (Resolve-Path -LiteralPath $SysmonConfigPath).Path

if (-not $SkipPowerShellLogging) {
    Enable-PowerShellTelemetry
}

if (-not $SkipSysmon) {
    Ensure-SysmonInstalled -ConfigPath $ConfigPath
}

Write-Host ""
Write-Host "Telemetry enablement complete." -ForegroundColor Green
Get-TelemetryStatus | ConvertTo-Json -Depth 4
