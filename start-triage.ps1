[CmdletBinding()]
param(
    [ValidateSet("server", "investigate", "readiness", "docker")]
    [string]$Mode = "server",
    [string]$EvtxPath = "",
    [string]$CaseName = "",
    [string]$BindHost = "127.0.0.1",
    [int]$Port = 8000,
    [switch]$Reload,
    [switch]$BootstrapDeps,
    [switch]$EnableSigma,
    [string[]]$SigmaRules = @(),
    [string[]]$Tuning = @(),
    [switch]$Overwrite,
    [switch]$Detach
)

$ErrorActionPreference = "Stop"
$repoRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $repoRoot

function Resolve-PythonSpec {
    $candidates = @()

    if ($env:TRIAGE_PYTHON) {
        $candidates += $env:TRIAGE_PYTHON
    }

    $venvPython = Join-Path $repoRoot ".venv\Scripts\python.exe"
    $candidates += $venvPython

    if ($env:LOCALAPPDATA) {
        $windowsAppsPattern = Join-Path $env:LOCALAPPDATA "Microsoft\WindowsApps\PythonSoftwareFoundation.Python.*\python.exe"
        $windowsAppsCandidates = Get-ChildItem -Path $windowsAppsPattern -ErrorAction SilentlyContinue |
            Sort-Object FullName -Descending |
            Select-Object -ExpandProperty FullName
        $candidates += $windowsAppsCandidates
    }

    $pythonCommand = Get-Command python -ErrorAction SilentlyContinue
    if ($pythonCommand) {
        $candidates += $pythonCommand.Source
    }

    foreach ($candidate in ($candidates | Where-Object { $_ } | Select-Object -Unique)) {
        if (Test-Path $candidate) {
            return @{
                Command = $candidate
                Prefix = @()
            }
        }
    }

    $pyLauncher = Get-Command py -ErrorAction SilentlyContinue
    if ($pyLauncher) {
        return @{
            Command = $pyLauncher.Source
            Prefix = @("-3")
        }
    }

    throw "No Python runtime was found. Set TRIAGE_PYTHON, create .venv\Scripts\python.exe, or install Python 3.10+."
}

function Invoke-Python {
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$Arguments
    )

    $command = @($script:PythonSpec.Command) + $script:PythonSpec.Prefix + $Arguments
    Write-Host ""
    Write-Host "==> $($command -join ' ')"
    & $script:PythonSpec.Command @($script:PythonSpec.Prefix + $Arguments)
    if ($LASTEXITCODE -ne 0) {
        throw "Python command failed with exit code $LASTEXITCODE."
    }
}

function Invoke-Docker {
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$Arguments
    )

    $dockerCommand = Get-Command docker -ErrorAction SilentlyContinue
    if (-not $dockerCommand) {
        throw "Docker was not found in PATH. Install Docker Desktop or run the local Python mode instead."
    }

    $command = @($dockerCommand.Source) + $Arguments
    Write-Host ""
    Write-Host "==> $($command -join ' ')"
    & $dockerCommand.Source @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "Docker command failed with exit code $LASTEXITCODE."
    }
}

if ($Mode -ne "docker") {
    $script:PythonSpec = Resolve-PythonSpec
    $env:TRIAGE_RUNTIME_MODE = "local"

    if ($BootstrapDeps) {
        Write-Host "Installing local project dependencies..."
        Invoke-Python -Arguments @("-m", "pip", "install", "-e", ".[server,sigma]")
    }
} elseif ($BootstrapDeps) {
    Write-Warning "-BootstrapDeps is only used for local Python mode and will be ignored for Docker."
}

switch ($Mode) {
    "server" {
        Write-Host "Starting Triage Engine dashboard on http://$BindHost`:$Port"
        Write-Host "If this is the first run, open the page and create the initial admin account."

        $args = @("server.py", "--host", $BindHost, "--port", $Port.ToString())
        if ($Reload) {
            $args += "--reload"
        }
        Invoke-Python -Arguments $args
    }

    "investigate" {
        if (-not $EvtxPath) {
            throw "Mode 'investigate' requires -EvtxPath."
        }

        $args = @("-m", "triage_engine.cli", "investigate", "--evtx", $EvtxPath)
        if ($CaseName) {
            $args += @("--case", $CaseName)
        }
        if ($Overwrite) {
            $args += "--overwrite"
        }
        if ($EnableSigma) {
            $args += "--enable-sigma"
        }
        foreach ($rulePath in $SigmaRules) {
            $args += @("--sigma-rules", $rulePath)
        }
        foreach ($tuningPath in $Tuning) {
            $args += @("--tuning", $tuningPath)
        }

        Invoke-Python -Arguments $args
    }

    "readiness" {
        Invoke-Python -Arguments @("scripts/production_readiness.py")
    }

    "docker" {
        Write-Host "Starting Triage Engine with Docker Compose on http://127.0.0.1:8000"
        Write-Host "The dashboard runtime badge should show Docker after the page loads."
        $args = @("compose", "up", "--build")
        if ($Detach) {
            $args += "-d"
        }
        Invoke-Docker -Arguments $args
        if ($Detach) {
            Write-Host "Docker services are running in the background. Use 'docker compose logs -f' to watch startup output."
        }
    }
}
