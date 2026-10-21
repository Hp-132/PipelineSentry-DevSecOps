# Runs the whole PipelineSentry stack end to end and prints a PASS/FAIL summary.
#
#   .\scripts\run-all.ps1                  start everything, run demos and all checks, keep it running
#   .\scripts\run-all.ps1 -SkipTests       start everything and run the demos only (quicker, lighter)
#   .\scripts\run-all.ps1 -SkipDashboard   backend, demos and checks only (no Node.js needed)
#   .\scripts\run-all.ps1 -Stop            tear the stack down at the end
#   .\scripts\run-all.ps1 -Down            just stop a running stack and the dashboard
#
# If PowerShell blocks the script:  powershell -ExecutionPolicy Bypass -File .\scripts\run-all.ps1
param(
    [switch]$SkipTests,
    [switch]$SkipDashboard,
    [switch]$Stop,
    [switch]$Down,
    [switch]$NoBrowser
)

Set-Location (Split-Path $PSScriptRoot -Parent)
$ApiUrl = "http://localhost:8000"
$DashboardUrl = "http://localhost:5173"
$DashboardPidFile = Join-Path $env:TEMP "pipelinesentry-dashboard.pid"
# Docker Desktop's Bake integration can fail with "DeadlineExceeded" / "no such job"
$env:COMPOSE_BAKE = "false"

$results = New-Object System.Collections.Generic.List[object]

function Section($title) {
    Write-Host ""
    Write-Host ("=" * 72) -ForegroundColor DarkCyan
    Write-Host "  $title" -ForegroundColor Cyan
    Write-Host ("=" * 72) -ForegroundColor DarkCyan
}

function Record($name, [bool]$ok, $detail = "") {
    $results.Add([pscustomobject]@{ Step = $name; Result = $(if ($ok) { "PASS" } else { "FAIL" }); Detail = $detail })
    if ($ok) { Write-Host "  -> PASS" -ForegroundColor Green } else { Write-Host "  -> FAIL $detail" -ForegroundColor Red }
}

# Runs a native command with live output; returns $true when it exits 0
function Run([string]$name, [scriptblock]$command) {
    Write-Host ""
    Write-Host "> $name" -ForegroundColor Yellow
    # Out-Host prints live; otherwise the output would become this function's return value
    & $command | Out-Host
    $ok = ($LASTEXITCODE -eq 0)
    Record $name $ok $(if ($ok) { "" } else { "(exit code $LASTEXITCODE)" })
    return $ok
}

function Test-Url($url) {
    try {
        $r = Invoke-WebRequest -Uri $url -UseBasicParsing -TimeoutSec 5
        return $r.StatusCode -eq 200
    } catch { return $false }
}

function Stop-Dashboard {
    if (Test-Path $DashboardPidFile) {
        $dashPid = Get-Content $DashboardPidFile
        # taskkill /T also stops the node process started by npm
        taskkill /PID $dashPid /T /F 2>$null | Out-Null
        Remove-Item $DashboardPidFile -ErrorAction SilentlyContinue
        Write-Host "Dashboard stopped."
    }
}

function Show-Summary {
    Section "Summary"
    $results | Format-Table -AutoSize | Out-String | Write-Host
    $failed = @($results | Where-Object { $_.Result -eq "FAIL" }).Count
    if ($failed -eq 0) {
        Write-Host "  ALL $($results.Count) STEPS PASSED" -ForegroundColor Green
    } else {
        Write-Host "  $failed OF $($results.Count) STEPS FAILED - scroll up for the output of each failed step" -ForegroundColor Red
    }
    return $failed
}

if ($Down) {
    Stop-Dashboard
    docker compose down
    exit $LASTEXITCODE
}

# ---------------------------------------------------------------------------
Section "1/6  Prerequisites"
if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
    Write-Host "Docker is not installed. Install Docker Desktop: https://docs.docker.com/get-docker/" -ForegroundColor Red
    exit 1
}
docker info --format "Docker engine {{.ServerVersion}}, {{.NCPU}} CPUs, memory for containers: {{.MemTotal}} bytes" 2>$null
if ($LASTEXITCODE -ne 0) {
    Write-Host "The Docker engine is not running. Start Docker Desktop, wait for 'Engine running', then re-run." -ForegroundColor Red
    exit 1
}
if (-not $SkipDashboard -and -not (Get-Command npm -ErrorAction SilentlyContinue)) {
    Write-Host "Node.js/npm not found: skipping the dashboard (install Node 18+ to include it)." -ForegroundColor Yellow
    $SkipDashboard = $true
}
try {
    $freeMb = [int]((Get-CimInstance Win32_OperatingSystem).FreePhysicalMemory / 1024)
    Write-Host "Free RAM: $freeMb MB"
    if ($freeMb -lt 2048) {
        Write-Host "Low memory: close other apps/containers if the start-up is slow ('docker ps' lists them)." -ForegroundColor Yellow
    }
} catch {}
if (-not (Test-Path .env)) {
    Copy-Item .env.example .env
    Write-Host "Created .env from .env.example"
}
Record "Prerequisites" $true

# ---------------------------------------------------------------------------
Section "2/6  Backend (Postgres, RabbitMQ, Redis, registry, API, worker, responder)"
Write-Host "Building and starting containers. The first run takes several minutes."
$started = Run "docker compose up" { docker compose up -d --build --wait }
if (-not $started) {
    # The API can report unhealthy if it came up before RabbitMQ; it reconnects by itself, so retry once
    Write-Host "Retrying once (a service may have started before its dependency was ready)..." -ForegroundColor Yellow
    $results.RemoveAt($results.Count - 1)
    $started = Run "docker compose up" { docker compose up -d --wait }
}
docker compose ps | Out-Host

Write-Host ""
Write-Host "Waiting for $ApiUrl/health ..."
$healthy = $false
for ($i = 0; $i -lt 40; $i++) {
    try {
        $health = Invoke-RestMethod -Uri "$ApiUrl/health" -TimeoutSec 5
        if ($health.status -eq "ok") { $healthy = $true; break }
    } catch {}
    Start-Sleep -Seconds 3
}
if ($healthy) { $health | ConvertTo-Json -Compress | Write-Host }
Record "API health" $healthy $(if ($healthy) { "" } else { "see: docker compose logs api rabbitmq" })
if (-not $healthy) {
    Write-Host "The backend is not healthy, so the demos cannot run. Troubleshooting: README.md > Quick Start." -ForegroundColor Red
    [void](Show-Summary)
    exit 1
}

# ---------------------------------------------------------------------------
Section "3/6  Dashboard"
if ($SkipDashboard) {
    Write-Host "Skipped."
} elseif (Test-Url $DashboardUrl) {
    Write-Host "Already running at $DashboardUrl"
    Record "Dashboard" $true
} else {
    if (-not (Test-Path dashboard\node_modules)) {
        Push-Location dashboard
        [void](Run "npm ci" { npm ci --no-audit --no-fund })
        Pop-Location
    }
    $proc = Start-Process -FilePath "cmd.exe" -ArgumentList "/c", "npm run dev > ..\dashboard-dev.log 2>&1" `
        -WorkingDirectory (Resolve-Path dashboard) -WindowStyle Hidden -PassThru
    $proc.Id | Set-Content $DashboardPidFile
    Write-Host "Starting the dev server (log: dashboard-dev.log) ..."
    $up = $false
    for ($i = 0; $i -lt 30; $i++) { if (Test-Url $DashboardUrl) { $up = $true; break }; Start-Sleep -Seconds 2 }
    Record "Dashboard" $up $(if ($up) { "" } else { "see dashboard-dev.log" })
}

# ---------------------------------------------------------------------------
Section "4/6  Attack scenarios (detection layers)"
foreach ($id in @("01", "02", "03", "04", "05", "06", "07")) {
    [void](Run "Attack scenario $id" { docker compose exec -T api python attack-lab/run.py $id })
}

# ---------------------------------------------------------------------------
Section "5/6  End-to-end demo: detection -> response -> recovery -> signing -> SBOM -> policy"
[void](Run "End-to-end demo" { docker compose exec -T api python scripts/demo_member2.py })

# ---------------------------------------------------------------------------
Section "6/6  Checks"
if ($SkipTests) {
    Write-Host "Skipped (-SkipTests)."
} else {
    [void](Run "Python test suite (unit + integration)" { docker compose exec -T api pytest -q -p no:cacheprovider })
    [void](Run "OPA policy tests" { docker compose exec -T api opa test policy/opa -v })
    [void](Run "Kyverno policy tests" { docker run --rm -v "${PWD}/policy:/policy" ghcr.io/kyverno/kyverno-cli:v1.13.2 test /policy/kyverno })
    if (-not $SkipDashboard) {
        Push-Location dashboard
        [void](Run "Dashboard type-check" { npm run type-check })
        Pop-Location
    }
}

# ---------------------------------------------------------------------------
$failed = Show-Summary
Write-Host ""
if ($Stop) {
    Stop-Dashboard
    docker compose down
    Write-Host "Stack stopped."
} else {
    Write-Host "Still running - look around:" -ForegroundColor Cyan
    if (-not $SkipDashboard) { Write-Host "  Dashboard        $DashboardUrl" }
    Write-Host "  API docs         $ApiUrl/docs"
    Write-Host "  Incidents (JSON) $ApiUrl/incidents"
    Write-Host "  RabbitMQ UI      http://localhost:15672   (user/password from .env)"
    Write-Host ""
    Write-Host "Stop everything:   .\scripts\run-all.ps1 -Down"
    if (-not $SkipDashboard -and -not $NoBrowser) { Start-Process $DashboardUrl }
}
exit $failed
