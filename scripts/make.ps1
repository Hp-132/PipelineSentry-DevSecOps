# PowerShell equivalent of the Makefile, e.g.  .\scripts\make.ps1 up   or   .\scripts\make.ps1 attack 01
param(
    [Parameter(Position = 0)][string]$Target = "help",
    [Parameter(Position = 1)][string]$Id = "01",
    [switch]$Force
)

Set-Location (Split-Path $PSScriptRoot -Parent)

function Ensure-Env {
    if (-not (Test-Path .env)) {
        Copy-Item .env.example .env
        Write-Host "Created .env from .env.example"
    }
}

function Invoke-Compose {
    docker compose @args
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
}

switch ($Target) {
    "up"        { Ensure-Env; Invoke-Compose up -d --build --wait }
    "down"      { Invoke-Compose down }
    "reset" {
        Write-Warning "This deletes all stored alerts, events, baselines and queued messages."
        if (-not $Force) {
            $answer = Read-Host "Type 'yes' to continue"
            if ($answer -ne "yes") { Write-Host "Cancelled."; exit 1 }
        }
        Invoke-Compose down -v
    }
    "test"      { Ensure-Env; Invoke-Compose up -d --build --wait; Invoke-Compose run --rm api pytest -q }
    "test-unit" { Ensure-Env; Invoke-Compose build api; Invoke-Compose run --rm --no-deps api pytest -q -m "not integration" }
    "logs"      { Invoke-Compose logs -f --tail=100 api worker }
    "ps"        { Invoke-Compose ps }
    "baseline"  { Invoke-Compose exec -T worker python -m detection.behaviour.baseline }
    "attack"    { Invoke-Compose exec -T api python attack-lab/run.py $Id }
    "demo" {
        Write-Host "=== PipelineSentry end-to-end demo ==="
        foreach ($scenario in @("01","04","05","06","07")) {
            Write-Host "`n--- Scenario $scenario ---"
            Invoke-Compose exec -T api python attack-lab/run.py $scenario
        }
        Write-Host "`n=== Demo complete. ==="
    }
    default     { Write-Host "Targets: up, down, reset [-Force], test, test-unit, logs, ps, baseline, attack <01-07>, demo" }
}
