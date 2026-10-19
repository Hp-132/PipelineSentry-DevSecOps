# PipelineSentry

CI/CD pipeline attack detection for a final-year BTech CSE Cloud DevOps project.
This README is completed in the final phase.

## Architecture

**Member 1** (Complete): Event ingestion, static/behaviour/runtime detection, correlation, deduplication, alert persistence.

**Member 2** (Stub): Response, recovery, supply-chain, policy modules (not implemented).

**Frontend (Dashboard)**: Premium React UI for alerts, incidents, attack lab, and system health.

## Quick Start

### Backend (Docker)

```bash
cd C:\Users\Hensi\Downloads\PipelineSentry
cp .env.example .env      # edit passwords if needed
make up                   # or: .\scripts\make.ps1 up
```

Services available:
- **Detection API** — `http://localhost:8000` (FastAPI)
- **API Docs** — `http://localhost:8000/docs`
- **RabbitMQ UI** — `http://localhost:15672` (default: guest/guest)

### Frontend (Dashboard)

```powershell
cd C:\Users\Hensi\Downloads\PipelineSentry\dashboard
npm install
npm run dev
```

Dashboard available at `http://localhost:5173`

### Run a Scenario

```bash
make attack ID=01         # or: .\scripts\make.ps1 attack 01
# or run from the dashboard UI: Attack Lab → Run Scenario
```

## Key URLs

| Component | URL | Purpose |
|-----------|-----|---------|
| Dashboard | http://localhost:5173 | UI for alerts, incidents, attack lab |
| API | http://localhost:8000 | FastAPI detection backend |
| API Docs | http://localhost:8000/docs | Swagger documentation |
| RabbitMQ | http://localhost:15672 | Message queue management |
| Health | http://localhost:8000/health | Service health check |

## Cleanup

`make down` stops containers and keeps data. `make reset` deletes volumes.
