export type Layer = 'static' | 'behaviour' | 'runtime' | 'correlation'
export type Severity = 'low' | 'med' | 'high' | 'critical'
export type AlertStatus = 'new' | 'handled'
export type EventKind = 'workflow' | 'secrets' | 'dependency' | 'image' | 'run_metrics' | 'runtime'

export interface Alert {
  id: string
  run_id: string
  workflow: string
  timestamp: string
  layer: Layer
  attack_id?: string
  severity: Severity
  risk_score: number
  title: string
  evidence: Record<string, any>
  recommended_action: string
  status: AlertStatus
  parent_alert_id?: string
}

export interface HealthCheck {
  status: 'ok' | 'degraded' | 'unhealthy'
  checks: {
    database: string
    rabbitmq: string
    redis: string
  }
  queues?: Record<string, number>
}

export interface EventStatus {
  event_id: string
  kind: EventKind
  run_id: string
  workflow: string
  attack_id?: string
  source: string
  status: string
  attempts: number
  error?: string
  alert_ids: string[]
  received_at: string
  processed_at?: string
}

export interface TimelineEntry {
  timestamp: string
  alert_id: string
  rule_id: string
  layer: Layer
  severity: Severity
  title: string
}

export interface Timeline {
  run_id: string
  alert_count: number
  layers: Layer[]
  rollup?: Alert | null
  entries: TimelineEntry[]
}

export interface CorrelationResponse {
  run_id: string
  criteria_met: boolean
  rollup?: Alert
  score?: number
  reason?: string
}

// --- Member 2: response, recovery, supply chain, policy ---

export type ResponseMode = 'dry_run' | 'simulated' | 'live'
export type ActionStatus = 'planned' | 'succeeded' | 'failed' | 'rejected'

export interface Incident extends Alert {
  child_count: number
  layers: Layer[]
  action_counts: Record<string, number>
  recovery_status: string | null
}

export interface ResponseAction {
  id: string
  alert_id: string
  trigger_alert_id: string
  run_id: string
  rule_id: string | null
  action: string
  target: string
  mode: ResponseMode
  status: ActionStatus
  attempts: number
  reason: string
  result: Record<string, any>
  error: string | null
  requested_by: string
  simulated: boolean
  duplicate: boolean
  created_at: string
  updated_at: string
}

export interface PlannedAction {
  action: string
  target: string
  trigger_alert_id: string
  rule_id: string | null
  reason: string
}

export interface Containment {
  id: string
  kind: string
  target: string
  state: string
  simulated: boolean
  incident_id: string
  updated_at: string
}

export interface RecoveryStep {
  name: string
  status: 'ok' | 'failed' | 'manual' | 'skipped'
  detail: string
  at: string
}

export interface RecoveryRun {
  id: string
  incident_id: string
  plan: string
  target: string
  mode: string
  simulated: boolean
  status: 'running' | 'succeeded' | 'failed' | 'manual_required' | 'blocked'
  steps: RecoveryStep[]
  error: string | null
  created_at: string
  finished_at: string | null
}

export interface RecoveryPlan {
  incident_id: string
  ready: boolean
  blocked_by: string[]
  plans: { plan: string; kind: string; target: string; state: string; description: string }[]
}

export interface IncidentDetail {
  incident: Alert
  children: Alert[]
  planned_actions: PlannedAction[]
  actions: ResponseAction[]
  containments: Containment[]
  recovery_runs: RecoveryRun[]
  recovery_plan: RecoveryPlan
}

export interface RespondResult {
  alert_id: string
  mode: ResponseMode
  outcome: 'no_action' | 'planned' | 'contained' | 'incomplete' | 'rejected'
  detail: string | null
  actions: ResponseAction[]
}

export interface SupplyChainResult {
  id: string
  kind: 'sbom' | 'signature'
  subject: string
  status: string
  tool: string
  tool_version: string | null
  summary: Record<string, any>
  run_id: string | null
  event_ids: string[]
  has_document: boolean
  created_at: string
}

export interface PolicyViolation {
  rule_id: string
  severity: Severity
  resource: string
  message: string
}

export interface PolicyResult {
  id: string
  target: string
  target_kind: 'kubernetes' | 'workflow'
  engine: string
  allowed: boolean
  violations: PolicyViolation[]
  run_id: string | null
  alert_ids: string[]
  evaluation_only: boolean
  created_at: string
}

export interface PolicySample {
  kind: 'kubernetes' | 'workflow'
  path: string
  name: string
}

export interface DefenceStatus {
  response: {
    default_mode: ResponseMode
    min_score: number
    live_enabled: boolean
    live_actions: string[]
    live_token_configured: boolean
    github_configured: boolean
  }
  recovery: { mode: string; identity_provider: string }
  supply_chain: { cosign: string | null; cosign_public_key: boolean; cyclonedx: string | null }
  policy: { opa: string | null; allowed_registries: string[]; enforcement: string }
}

export const SCENARIO_DEFS: Record<string, {
  name: string
  description: string
  layer: Layer | 'multi'
  rules: string[]
  severity: Severity
}> = {
  '01': {
    name: 'Poisoned Pipeline',
    description: 'Detects pull_request_target workflows that check out untrusted PR code',
    layer: 'static',
    rules: ['PPE-001', 'INJ-001', 'PERM-001', 'SEC-003', 'PIN-001'],
    severity: 'critical',
  },
  '02': {
    name: 'Secret Exfiltration',
    description: 'Detects workflows that expose secrets to external hosts',
    layer: 'static',
    rules: ['SEC-001', 'SEC-002'],
    severity: 'critical',
  },
  '03': {
    name: 'Dependency Typosquatting',
    description: 'Detects malicious package names and suspicious package sources',
    layer: 'static',
    rules: ['DEP-001', 'DEP-002', 'DEP-004'],
    severity: 'high',
  },
  '04': {
    name: 'Unsigned/Tampered Image',
    description: 'Detects container images without valid signatures or with mismatched digests',
    layer: 'static',
    rules: ['IMG-001', 'IMG-002', 'IMG-003'],
    severity: 'high',
  },
  '05': {
    name: 'Anomalous Run Behaviour',
    description: 'Detects pipeline runs with unusual metrics: duration drift, new domains, sensitive files',
    layer: 'behaviour',
    rules: ['BEH-001'],
    severity: 'high',
  },
  '06': {
    name: 'Runtime Compromise',
    description: 'Detects reverse shells and cryptocurrency miners in runner containers',
    layer: 'runtime',
    rules: ['RT-SHELL', 'RT-MINER'],
    severity: 'critical',
  },
  '07': {
    name: 'Correlated Multi-Layer',
    description: 'Multi-layer incident: static PPE + behaviour anomaly + runtime shell',
    layer: 'multi',
    rules: ['PPE-001', 'BEH-001', 'RT-SHELL', 'correlation'],
    severity: 'critical',
  },
}
