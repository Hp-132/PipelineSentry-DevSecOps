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
  entries: TimelineEntry[]
}

export interface CorrelationResponse {
  run_id: string
  criteria_met: boolean
  rollup?: Alert
  score?: number
  reason?: string
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
