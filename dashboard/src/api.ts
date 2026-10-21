import axios, { AxiosError, AxiosInstance } from 'axios'
import {
  Alert, HealthCheck, Timeline, EventStatus, CorrelationResponse, Incident, IncidentDetail, RespondResult,
  ResponseAction, ResponseMode, RecoveryRun, RecoveryPlan, Containment, SupplyChainResult, PolicyResult,
  PolicySample, DefenceStatus,
} from './types'

const API_BASE = import.meta.env.VITE_API_URL || 'http://localhost:8000'

const client: AxiosInstance = axios.create({
  baseURL: API_BASE,
  timeout: 10000,
})

/** Human-readable message for an API failure, distinguishing an unreachable backend from an error reply. */
export const describeError = (error: unknown): string => {
  if (axios.isAxiosError(error)) {
    const err = error as AxiosError<{ detail?: unknown }>
    if (!err.response) return `API unreachable at ${API_BASE} — is the backend running?`
    const detail = err.response.data?.detail
    const text = typeof detail === 'string' ? detail : detail ? JSON.stringify(detail) : err.message
    return `${err.response.status}: ${text}`
  }
  return error instanceof Error ? error.message : 'Unknown error'
}

export const api = {
  health: async (): Promise<HealthCheck> => {
    const res = await client.get('/health', { validateStatus: s => s === 200 || s === 503 })
    return res.data
  },

  alerts: {
    list: async (filters?: {
      run_id?: string
      layer?: string
      severity?: string
      status?: string
      attack_id?: string
      limit?: number
      offset?: number
    }): Promise<Alert[]> => {
      const res = await client.get('/alerts', { params: filters })
      return res.data
    },

    get: async (alertId: string): Promise<Alert> => {
      const res = await client.get(`/alerts/${alertId}`)
      return res.data
    },

    respond: async (alertId: string, mode: ResponseMode): Promise<RespondResult> => {
      // 403 carries the audited rejection, so it is returned rather than thrown
      const res = await client.post(`/alerts/${alertId}/respond`, { mode },
        { validateStatus: s => s === 200 || s === 403 })
      return res.data
    },
  },

  events: {
    list: async (filters?: { run_id?: string; kind?: string; status?: string; limit?: number }): Promise<EventStatus[]> => {
      const res = await client.get('/events', { params: filters })
      return res.data
    },

    status: async (eventId: string): Promise<EventStatus> => {
      const res = await client.get(`/events/${eventId}`)
      return res.data
    },

    local: async (payload: {
      kind: string
      run_id?: string
      workflow?: string
      attack_id?: string
      payload: Record<string, any>
    }): Promise<{
      event_ids: string[]
      status: string
      run_id?: string
      status_urls?: string[]
    }> => {
      const res = await client.post('/events', payload)
      return res.data
    },
  },

  runs: {
    timeline: async (runId: string): Promise<Timeline> => {
      const res = await client.get(`/runs/${runId}/timeline`)
      return res.data
    },

    correlate: async (runId: string): Promise<CorrelationResponse> => {
      const res = await client.post(`/runs/${runId}/correlate`)
      return res.data
    },
  },

  scenarios: {
    run: async (scenarioId: string): Promise<{
      run_id: string
      name: string
      event_ids: string[]
      status: string
    }> => {
      // Server-side runner: sends the same steps as `python attack-lab/run.py <id>`
      const res = await client.post(`/attack-lab/${scenarioId}/run`, undefined, { timeout: 60000 })
      return res.data
    },
  },

  incidents: {
    list: async (filters?: { status?: string; severity?: string; limit?: number }): Promise<Incident[]> => {
      const res = await client.get('/incidents', { params: filters })
      return res.data
    },

    get: async (incidentId: string): Promise<IncidentDetail> => {
      const res = await client.get(`/incidents/${incidentId}`)
      return res.data
    },

    recoveryPlan: async (incidentId: string): Promise<RecoveryPlan> => {
      const res = await client.get(`/incidents/${incidentId}/recovery-plan`)
      return res.data
    },

    recover: async (incidentId: string, plans?: string[]): Promise<{ outcome: string; runs: RecoveryRun[] }> => {
      const res = await client.post(`/incidents/${incidentId}/recover`, { plans })
      return res.data
    },
  },

  responses: {
    list: async (filters?: { alert_id?: string; mode?: string; status?: string; action?: string; limit?: number }): Promise<ResponseAction[]> => {
      const res = await client.get('/responses', { params: filters })
      return res.data
    },

    containments: async (): Promise<Containment[]> => {
      const res = await client.get('/containments')
      return res.data
    },
  },

  recovery: {
    list: async (filters?: { incident_id?: string; status?: string }): Promise<RecoveryRun[]> => {
      const res = await client.get('/recovery', { params: filters })
      return res.data
    },
  },

  supplyChain: {
    results: async (filters?: { kind?: string; status?: string }): Promise<SupplyChainResult[]> => {
      const res = await client.get('/supply-chain/results', { params: filters })
      return res.data
    },

    verify: async (image: string): Promise<SupplyChainResult> => {
      const res = await client.post('/supply-chain/verify', { image }, { timeout: 90000 })
      return res.data
    },

    sbom: async (body: { path?: string; environment?: boolean }): Promise<SupplyChainResult> => {
      const res = await client.post('/supply-chain/sbom', body, { timeout: 120000 })
      return res.data
    },

    sbomUrl: (resultId: string) => `${API_BASE}/supply-chain/results/${resultId}/sbom`,
  },

  policy: {
    samples: async (): Promise<PolicySample[]> => {
      const res = await client.get('/policy/samples')
      return res.data
    },

    evaluate: async (body: { kind: string; path?: string; content?: string; filename?: string }): Promise<PolicyResult> => {
      const res = await client.post('/policy/evaluate', body, { timeout: 60000 })
      return res.data
    },

    results: async (filters?: { allowed?: boolean; target_kind?: string }): Promise<PolicyResult[]> => {
      const res = await client.get('/policy/results', { params: filters })
      return res.data
    },
  },

  defenceStatus: async (): Promise<DefenceStatus> => {
    const res = await client.get('/defence/status')
    return res.data
  },
}

export const withErrorHandling = async <T,>(
  fn: () => Promise<T>,
  onError?: (error: Error) => void
): Promise<T | null> => {
  try {
    return await fn()
  } catch (error) {
    const message = describeError(error)
    console.error(message)
    onError?.(new Error(message))
    return null
  }
}
