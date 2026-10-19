import axios, { AxiosInstance } from 'axios'
import { Alert, HealthCheck, Timeline, EventStatus, CorrelationResponse } from './types'

const API_BASE = import.meta.env.VITE_API_URL || 'http://localhost:8000'

const client: AxiosInstance = axios.create({
  baseURL: API_BASE,
  timeout: 10000,
})

export const api = {
  health: async (): Promise<HealthCheck> => {
    const res = await client.get('/health')
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
  },

  events: {
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
      event_ids: string[]
      status: string
      run_id?: string
      detail?: string
    }> => {
      // Call attack-lab/run.py via the local event endpoint
      const res = await client.post('/events', {
        kind: 'workflow',
        run_id: `scenario-${scenarioId}-${Date.now()}`,
        workflow: `scenario-${scenarioId}`,
        attack_id: scenarioId,
        payload: { scenario_id: scenarioId },
      })
      return res.data
    },
  },
}

export const withErrorHandling = async <T,>(
  fn: () => Promise<T>,
  onError?: (error: Error) => void
): Promise<T | null> => {
  try {
    return await fn()
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Unknown error'
    console.error(message)
    onError?.(error instanceof Error ? error : new Error(message))
    return null
  }
}
