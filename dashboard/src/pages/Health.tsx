import { useEffect, useState } from 'react'
import { HealthCheck } from '@/types'
import { api } from '@/api'
import { StatusIndicator } from '@/components/StatusIndicator'
import { LoadingSkeleton } from '@/components/LoadingSkeleton'
import { Server } from 'lucide-react'

export const Health: React.FC = () => {
  const [health, setHealth] = useState<HealthCheck | null>(null)
  const [loading, setLoading] = useState(true)

  const refresh = async () => {
    setLoading(true)
    const data = await api.health().catch(console.error)
    setHealth(data || null)
    setLoading(false)
  }

  useEffect(() => {
    refresh()
    const interval = setInterval(refresh, 10000)
    return () => clearInterval(interval)
  }, [])

  return (
    <div className="space-y-6">
      <div className="card p-6 flex items-start justify-between">
        <div>
          <h2 className="text-lg font-semibold text-slate-300 mb-2">System Health</h2>
          <p className="text-sm text-slate-400">Real-time status of backend services</p>
        </div>
        <Server size={24} className="text-accent-blue/50" />
      </div>

      {loading ? (
        <div className="card p-6">
          <LoadingSkeleton count={4} />
        </div>
      ) : health ? (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div className="card p-6">
            <StatusIndicator
              status={health.status === 'ok' ? 'healthy' : health.status === 'degraded' ? 'degraded' : 'unhealthy'}
              label={`Overall: ${health.status.toUpperCase()}`}
            />
            <p className="text-xs text-slate-400 mt-4">
              {health.status === 'ok' && 'All systems operational'}
              {health.status === 'degraded' && 'Some services degraded but API functional'}
              {health.status === 'unhealthy' && 'Critical services unavailable'}
            </p>
          </div>

          {Object.entries(health.checks).map(([service, status]) => (
            <div key={service} className="card p-6">
              <div className="flex items-center justify-between mb-2">
                <p className="text-sm font-semibold text-slate-300 capitalize">{service}</p>
                <StatusIndicator
                  status={status === 'ok' ? 'healthy' : 'unhealthy'}
                  label={status}
                />
              </div>
              <p className="text-xs text-slate-400 font-mono">{status}</p>
            </div>
          ))}
        </div>
      ) : null}

      {health?.queues && (
        <div className="card p-6">
          <h3 className="text-sm font-semibold text-slate-300 mb-4">Message Queues</h3>
          <div className="grid grid-cols-2 gap-4">
            {Object.entries(health.queues).map(([queue, count]) => (
              <div key={queue} className="p-3 bg-navy-800/50 rounded-lg">
                <p className="text-xs text-slate-400 uppercase tracking-wider">{queue}</p>
                <p className="text-lg font-mono text-accent-blue mt-2">{count}</p>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}
