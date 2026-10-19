import { useEffect, useState } from 'react'
import { Alert, HealthCheck } from '@/types'
import { api } from '@/api'
import { MetricCard } from '@/components/MetricCard'
import { SeverityBadge } from '@/components/SeverityBadge'
import { LoadingGrid, LoadingSkeleton } from '@/components/LoadingSkeleton'
import { EmptyState } from '@/components/EmptyState'
import { AlertCircle, Zap, Shield } from 'lucide-react'

export const Overview: React.FC = () => {
  const [alerts, setAlerts] = useState<Alert[]>([])
  const [health, setHealth] = useState<HealthCheck | null>(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    const load = async () => {
      setLoading(true)
      const [h, a] = await Promise.all([
        api.health().catch(console.error),
        api.alerts.list({ limit: 100 }).catch(console.error),
      ])
      setHealth(h || null)
      setAlerts(a || [])
      setLoading(false)
    }
    load()
  }, [])

  const critical = alerts.filter(a => a.severity === 'critical').length
  const high = alerts.filter(a => a.severity === 'high').length
  const beh = alerts.filter(a => a.layer === 'behaviour').length
  const corr = alerts.filter(a => a.layer === 'correlation').length

  return (
    <div className="space-y-6">
      {/* Metrics Grid */}
      {loading ? (
        <LoadingGrid />
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-5">
          <MetricCard title="Total Alerts" value={alerts.length} icon={<AlertCircle className="text-accent-blue" />} />
          <MetricCard
            title="Critical"
            value={critical}
            subtitle="Immediate action required"
            icon={<Zap className="text-severity-critical" />}
          />
          <MetricCard
            title="High Severity"
            value={high}
            subtitle="Review recommended"
            icon={<AlertCircle className="text-severity-high" />}
          />
          <MetricCard
            title="Advanced Detection"
            value={beh + corr}
            subtitle={`${beh} behaviour, ${corr} correlated`}
            icon={<Shield className="text-accent-cyan" />}
          />
        </div>
      )}

      {/* Recent Alerts */}
      <div className="glass p-6 rounded-2xl">
        <div className="flex items-center gap-3 mb-5">
          <div className="p-2 bg-gradient-to-br from-accent-blue to-accent-cyan rounded-lg">
            <AlertCircle size={20} className="text-white" />
          </div>
          <div>
            <h2 className="text-lg font-bold text-slate-200">Recent Alerts</h2>
            <p className="text-xs text-slate-400">Last 10 detected incidents</p>
          </div>
        </div>

        {loading ? (
          <LoadingSkeleton count={3} />
        ) : alerts.length === 0 ? (
          <EmptyState
            title="No alerts yet"
            description="Run an attack scenario to see alerts and detection results"
            icon={<AlertCircle className="w-12 h-12 text-accent-blue/30" />}
          />
        ) : (
          <div className="space-y-2">
            {alerts.slice(0, 10).map((alert, idx) => (
              <div
                key={alert.id}
                className="flex items-center justify-between p-4 bg-white/5 hover:bg-white/10 rounded-lg border border-white/10 transition-all duration-300 group cursor-pointer alert-row"
                style={{ animationDelay: `${idx * 50}ms` }}
              >
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 mb-1.5 flex-wrap">
                    <SeverityBadge severity={alert.severity} size="sm" />
                    <span className="text-xs font-mono bg-accent-blue/20 text-accent-blue px-2.5 py-1 rounded border border-accent-blue/30">
                      {alert.evidence.rule_id || 'unknown'}
                    </span>
                  </div>
                  <p className="text-sm text-slate-200 group-hover:text-white transition-colors truncate font-medium">{alert.title}</p>
                </div>
                <span className="text-xs text-slate-400 ml-4 flex-shrink-0 whitespace-nowrap">
                  {new Date(alert.timestamp).toLocaleDateString()}
                </span>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Health Status */}
      {health && (
        <div className="glass p-6 rounded-2xl">
          <div className="flex items-center gap-3 mb-5">
            <div className="p-2 bg-gradient-to-br from-green-400 to-green-500 rounded-lg">
              <Shield size={20} className="text-white" />
            </div>
            <div>
              <h2 className="text-lg font-bold text-slate-200">System Health</h2>
              <p className="text-xs text-slate-400">
                Overall Status: <span className="text-green-400 font-semibold">Healthy</span>
              </p>
            </div>
          </div>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            {Object.entries(health.checks).map(([service, status]) => (
              <div key={service} className="p-4 bg-white/5 border border-white/10 rounded-lg hover:border-white/20 hover:bg-white/10 transition-all duration-300 group">
                <p className="text-xs text-slate-400 uppercase tracking-widest font-semibold mb-2">{service}</p>
                <div className="flex items-center gap-2">
                  <div className={`w-2.5 h-2.5 rounded-full ${status === 'ok' ? 'bg-green-400' : 'bg-yellow-400'} shadow-glow-md`} />
                  <p className={`text-sm font-mono font-bold ${status === 'ok' ? 'text-green-400' : 'text-yellow-400'}`}>
                    {status.toUpperCase()}
                  </p>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}
