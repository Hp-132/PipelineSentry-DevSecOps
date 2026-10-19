import { useState } from 'react'
import { RefreshCw } from 'lucide-react'
import { HealthCheck } from '@/types'
import { StatusIndicator } from './StatusIndicator'

interface TopbarProps {
  title: string
  onRefresh?: () => void
  health?: HealthCheck
}

export const Topbar: React.FC<TopbarProps> = ({ title, onRefresh, health }) => {
  const [refreshing, setRefreshing] = useState(false)

  const handleRefresh = async () => {
    setRefreshing(true)
    await onRefresh?.()
    setRefreshing(false)
  }

  return (
    <header className="h-14 bg-navy-800/60 backdrop-blur-xl border-b border-white/10 px-6 flex items-center justify-between shrink-0">
      <div>
        <h1 className="text-lg font-semibold text-slate-100 tracking-tight">{title}</h1>
        <p className="text-[11px] text-slate-500 mt-0.5">Member 1 · Detection &amp; Analysis</p>
      </div>

      <div className="flex items-center gap-3">
        {health && (
          <div className="flex items-center gap-2 px-3 py-1.5 rounded-lg border border-white/10 bg-white/5">
            <StatusIndicator
              status={health.status === 'ok' ? 'healthy' : health.status === 'degraded' ? 'degraded' : 'unhealthy'}
              label={health.status.toUpperCase()}
            />
          </div>
        )}

        <button
          onClick={handleRefresh}
          disabled={refreshing}
          className={`p-2 rounded-lg border border-white/10 transition-colors ${
            refreshing
              ? 'animate-spin bg-white/5 text-accent-blue'
              : 'bg-white/5 hover:bg-white/10 text-slate-400 hover:text-slate-200'
          }`}
          title="Refresh data"
        >
          <RefreshCw size={20} />
        </button>
      </div>
    </header>
  )
}
