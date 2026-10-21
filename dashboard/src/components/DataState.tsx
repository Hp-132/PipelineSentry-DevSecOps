import { DependencyList, ReactNode, useCallback, useEffect, useState } from 'react'
import { AlertTriangle, RefreshCw, WifiOff } from 'lucide-react'
import { describeError } from '@/api'
import { LoadingSkeleton } from './LoadingSkeleton'
import { EmptyState } from './EmptyState'

export interface AsyncState<T> {
  data: T | null
  error: string | null
  loading: boolean
  reload: () => void
}

/** Loads data from the API; keeps the last good data visible while reloading. */
export function useAsync<T>(fn: () => Promise<T>, deps: DependencyList = []): AsyncState<T> {
  const [data, setData] = useState<T | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(true)
  const [tick, setTick] = useState(0)

  useEffect(() => {
    let cancelled = false
    setLoading(true)
    fn()
      .then(result => { if (!cancelled) { setData(result); setError(null) } })
      .catch(err => { if (!cancelled) setError(describeError(err)) })
      .finally(() => { if (!cancelled) setLoading(false) })
    return () => { cancelled = true }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [...deps, tick])

  const reload = useCallback(() => setTick(t => t + 1), [])
  return { data, error, loading, reload }
}

export const ErrorState: React.FC<{ message: string; onRetry?: () => void }> = ({ message, onRetry }) => {
  const unreachable = message.startsWith('API unreachable')
  const Icon = unreachable ? WifiOff : AlertTriangle
  return (
    <div className="glass p-6 rounded-2xl border-l-4 border-red-500/60 flex items-start gap-4">
      <Icon className="text-red-400 shrink-0 mt-0.5" size={20} />
      <div className="flex-1 min-w-0">
        <p className="text-slate-200 font-semibold">{unreachable ? 'Service unavailable' : 'Request failed'}</p>
        <p className="text-sm text-slate-400 mt-1 break-words">{message}</p>
      </div>
      {onRetry && (
        <button onClick={onRetry} className="btn-secondary flex items-center gap-2 shrink-0">
          <RefreshCw size={14} /> Retry
        </button>
      )}
    </div>
  )
}

/** Standard loading / error / empty / content switch for a list loaded with useAsync. */
export function DataView<T>({ state, empty, children, isEmpty }: {
  state: AsyncState<T>
  empty: { title: string; description: string; icon?: ReactNode }
  isEmpty?: (data: T) => boolean
  children: (data: T) => ReactNode
}) {
  if (state.error && state.data === null) return <ErrorState message={state.error} onRetry={state.reload} />
  if (state.loading && state.data === null) {
    return <div className="glass p-6 rounded-2xl"><LoadingSkeleton count={4} /></div>
  }
  const data = state.data as T
  const blank = isEmpty ? isEmpty(data) : Array.isArray(data) && data.length === 0
  return (
    <>
      {state.error && <div className="mb-4"><ErrorState message={state.error} onRetry={state.reload} /></div>}
      {blank ? <div className="glass p-10 rounded-2xl"><EmptyState {...empty} /></div> : children(data)}
    </>
  )
}

const MODE_STYLES: Record<string, string> = {
  dry_run: 'bg-slate-500/15 text-slate-300 border-slate-400/30',
  simulated: 'bg-amber-500/15 text-amber-300 border-amber-400/40',
  live: 'bg-red-500/15 text-red-300 border-red-400/50',
}
const MODE_LABELS: Record<string, string> = { dry_run: 'DRY RUN', simulated: 'SIMULATED', live: 'LIVE' }

/** Makes it impossible to mistake a simulated or planned action for a real one. */
export const ModeBadge: React.FC<{ mode: string }> = ({ mode }) => (
  <span className={`text-[10px] font-bold tracking-widest px-2 py-0.5 rounded border ${MODE_STYLES[mode] || MODE_STYLES.dry_run}`}>
    {MODE_LABELS[mode] || mode.toUpperCase()}
  </span>
)

const STATUS_STYLES: Record<string, string> = {
  succeeded: 'text-green-300 bg-green-500/10 border-green-500/30',
  verified: 'text-green-300 bg-green-500/10 border-green-500/30',
  generated: 'text-green-300 bg-green-500/10 border-green-500/30',
  allowed: 'text-green-300 bg-green-500/10 border-green-500/30',
  handled: 'text-green-300 bg-green-500/10 border-green-500/30',
  restored: 'text-green-300 bg-green-500/10 border-green-500/30',
  released: 'text-green-300 bg-green-500/10 border-green-500/30',
  rotated: 'text-green-300 bg-green-500/10 border-green-500/30',
  done: 'text-green-300 bg-green-500/10 border-green-500/30',
  ok: 'text-green-300 bg-green-500/10 border-green-500/30',
  planned: 'text-sky-300 bg-sky-500/10 border-sky-500/30',
  new: 'text-sky-300 bg-sky-500/10 border-sky-500/30',
  queued: 'text-sky-300 bg-sky-500/10 border-sky-500/30',
  processing: 'text-sky-300 bg-sky-500/10 border-sky-500/30',
  manual_required: 'text-amber-300 bg-amber-500/10 border-amber-500/30',
  manual: 'text-amber-300 bg-amber-500/10 border-amber-500/30',
  blocked: 'text-amber-300 bg-amber-500/10 border-amber-500/30',
  unsupported: 'text-amber-300 bg-amber-500/10 border-amber-500/30',
  tool_unavailable: 'text-amber-300 bg-amber-500/10 border-amber-500/30',
  skipped: 'text-slate-400 bg-white/5 border-white/10',
}

export const StatusPill: React.FC<{ status: string }> = ({ status }) => (
  <span className={`text-xs font-semibold px-2 py-0.5 rounded-md border whitespace-nowrap ${
    STATUS_STYLES[status] || 'text-red-300 bg-red-500/10 border-red-500/30'}`}>
    {status.replace(/_/g, ' ')}
  </span>
)

export const SectionTitle: React.FC<{ children: ReactNode; aside?: ReactNode }> = ({ children, aside }) => (
  <div className="flex items-center justify-between gap-3 mb-3">
    <h3 className="text-xs text-slate-400 uppercase tracking-widest font-semibold">{children}</h3>
    {aside}
  </div>
)

export const formatTime = (iso: string | null | undefined) =>
  iso ? `${new Date(iso).toLocaleDateString()} ${new Date(iso).toLocaleTimeString()}` : '—'
