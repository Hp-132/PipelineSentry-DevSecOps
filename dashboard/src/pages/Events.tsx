import { useState } from 'react'
import { AlertCircle, Search } from 'lucide-react'
import { api } from '@/api'
import { EventStatus } from '@/types'
import { DataView, StatusPill, formatTime, useAsync } from '@/components/DataState'

export const Events: React.FC = () => {
  const [runId, setRunId] = useState('')
  const [query, setQuery] = useState('')
  const events = useAsync(() => api.events.list({ run_id: query || undefined, limit: 200 }), [query])

  return (
    <div className="space-y-6">
      <form className="glass p-5 flex flex-wrap gap-3 items-end" onSubmit={e => { e.preventDefault(); setQuery(runId.trim()) }}>
        <div className="flex-1 min-w-[16rem]">
          <label className="text-xs text-slate-400 uppercase tracking-widest font-semibold mb-2 block">Run ID</label>
          <div className="relative">
            <Search size={16} className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" />
            <input value={runId} onChange={e => setRunId(e.target.value)} placeholder="exact run id (empty for latest)"
              className="w-full pl-9 pr-4 py-2.5 bg-white/5 border border-white/20 rounded-lg text-sm text-slate-300 placeholder:text-slate-500 focus:outline-none focus:ring-2 focus:ring-accent-blue/50" />
          </div>
        </div>
        <button type="submit" className="btn-primary">Filter</button>
        <button type="button" onClick={events.reload} className="btn-secondary">Refresh</button>
      </form>

      <DataView state={events} empty={{
        icon: <AlertCircle className="w-12 h-12 text-accent-blue/30" />,
        title: 'No events',
        description: query ? `No events stored for run ${query}.` : 'Events appear here once webhooks, scans or attack scenarios are submitted.',
      }}>
        {(list: EventStatus[]) => (
          <div className="glass rounded-2xl overflow-x-auto">
            <table className="w-full text-sm">
              <thead className="text-xs text-slate-400 uppercase tracking-widest">
                <tr className="border-b border-white/10">
                  {['Received', 'Kind', 'Source', 'Status', 'Alerts', 'Attempts', 'Run', 'Workflow'].map(h =>
                    <th key={h} className="text-left font-semibold px-4 py-3">{h}</th>)}
                </tr>
              </thead>
              <tbody className="divide-y divide-white/5">
                {list.map(e => (
                  <tr key={e.event_id} className="hover:bg-white/5 align-top">
                    <td className="px-4 py-3 text-xs text-slate-500 whitespace-nowrap">{formatTime(e.received_at)}</td>
                    <td className="px-4 py-3 font-mono text-slate-200">{e.kind}</td>
                    <td className="px-4 py-3 text-slate-400">{e.source}</td>
                    <td className="px-4 py-3">
                      <StatusPill status={e.status} />
                      {e.error && <p className="text-xs text-red-300 mt-1 max-w-[18rem]">{e.error}</p>}
                    </td>
                    <td className="px-4 py-3 tabular-nums text-slate-300">{e.alert_ids.length}</td>
                    <td className="px-4 py-3 tabular-nums text-slate-400">{e.attempts}</td>
                    <td className="px-4 py-3 text-xs font-mono">
                      <button type="button" className="text-accent-cyan hover:underline" onClick={() => { setRunId(e.run_id); setQuery(e.run_id) }}>
                        {e.run_id}
                      </button>
                    </td>
                    <td className="px-4 py-3 text-xs text-slate-400 max-w-[14rem] truncate" title={e.workflow}>{e.workflow}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </DataView>
    </div>
  )
}
