import { useState } from 'react'
import { ShieldAlert } from 'lucide-react'
import { api } from '@/api'
import { DefenceStatus, ResponseAction } from '@/types'
import { DataView, ModeBadge, StatusPill, formatTime, useAsync } from '@/components/DataState'
import { MetricCard } from '@/components/MetricCard'

const select = 'px-4 py-2.5 bg-white/5 border border-white/20 rounded-lg text-sm text-slate-300 focus:outline-none focus:ring-2 focus:ring-accent-blue/50'

export const Response: React.FC = () => {
  const [mode, setMode] = useState('')
  const [status, setStatus] = useState('')
  const actions = useAsync(() => api.responses.list({ mode: mode || undefined, status: status || undefined, limit: 300 }), [mode, status])
  const defence = useAsync<DefenceStatus>(() => api.defenceStatus())
  const list = actions.data || []
  const count = (pred: (a: ResponseAction) => boolean) => list.filter(pred).length

  return (
    <div className="space-y-6">
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <MetricCard title="Default mode" value={defence.data ? defence.data.response.default_mode.replace('_', ' ') : '—'}
          subtitle="RESPONSE_MODE used by the responder service" />
        <MetricCard title="Live actions" value={defence.data ? (defence.data.response.live_enabled ? 'enabled' : 'disabled') : '—'}
          subtitle={defence.data?.response.live_enabled ? `allowed: ${defence.data.response.live_actions.join(', ')}` : 'RESPONSE_LIVE_ENABLED=false'} />
        <MetricCard title="Simulated / live succeeded" value={`${count(a => a.mode === 'simulated' && a.status === 'succeeded')} / ${count(a => a.mode === 'live' && a.status === 'succeeded')}`}
          subtitle="in the current filter" />
        <MetricCard title="Failed / rejected" value={`${count(a => a.status === 'failed')} / ${count(a => a.status === 'rejected')}`}
          subtitle="in the current filter" />
      </div>

      <div className="glass p-5 flex flex-wrap gap-4 items-end">
        <div>
          <label className="text-xs text-slate-400 uppercase tracking-widest font-semibold mb-2 block">Mode</label>
          <select value={mode} onChange={e => setMode(e.target.value)} className={select}>
            <option value="">All</option>
            <option value="dry_run">Dry run (planned only)</option>
            <option value="simulated">Simulated</option>
            <option value="live">Live</option>
          </select>
        </div>
        <div>
          <label className="text-xs text-slate-400 uppercase tracking-widest font-semibold mb-2 block">Status</label>
          <select value={status} onChange={e => setStatus(e.target.value)} className={select}>
            <option value="">All</option>
            <option value="planned">Planned</option>
            <option value="succeeded">Succeeded</option>
            <option value="failed">Failed</option>
            <option value="rejected">Rejected</option>
          </select>
        </div>
        <button onClick={actions.reload} className="btn-secondary ml-auto">Refresh</button>
      </div>

      <DataView state={actions} empty={{
        icon: <ShieldAlert className="w-12 h-12 text-accent-blue/30" />,
        title: 'No response actions',
        description: 'The responder records actions for new correlated incidents, or trigger one from the Incidents page.',
      }}>
        {(rows: ResponseAction[]) => (
          <div className="glass rounded-2xl overflow-x-auto">
            <table className="w-full text-sm">
              <thead className="text-xs text-slate-400 uppercase tracking-widest">
                <tr className="border-b border-white/10">
                  {['Mode', 'Action', 'Target', 'Status', 'Attempts', 'Outcome', 'Run', 'Updated'].map(h =>
                    <th key={h} className="text-left font-semibold px-4 py-3">{h}</th>)}
                </tr>
              </thead>
              <tbody className="divide-y divide-white/5">
                {rows.map(a => (
                  <tr key={a.id} className="hover:bg-white/5 align-top">
                    <td className="px-4 py-3"><ModeBadge mode={a.mode} /></td>
                    <td className="px-4 py-3 font-mono text-slate-200">{a.action}</td>
                    <td className="px-4 py-3 text-slate-300 max-w-[14rem] truncate" title={a.target}>{a.target}</td>
                    <td className="px-4 py-3"><StatusPill status={a.status} /></td>
                    <td className="px-4 py-3 text-slate-400 tabular-nums">{a.attempts}</td>
                    <td className="px-4 py-3 text-xs text-slate-400 max-w-[22rem]">{a.error || a.result.effect}</td>
                    <td className="px-4 py-3 text-xs font-mono text-slate-500 max-w-[10rem] truncate" title={a.run_id}>{a.run_id}</td>
                    <td className="px-4 py-3 text-xs text-slate-500 whitespace-nowrap">{formatTime(a.updated_at)}</td>
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
