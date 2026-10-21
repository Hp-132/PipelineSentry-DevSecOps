import { useState } from 'react'
import { GitBranch, Play, ShieldCheck, RotateCcw, ListChecks } from 'lucide-react'
import { api, describeError } from '@/api'
import { Incident, IncidentDetail, ResponseMode } from '@/types'
import { SeverityBadge } from '@/components/SeverityBadge'
import { useToast } from '@/components/Toast'
import { DataView, ErrorState, ModeBadge, SectionTitle, StatusPill, formatTime, useAsync } from '@/components/DataState'
import { LoadingSkeleton } from '@/components/LoadingSkeleton'

export const Incidents: React.FC = () => {
  const [statusFilter, setStatusFilter] = useState('')
  const [selected, setSelected] = useState<string | null>(null)
  const incidents = useAsync(() => api.incidents.list({ status: statusFilter || undefined, limit: 100 }), [statusFilter])

  return (
    <div className="space-y-6">
      <div className="glass p-5 flex flex-wrap items-end gap-4">
        <div>
          <label className="text-xs text-slate-400 uppercase tracking-widest font-semibold mb-2 block">Status</label>
          <select
            value={statusFilter}
            onChange={e => setStatusFilter(e.target.value)}
            className="px-4 py-2.5 bg-white/5 border border-white/20 rounded-lg text-sm text-slate-300 focus:outline-none focus:ring-2 focus:ring-accent-blue/50"
          >
            <option value="">All</option>
            <option value="new">New (not contained)</option>
            <option value="handled">Handled (contained)</option>
          </select>
        </div>
        <p className="text-sm text-slate-400 flex-1 min-w-[16rem]">
          Incidents are Member 1's correlation roll-ups. Response actions and recovery runs are stored against them.
        </p>
        <button onClick={incidents.reload} className="btn-secondary">Refresh</button>
      </div>

      <div className="grid grid-cols-1 xl:grid-cols-5 gap-6">
        <div className="xl:col-span-2">
          <DataView
            state={incidents}
            empty={{
              icon: <GitBranch className="w-12 h-12 text-accent-blue/30" />,
              title: 'No correlated incidents',
              description: 'Run attack scenario 07 (or any scenario that crosses the correlation threshold) to create one.',
            }}
          >
            {(list: Incident[]) => (
              <div className="glass rounded-2xl divide-y divide-white/5 overflow-hidden">
                {list.map(inc => (
                  <button
                    key={inc.id}
                    onClick={() => setSelected(inc.id)}
                    className={`w-full text-left p-4 transition-colors ${selected === inc.id ? 'bg-accent-blue/10' : 'hover:bg-white/5'}`}
                  >
                    <div className="flex items-center gap-2 flex-wrap mb-2">
                      <SeverityBadge severity={inc.severity} size="sm" />
                      <span className="text-xs font-mono text-accent-cyan">score {inc.risk_score}</span>
                      <StatusPill status={inc.status} />
                      {inc.recovery_status && <StatusPill status={inc.recovery_status} />}
                    </div>
                    <p className="text-sm text-slate-200 font-medium">{inc.title}</p>
                    <p className="text-xs text-slate-500 mt-1 font-mono truncate">run {inc.run_id}</p>
                    <p className="text-xs text-slate-500 mt-1">
                      {inc.child_count} alert(s) · {inc.layers.join(', ') || '—'} · {formatTime(inc.timestamp)}
                    </p>
                  </button>
                ))}
              </div>
            )}
          </DataView>
        </div>

        <div className="xl:col-span-3">
          {selected ? (
            <IncidentPanel key={selected} incidentId={selected} onChanged={incidents.reload} />
          ) : (
            <div className="glass p-10 rounded-2xl text-center text-slate-400 text-sm">
              Select an incident to see its alerts, response actions and recovery status.
            </div>
          )}
        </div>
      </div>
    </div>
  )
}

const IncidentPanel: React.FC<{ incidentId: string; onChanged: () => void }> = ({ incidentId, onChanged }) => {
  const toast = useToast()
  const detail = useAsync(() => api.incidents.get(incidentId), [incidentId])
  const [busy, setBusy] = useState<string | null>(null)

  const run = async (label: string, fn: () => Promise<string>) => {
    setBusy(label)
    try {
      toast.success(await fn())
      detail.reload()
      onChanged()
    } catch (err) {
      toast.error(describeError(err))
    } finally {
      setBusy(null)
    }
  }

  const respond = (mode: ResponseMode) => run(mode, async () => {
    const r = await api.alerts.respond(incidentId, mode)
    if (r.outcome === 'rejected') throw new Error(r.detail || 'rejected')
    return `${mode.replace('_', ' ')}: ${r.outcome} (${r.actions.length} action(s))`
  })
  const recover = () => run('recover', async () => {
    const r = await api.incidents.recover(incidentId)
    return `recovery: ${r.outcome.replace('_', ' ')}`
  })

  if (detail.error && !detail.data) return <ErrorState message={detail.error} onRetry={detail.reload} />
  if (!detail.data) return <div className="glass p-6 rounded-2xl"><LoadingSkeleton count={6} /></div>
  const d: IncidentDetail = detail.data
  const reasons: string[] = d.incident.evidence.reasons || []

  return (
    <div className="space-y-5">
      <div className="glass p-6 rounded-2xl border-l-4 border-accent-cyan">
        <div className="flex items-start justify-between gap-4 flex-wrap">
          <div className="min-w-0">
            <div className="flex items-center gap-2 mb-2">
              <SeverityBadge severity={d.incident.severity} />
              <StatusPill status={d.incident.status} />
            </div>
            <h3 className="text-lg font-semibold text-slate-100">{d.incident.title}</h3>
            <p className="text-xs text-slate-500 font-mono mt-1 break-all">{d.incident.id}</p>
          </div>
          <div className="text-right">
            <p className="text-3xl font-semibold text-slate-100 tabular-nums">{d.incident.risk_score}</p>
            <p className="text-xs text-slate-500">risk score</p>
          </div>
        </div>
        {reasons.length > 0 && (
          <ul className="mt-4 space-y-1 text-sm text-slate-400 list-disc list-inside">
            {reasons.map(r => <li key={r}>{r}</li>)}
          </ul>
        )}
        <div className="mt-5 flex flex-wrap gap-2">
          <button disabled={!!busy} onClick={() => respond('dry_run')} className="btn-secondary flex items-center gap-2">
            <ListChecks size={15} /> {busy === 'dry_run' ? 'Planning…' : 'Dry-run response'}
          </button>
          <button disabled={!!busy} onClick={() => respond('simulated')} className="btn-primary flex items-center gap-2">
            <Play size={15} /> {busy === 'simulated' ? 'Running…' : 'Run simulated response'}
          </button>
          <button disabled={!!busy || !d.recovery_plan.ready} onClick={recover} className="btn-secondary flex items-center gap-2"
            title={d.recovery_plan.blocked_by.join('\n') || undefined}>
            <RotateCcw size={15} /> {busy === 'recover' ? 'Recovering…' : 'Run recovery'}
          </button>
        </div>
        <p className="text-xs text-slate-500 mt-3">
          Simulated actions change PipelineSentry's containment records only. Live mode is restricted to the API with a token.
        </p>
      </div>

      <div className="glass p-5 rounded-2xl">
        <SectionTitle>Correlated alerts ({d.children.length})</SectionTitle>
        <div className="space-y-2">
          {d.children.map(c => (
            <div key={c.id} className="flex items-center gap-3 text-sm bg-white/5 rounded-lg px-3 py-2">
              <SeverityBadge severity={c.severity} size="sm" />
              <span className="text-xs uppercase tracking-widest text-slate-400 w-20 shrink-0">{c.layer}</span>
              <code className="text-xs text-accent-cyan w-24 shrink-0">{c.evidence.rule_id}</code>
              <span className="text-slate-300 truncate flex-1">{c.title}</span>
              <StatusPill status={c.status} />
            </div>
          ))}
        </div>
      </div>

      <div className="glass p-5 rounded-2xl">
        <SectionTitle>Response actions</SectionTitle>
        {d.actions.length === 0 ? (
          <div className="text-sm text-slate-400">
            No actions recorded yet.{' '}
            {d.planned_actions.length > 0
              ? `The playbook would take ${d.planned_actions.length} action(s): ${d.planned_actions.map(p => p.action).join(', ')}.`
              : 'The playbook has no automated action for this incident.'}
          </div>
        ) : (
          <div className="space-y-2">
            {d.actions.map(a => (
              <div key={a.id} className="bg-white/5 rounded-lg px-3 py-2 text-sm">
                <div className="flex items-center gap-2 flex-wrap">
                  <ModeBadge mode={a.mode} />
                  <span className="font-mono text-slate-200">{a.action}</span>
                  <span className="text-slate-400 truncate">→ {a.target}</span>
                  <span className="ml-auto"><StatusPill status={a.status} /></span>
                </div>
                <p className="text-xs text-slate-500 mt-1">
                  {a.error || a.result.effect || a.reason} · attempts {a.attempts} · {formatTime(a.updated_at)}
                </p>
              </div>
            ))}
          </div>
        )}
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
        <div className="glass p-5 rounded-2xl">
          <SectionTitle>Containment</SectionTitle>
          {d.containments.length === 0 ? <p className="text-sm text-slate-400">Nothing contained.</p> : (
            <div className="space-y-2">
              {d.containments.map(c => (
                <div key={c.id} className="flex items-center gap-2 text-sm">
                  <ShieldCheck size={14} className="text-slate-500 shrink-0" />
                  <span className="text-slate-400 w-20 shrink-0">{c.kind}</span>
                  <span className="text-slate-300 truncate flex-1" title={c.target}>{c.target}</span>
                  <StatusPill status={c.state} />
                  {c.simulated && <ModeBadge mode="simulated" />}
                </div>
              ))}
            </div>
          )}
        </div>

        <div className="glass p-5 rounded-2xl">
          <SectionTitle>Recovery</SectionTitle>
          {d.recovery_plan.blocked_by.map(b => <p key={b} className="text-xs text-amber-300 mb-2">{b}</p>)}
          {d.recovery_plan.plans.map(p => (
            <p key={p.plan + p.target} className="text-sm text-slate-300 mb-1">
              <span className="font-mono text-accent-cyan">{p.plan}</span> <span className="text-slate-500">→ {p.target}</span>
            </p>
          ))}
          {d.recovery_runs.length > 0 && (
            <div className="mt-3 space-y-2">
              {d.recovery_runs.map(r => (
                <div key={r.id} className="bg-white/5 rounded-lg px-3 py-2 text-xs">
                  <div className="flex items-center gap-2">
                    <span className="font-mono text-slate-200">{r.plan}</span>
                    <span className="ml-auto"><StatusPill status={r.status} /></span>
                  </div>
                  {r.error && <p className="text-slate-400 mt-1">{r.error}</p>}
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
