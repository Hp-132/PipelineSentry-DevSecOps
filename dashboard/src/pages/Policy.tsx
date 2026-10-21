import { useState } from 'react'
import { FileCheck } from 'lucide-react'
import { api, describeError } from '@/api'
import { DefenceStatus, PolicyResult, PolicySample } from '@/types'
import { DataView, StatusPill, formatTime, useAsync } from '@/components/DataState'
import { SeverityBadge } from '@/components/SeverityBadge'
import { useToast } from '@/components/Toast'

export const Policy: React.FC = () => {
  const toast = useToast()
  const results = useAsync(() => api.policy.results())
  const samples = useAsync<PolicySample[]>(() => api.policy.samples())
  const defence = useAsync<DefenceStatus>(() => api.defenceStatus())
  const [busy, setBusy] = useState<string | null>(null)

  const evaluate = async (sample: PolicySample) => {
    setBusy(sample.path)
    try {
      const r = await api.policy.evaluate({ kind: sample.kind, path: sample.path })
      toast.success(`${sample.name}: ${r.allowed ? 'allowed' : `denied (${r.violations.length} violation(s))`}`)
      results.reload()
    } catch (err) {
      toast.error(describeError(err))
    } finally {
      setBusy(null)
    }
  }

  return (
    <div className="space-y-6">
      <div className="glass p-5 rounded-2xl">
        <p className="text-sm text-slate-300">
          Engine: <span className="font-mono text-accent-cyan">{defence.data ? (defence.data.policy.opa ? `OPA ${defence.data.policy.opa}` : 'OPA not installed') : '…'}</span>
          {defence.data && <> · approved registries: <span className="font-mono">{defence.data.policy.allowed_registries.join(', ')}</span></>}
        </p>
        <p className="text-xs text-slate-500 mt-2">
          This is policy <strong>evaluation</strong>: it reports whether a configuration would be admitted and raises
          alerts for violations. Blocking at admission time is done by the Kyverno policies in <code>policy/kyverno</code>,
          which need a Kubernetes cluster.
        </p>
      </div>

      <div className="glass p-5 rounded-2xl">
        <p className="text-sm font-semibold text-slate-200 mb-3">Evaluate a sample</p>
        {samples.error && <p className="text-sm text-red-300">{samples.error}</p>}
        <div className="flex flex-wrap gap-2">
          {(samples.data || []).map(s => (
            <button key={s.path} disabled={!!busy} onClick={() => evaluate(s)} className="btn-secondary text-xs">
              {busy === s.path ? 'Evaluating…' : `${s.kind}: ${s.name}`}
            </button>
          ))}
        </div>
      </div>

      <DataView state={results} empty={{
        icon: <FileCheck className="w-12 h-12 text-accent-blue/30" />,
        title: 'No policy evaluations yet',
        description: 'Evaluate one of the samples above or call POST /policy/evaluate.',
      }}>
        {(list: PolicyResult[]) => (
          <div className="space-y-4">
            {list.map(r => (
              <div key={r.id} className="glass p-5 rounded-2xl">
                <div className="flex items-center gap-3 flex-wrap">
                  <StatusPill status={r.allowed ? 'allowed' : 'denied'} />
                  <span className="text-xs uppercase tracking-widest text-slate-400">{r.target_kind}</span>
                  <span className="font-mono text-slate-200 break-all flex-1">{r.target}</span>
                  <span className="text-xs text-slate-500">{r.engine} · {formatTime(r.created_at)}</span>
                </div>
                {r.violations.length > 0 && (
                  <div className="mt-3 space-y-1.5">
                    {r.violations.map((v, i) => (
                      <div key={i} className="flex items-center gap-3 text-sm bg-white/5 rounded-lg px-3 py-2">
                        <SeverityBadge severity={v.severity} size="sm" />
                        <code className="text-xs text-accent-cyan w-24 shrink-0">{v.rule_id}</code>
                        <span className="text-slate-300 flex-1">{v.message}</span>
                        <span className="text-xs text-slate-500 hidden md:inline">{v.resource}</span>
                      </div>
                    ))}
                  </div>
                )}
                {r.alert_ids.length > 0 && (
                  <p className="text-xs text-slate-500 mt-3">{r.alert_ids.length} alert(s) raised in run <span className="font-mono">{r.run_id}</span> — see Alerts / Incidents.</p>
                )}
              </div>
            ))}
          </div>
        )}
      </DataView>
    </div>
  )
}
