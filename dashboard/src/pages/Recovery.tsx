import { RotateCcw } from 'lucide-react'
import { api } from '@/api'
import { RecoveryRun } from '@/types'
import { DataView, ModeBadge, StatusPill, formatTime, useAsync } from '@/components/DataState'

export const Recovery: React.FC = () => {
  const runs = useAsync(() => api.recovery.list())
  return (
    <div className="space-y-6">
      <div className="glass p-5 flex items-center gap-4">
        <p className="text-sm text-slate-400 flex-1">
          Recovery runs for contained incidents. All recovery is simulated: it updates PipelineSentry's containment
          state and audit trail. Steps that are unsafe to automate stop with <span className="text-amber-300">manual required</span>.
        </p>
        <button onClick={runs.reload} className="btn-secondary">Refresh</button>
      </div>
      <DataView state={runs} empty={{
        icon: <RotateCcw className="w-12 h-12 text-accent-blue/30" />,
        title: 'No recovery runs',
        description: 'Contain an incident with a simulated response, then run recovery from the Incidents page.',
      }}>
        {(list: RecoveryRun[]) => (
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
            {list.map(run => (
              <div key={run.id} className="glass p-5 rounded-2xl">
                <div className="flex items-center gap-2 flex-wrap mb-1">
                  <span className="font-mono text-slate-100">{run.plan}</span>
                  {run.simulated && <ModeBadge mode="simulated" />}
                  <span className="ml-auto"><StatusPill status={run.status} /></span>
                </div>
                <p className="text-xs text-slate-500 truncate" title={run.target}>target {run.target}</p>
                <p className="text-xs text-slate-500 font-mono truncate">incident {run.incident_id}</p>
                <ol className="mt-4 space-y-2">
                  {run.steps.map((step, i) => (
                    <li key={i} className="text-sm bg-white/5 rounded-lg px-3 py-2">
                      <div className="flex items-center gap-2">
                        <span className="text-slate-500 tabular-nums">{i + 1}.</span>
                        <span className="font-mono text-slate-300">{step.name}</span>
                        <span className="ml-auto"><StatusPill status={step.status} /></span>
                      </div>
                      <p className="text-xs text-slate-400 mt-1">{step.detail}</p>
                    </li>
                  ))}
                </ol>
                <p className="text-xs text-slate-500 mt-3">{formatTime(run.created_at)}</p>
              </div>
            ))}
          </div>
        )}
      </DataView>
    </div>
  )
}
