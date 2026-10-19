import { useState } from 'react'
import { Play, AlertCircle, CheckCircle, Clock, Zap } from 'lucide-react'
import { SCENARIO_DEFS, Alert as AlertType } from '@/types'
import { api } from '@/api'
import { SeverityBadge } from '@/components/SeverityBadge'
import { useToast } from '@/components/Toast'

export const AttackLab: React.FC = () => {
  const toast = useToast()
  const [running, setRunning] = useState<string | null>(null)
  const [results, setResults] = useState<Record<string, { alerts: AlertType[]; runId: string }>>({})
  const [loading, setLoading] = useState<string | null>(null)

  const handleRunScenario = async (scenarioId: string) => {
    setRunning(scenarioId)
    setLoading(scenarioId)
    try {
      const res = await api.scenarios.run(scenarioId)
      const runId = res.run_id || `scenario-${scenarioId}`

      // Poll for results
      let attempts = 0
      const maxAttempts = 30
      while (attempts < maxAttempts) {
        const alerts = await api.alerts.list({ attack_id: scenarioId, limit: 50 })
        if (alerts && alerts.length > 0) {
          setResults(prev => ({
            ...prev,
            [scenarioId]: { alerts, runId },
          }))
          toast.success(`Scenario ${scenarioId} completed: ${alerts.length} alerts detected`)
          break
        }
        await new Promise(r => setTimeout(r, 1000))
        attempts++
      }

      if (attempts === maxAttempts) {
        toast.error(`Scenario ${scenarioId} timed out waiting for results`)
      }
    } catch (err) {
      toast.error(`Failed to run scenario ${scenarioId}`)
      console.error(err)
    } finally {
      setRunning(null)
      setLoading(null)
    }
  }

  return (
    <div className="space-y-6">
      {/* Header Card */}
      <div className="metric-card relative overflow-hidden border-l-4 border-accent-cyan p-6">
        <div className="absolute inset-0 bg-gradient-to-r from-accent-cyan/5 to-accent-blue/5 pointer-events-none" />
        <div className="relative z-10">
          <div className="flex items-start gap-4">
            <div className="p-3 bg-gradient-to-br from-accent-cyan to-accent-blue rounded-lg shadow-glow-md">
              <Zap size={24} className="text-white" />
            </div>
            <div>
              <h2 className="text-xl font-bold bg-clip-text text-transparent bg-gradient-to-r from-accent-cyan to-accent-blue">
                🧪 Attack Scenario Lab
              </h2>
              <p className="text-sm text-slate-400 mt-2">
                Run synthetic attack scenarios (01–07) to test and demonstrate the detection engine. All scenarios are safe simulations.
              </p>
            </div>
          </div>
        </div>
      </div>

      {/* Scenarios Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
        {Object.entries(SCENARIO_DEFS).map(([id, def]) => {
          const result = results[id]
          const isRunning = running === id
          const layerColors: Record<string, { bg: string; border: string; text: string }> = {
            static: { bg: 'bg-blue-500/10', border: 'border-blue-500/30', text: 'text-blue-300' },
            behaviour: { bg: 'bg-violet-500/10', border: 'border-violet-500/30', text: 'text-violet-300' },
            runtime: { bg: 'bg-red-500/10', border: 'border-red-500/30', text: 'text-red-300' },
            multi: { bg: 'bg-cyan-500/10', border: 'border-cyan-500/30', text: 'text-cyan-300' },
          }

          const colors = layerColors[def.layer]

          return (
            <div key={id} className="scenario-card relative group">
              {/* Shimmer effect */}
              <div className="absolute inset-0 bg-gradient-to-r from-transparent via-white/5 to-transparent opacity-0 group-hover:opacity-100 transition-opacity duration-500" />

              <div className="relative z-20">
                {/* Header */}
                <div className="flex items-start justify-between mb-4">
                  <div>
                    <div className="flex items-center gap-3 mb-2">
                      <span className="text-3xl font-bold text-transparent bg-clip-text bg-gradient-to-r from-accent-blue to-accent-cyan">#{id}</span>
                      <span className={`text-xs font-bold px-3 py-1.5 rounded-full border ${colors.bg} ${colors.border} ${colors.text} uppercase tracking-widest shadow-sm`}>
                        {def.layer}
                      </span>
                    </div>
                    <h3 className="text-lg font-bold text-slate-200 group-hover:text-white transition-colors">{def.name}</h3>
                  </div>
                  <div className="relative">
                    {result && !isRunning && (
                      <div className="relative">
                        <CheckCircle size={24} className="text-green-400 animate-glow-pulse" />
                      </div>
                    )}
                    {isRunning && (
                      <Clock size={24} className="text-accent-cyan animate-spin" />
                    )}
                  </div>
                </div>

                {/* Description */}
                <p className="text-sm text-slate-400 mb-4 line-clamp-2 group-hover:text-slate-300 transition-colors">{def.description}</p>

                {/* Rules */}
                <div className="mb-4">
                  <p className="text-xs text-slate-400 uppercase tracking-widest mb-2 font-semibold">Expected Detections</p>
                  <div className="flex flex-wrap gap-1.5">
                    {def.rules.map(rule => (
                      <span
                        key={rule}
                        className="text-xs font-mono bg-white/10 border border-white/10 px-2.5 py-1.5 rounded-md text-accent-cyan hover:border-accent-cyan/50 hover:bg-accent-cyan/5 transition-all duration-300"
                      >
                        {rule}
                      </span>
                    ))}
                  </div>
                </div>

                {/* Results */}
                {result && (
                  <div className="mb-4 p-4 bg-gradient-to-br from-white/5 to-white/5 border border-white/10 rounded-lg">
                    <p className="text-xs text-slate-400 uppercase tracking-widest mb-3 font-semibold">
                      ✓ Results: <span className="text-green-400">{result.alerts.length} alerts</span>
                    </p>
                    <div className="space-y-1.5 max-h-40 overflow-y-auto">
                      {result.alerts.map((alert, idx) => (
                        <div key={alert.id} className="text-xs flex items-center gap-2 p-1.5 bg-white/5 rounded hover:bg-white/10 transition-colors">
                          <SeverityBadge severity={alert.severity} size="sm" />
                          <code className="text-accent-cyan font-mono text-xs flex-1">
                            {alert.evidence.rule_id || 'unknown'}
                          </code>
                          <span className="text-slate-500">{idx + 1}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* Action Button */}
                <button
                  onClick={() => handleRunScenario(id)}
                  disabled={isRunning || !!loading}
                  className={`w-full flex items-center justify-center gap-2 py-3 rounded-lg font-semibold text-sm transition-all duration-300 ${
                    isRunning
                      ? 'bg-gradient-to-r from-accent-cyan/30 to-accent-blue/30 text-accent-cyan cursor-wait shadow-glow-md animate-pulse'
                      : 'btn-primary hover:shadow-neon-blue'
                  }`}
                >
                  <Play size={16} className={isRunning ? 'animate-pulse' : ''} />
                  {isRunning ? 'Running...' : result ? 'Run Again' : 'Run Scenario'}
                </button>
              </div>
            </div>
          )
        })}
      </div>

      {/* Info Box */}
      <div className="glass p-6 flex items-start gap-4 border-l-4 border-accent-cyan">
        <div className="p-2 bg-accent-cyan/20 rounded-lg flex-shrink-0">
          <AlertCircle size={20} className="text-accent-cyan" />
        </div>
        <div className="flex-1">
          <p className="text-slate-200 font-semibold">How it works</p>
          <p className="text-slate-400 mt-2 leading-relaxed">
            Each scenario sends a synthetic event through the backend detection pipeline. Results appear in real-time as alerts are processed. Check the <span className="text-accent-blue font-mono">Alerts</span> page for detailed evidence.
          </p>
        </div>
      </div>
    </div>
  )
}
