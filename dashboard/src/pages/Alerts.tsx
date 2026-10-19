import { useEffect, useState } from 'react'
import { Alert as AlertType } from '@/types'
import { api } from '@/api'
import { SeverityBadge } from '@/components/SeverityBadge'
import { LoadingSkeleton } from '@/components/LoadingSkeleton'
import { EmptyState } from '@/components/EmptyState'
import { Search, ChevronDown, X } from 'lucide-react'

export const Alerts: React.FC = () => {
  const [alerts, setAlerts] = useState<AlertType[]>([])
  const [filtered, setFiltered] = useState<AlertType[]>([])
  const [loading, setLoading] = useState(true)
  const [search, setSearch] = useState('')
  const [selectedAlert, setSelectedAlert] = useState<AlertType | null>(null)
  const [severityFilter, setSeverityFilter] = useState<string | null>(null)
  const [layerFilter, setLayerFilter] = useState<string | null>(null)

  useEffect(() => {
    const load = async () => {
      setLoading(true)
      const data = await api.alerts.list({ limit: 200 }).catch(console.error)
      setAlerts(data || [])
      setLoading(false)
    }
    load()
  }, [])

  useEffect(() => {
    let result = alerts
    if (search) {
      const q = search.toLowerCase()
      result = result.filter(
        a =>
          a.title.toLowerCase().includes(q) ||
          a.id.toLowerCase().includes(q) ||
          a.run_id.toLowerCase().includes(q) ||
          a.evidence.rule_id?.toLowerCase().includes(q)
      )
    }
    if (severityFilter) {
      result = result.filter(a => a.severity === severityFilter)
    }
    if (layerFilter) {
      result = result.filter(a => a.layer === layerFilter)
    }
    setFiltered(result)
  }, [alerts, search, severityFilter, layerFilter])

  return (
    <div className="space-y-6">
      {/* Filter Bar */}
      <div className="glass p-5 flex flex-wrap gap-4 items-end">
        <div className="flex-1 min-w-xs group">
          <label className="text-xs text-slate-400 uppercase tracking-widest font-semibold mb-2 block">Search</label>
          <div className="relative">
            <Search size={18} className="absolute left-3 top-1/2 -translate-y-1/2 text-accent-blue/50 group-hover:text-accent-blue transition-colors" />
            <input
              type="text"
              placeholder="Rule ID, title, or run ID..."
              value={search}
              onChange={e => setSearch(e.target.value)}
              className="w-full pl-10 pr-4 py-2.5 bg-white/5 border border-white/20 rounded-lg text-sm text-slate-300 placeholder:text-slate-500 focus:outline-none focus:ring-2 focus:ring-accent-blue/50 transition-all duration-300"
            />
          </div>
        </div>

        <div className="group">
          <label className="text-xs text-slate-400 uppercase tracking-widest font-semibold mb-2 block">Severity</label>
          <select
            value={severityFilter || ''}
            onChange={e => setSeverityFilter(e.target.value || null)}
            className="px-4 py-2.5 bg-white/5 border border-white/20 rounded-lg text-sm text-slate-300 focus:outline-none focus:ring-2 focus:ring-accent-blue/50 transition-all duration-300 cursor-pointer"
          >
            <option value="">All</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="med">Medium</option>
            <option value="low">Low</option>
          </select>
        </div>

        <div className="group">
          <label className="text-xs text-slate-400 uppercase tracking-widest font-semibold mb-2 block">Layer</label>
          <select
            value={layerFilter || ''}
            onChange={e => setLayerFilter(e.target.value || null)}
            className="px-4 py-2.5 bg-white/5 border border-white/20 rounded-lg text-sm text-slate-300 focus:outline-none focus:ring-2 focus:ring-accent-blue/50 transition-all duration-300 cursor-pointer"
          >
            <option value="">All</option>
            <option value="static">Static</option>
            <option value="behaviour">Behaviour</option>
            <option value="runtime">Runtime</option>
            <option value="correlation">Correlation</option>
          </select>
        </div>
      </div>

      {/* Alerts List */}
      {loading ? (
        <div className="glass p-6 rounded-2xl">
          <LoadingSkeleton count={5} />
        </div>
      ) : filtered.length === 0 ? (
        <div className="glass p-12 rounded-2xl">
          <EmptyState
            title="No alerts found"
            description={
              alerts.length === 0
                ? 'Run an attack scenario or submit events to generate alerts'
                : 'Try adjusting your filters or search query'
            }
          />
        </div>
      ) : (
        <div className="glass overflow-hidden rounded-2xl divide-y divide-white/5">
          {filtered.map((alert, idx) => (
            <button
              key={alert.id}
              onClick={() => setSelectedAlert(alert)}
              className="w-full p-5 hover:bg-white/10 transition-all duration-300 text-left group relative overflow-hidden alert-row"
              style={{ animationDelay: `${idx * 50}ms` }}
            >
              <div className="absolute inset-0 bg-gradient-to-r from-accent-blue/0 via-accent-blue/5 to-transparent opacity-0 group-hover:opacity-100 transition-opacity duration-300 pointer-events-none" />
              
              <div className="relative z-10 flex items-start justify-between gap-4">
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-3 mb-2 flex-wrap">
                    <SeverityBadge severity={alert.severity} size="sm" />
                    <span className="text-xs font-mono bg-accent-blue/20 text-accent-blue px-2.5 py-1 rounded-md border border-accent-blue/30">
                      {alert.evidence.rule_id || 'N/A'}
                    </span>
                    <span className="text-xs text-slate-400 bg-white/10 px-2.5 py-1 rounded-md border border-white/20 uppercase tracking-widest font-semibold">
                      {alert.layer}
                    </span>
                  </div>
                  <p className="text-sm text-slate-200 group-hover:text-white transition-colors font-medium">{alert.title}</p>
                  <p className="text-xs text-slate-500 mt-2 font-mono">
                    Run: <span className="text-accent-blue/60">{alert.run_id.substring(0, 16)}...</span>
                  </p>
                </div>
                <div className="flex flex-col items-end flex-shrink-0 gap-2">
                  <span className="text-xs text-slate-400 whitespace-nowrap">
                    {new Date(alert.timestamp).toLocaleDateString()} {new Date(alert.timestamp).toLocaleTimeString()}
                  </span>
                  <ChevronDown size={18} className="text-slate-400 group-hover:text-accent-blue group-hover:scale-110 transition-all duration-300" />
                </div>
              </div>
            </button>
          ))}
        </div>
      )}

      {/* Detail Panel */}
      {selectedAlert && (
        <div className="glass p-6 rounded-2xl border-l-4 border-accent-cyan scale-in">
          <div className="flex items-start justify-between mb-5">
            <div>
              <h3 className="text-lg font-bold bg-clip-text text-transparent bg-gradient-to-r from-accent-cyan to-accent-blue">Alert Details</h3>
              <p className="text-xs text-slate-400 mt-1">ID: {selectedAlert.id}</p>
            </div>
            <button 
              onClick={() => setSelectedAlert(null)} 
              className="p-2 hover:bg-white/10 rounded-lg transition-all duration-300 hover:text-accent-cyan"
            >
              <X size={20} />
            </button>
          </div>
          
          <div className="space-y-4 bg-white/5 p-4 rounded-lg border border-white/5">
            <div>
              <p className="text-xs text-slate-400 uppercase tracking-widest font-semibold mb-2">Rule ID</p>
              <code className="text-sm font-mono text-accent-cyan bg-white/5 px-3 py-2 rounded block break-all">{selectedAlert.evidence.rule_id}</code>
            </div>
            
            <div>
              <p className="text-xs text-slate-400 uppercase tracking-widest font-semibold mb-2">Recommended Action</p>
              <p className="text-sm text-slate-300 leading-relaxed">{selectedAlert.recommended_action}</p>
            </div>
            
            <div>
              <p className="text-xs text-slate-400 uppercase tracking-widest font-semibold mb-2">Evidence</p>
              <pre className="bg-white/5 border border-white/10 p-4 rounded-lg text-xs overflow-x-auto text-slate-300 font-mono max-h-48 overflow-y-auto">
                {JSON.stringify(selectedAlert.evidence, null, 2)}
              </pre>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
