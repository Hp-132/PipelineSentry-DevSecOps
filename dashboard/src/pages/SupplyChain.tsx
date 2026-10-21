import { useState } from 'react'
import { Download, Package } from 'lucide-react'
import { api, describeError } from '@/api'
import { DefenceStatus, SupplyChainResult } from '@/types'
import { DataView, StatusPill, formatTime, useAsync } from '@/components/DataState'
import { MetricCard } from '@/components/MetricCard'
import { useToast } from '@/components/Toast'

const input = 'w-full px-4 py-2.5 bg-white/5 border border-white/20 rounded-lg text-sm text-slate-300 placeholder:text-slate-500 focus:outline-none focus:ring-2 focus:ring-accent-blue/50'

export const SupplyChain: React.FC = () => {
  const toast = useToast()
  const [kind, setKind] = useState('')
  const results = useAsync(() => api.supplyChain.results({ kind: kind || undefined }), [kind])
  const defence = useAsync<DefenceStatus>(() => api.defenceStatus())
  const [image, setImage] = useState('registry:5000/demo/app:signed')
  const [path, setPath] = useState('requirements.txt')
  const [busy, setBusy] = useState<string | null>(null)

  const submit = async (label: string, fn: () => Promise<SupplyChainResult>) => {
    setBusy(label)
    try {
      const r = await fn()
      toast.success(`${r.kind} ${r.subject}: ${r.status.replace(/_/g, ' ')}`)
      results.reload()
    } catch (err) {
      toast.error(describeError(err))
    } finally {
      setBusy(null)
    }
  }

  const tools = defence.data?.supply_chain
  return (
    <div className="space-y-6">
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <MetricCard title="Cosign" value={tools ? (tools.cosign || 'missing') : '—'}
          subtitle={tools ? (tools.cosign_public_key ? 'trusted public key present' : 'no public key yet — run the demo to create one') : 'loading…'} />
        <MetricCard title="CycloneDX" value={tools ? (tools.cyclonedx || 'missing') : '—'} subtitle="cyclonedx-bom, spec 1.6 JSON" />
        <MetricCard title="Results stored" value={results.data ? results.data.length : '—'} subtitle="signature checks and SBOMs" />
      </div>
      {defence.error && <p className="text-sm text-red-300">{defence.error}</p>}

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
        <div className="glass p-5 rounded-2xl space-y-3">
          <p className="text-sm font-semibold text-slate-200">Verify an image signature</p>
          <input value={image} onChange={e => setImage(e.target.value)} className={input} placeholder="registry:5000/demo/app:signed" />
          <button disabled={!!busy || !image} onClick={() => submit('verify', () => api.supplyChain.verify(image))} className="btn-primary">
            {busy === 'verify' ? 'Verifying…' : 'Run cosign verify'}
          </button>
          <p className="text-xs text-slate-500">
            Verified only when <code>cosign verify</code> succeeds for this digest. Conclusive results are sent to the
            detection engine as image events (IMG-001 unsigned, IMG-002 failed verification).
          </p>
        </div>
        <div className="glass p-5 rounded-2xl space-y-3">
          <p className="text-sm font-semibold text-slate-200">Generate a CycloneDX SBOM</p>
          <input value={path} onChange={e => setPath(e.target.value)} className={input} placeholder="requirements file relative to the scan root" />
          <div className="flex gap-2 flex-wrap">
            <button disabled={!!busy || !path} onClick={() => submit('sbom', () => api.supplyChain.sbom({ path }))} className="btn-primary">
              {busy === 'sbom' ? 'Generating…' : 'SBOM for file'}
            </button>
            <button disabled={!!busy} onClick={() => submit('env', () => api.supplyChain.sbom({ environment: true }))} className="btn-secondary">
              {busy === 'env' ? 'Generating…' : 'SBOM for running environment'}
            </button>
          </div>
          <p className="text-xs text-slate-500">File SBOMs are also scanned by Member 1's dependency rules (typosquats, unsafe indexes).</p>
        </div>
      </div>

      <div className="flex items-center gap-3">
        <select value={kind} onChange={e => setKind(e.target.value)} className="px-4 py-2.5 bg-white/5 border border-white/20 rounded-lg text-sm text-slate-300">
          <option value="">All results</option>
          <option value="signature">Signatures</option>
          <option value="sbom">SBOMs</option>
        </select>
        <button onClick={results.reload} className="btn-secondary">Refresh</button>
      </div>

      <DataView state={results} empty={{
        icon: <Package className="w-12 h-12 text-accent-blue/30" />,
        title: 'No supply-chain results',
        description: 'Verify an image or generate an SBOM above, or run the Member 2 demo.',
      }}>
        {(list: SupplyChainResult[]) => (
          <div className="glass rounded-2xl divide-y divide-white/5">
            {list.map(r => (
              <div key={r.id} className="p-4 text-sm">
                <div className="flex items-center gap-3 flex-wrap">
                  <span className="text-xs uppercase tracking-widest text-slate-400 w-20">{r.kind}</span>
                  <span className="font-mono text-slate-200 break-all flex-1">{r.subject}</span>
                  <StatusPill status={r.status} />
                  {r.has_document && (
                    <a href={api.supplyChain.sbomUrl(r.id)} target="_blank" rel="noreferrer"
                      className="text-accent-cyan hover:underline flex items-center gap-1 text-xs">
                      <Download size={13} /> SBOM
                    </a>
                  )}
                </div>
                <p className="text-xs text-slate-400 mt-2">
                  {r.kind === 'sbom'
                    ? (r.summary.component_count !== undefined
                      ? `${r.summary.component_count} components · ${r.summary.format} · schema ${r.summary.schema_valid ? 'valid' : 'INVALID'}`
                      : r.summary.detail)
                    : r.summary.detail}
                  {r.summary.digest && <span className="font-mono"> · {r.summary.digest.slice(0, 19)}…</span>}
                  {r.event_ids.length > 0 && ` · sent to detection (run ${r.run_id})`}
                </p>
                <p className="text-xs text-slate-500 mt-1">{r.tool} {r.tool_version || ''} · {formatTime(r.created_at)}</p>
              </div>
            ))}
          </div>
        )}
      </DataView>
    </div>
  )
}
