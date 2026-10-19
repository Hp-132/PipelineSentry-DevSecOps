import { useEffect, useState } from 'react'
import { Sidebar } from '@/components/Sidebar'
import { Topbar } from '@/components/Topbar'
import { Toast } from '@/components/Toast'
import { Overview } from '@/pages/Overview'
import { Alerts } from '@/pages/Alerts'
import { Incidents } from '@/pages/Incidents'
import { AttackLab } from '@/pages/AttackLab'
import { Events } from '@/pages/Events'
import { Health } from '@/pages/Health'
import { api } from '@/api'
import { HealthCheck } from '@/types'

export default function App() {
  const [page, setPage] = useState('overview')
  const [health, setHealth] = useState<HealthCheck | null>(null)
  const [refreshKey, setRefreshKey] = useState(0)

  useEffect(() => {
    const check = async () => {
      const h = await api.health().catch(console.error)
      setHealth(h || null)
    }
    check()
  }, [refreshKey])

  const pages: Record<string, { title: string; component: React.FC }> = {
    overview: { title: 'Overview', component: Overview },
    alerts: { title: 'Alerts', component: Alerts },
    incidents: { title: 'Incidents & Correlation', component: Incidents },
    'attack-lab': { title: 'Attack Lab', component: AttackLab },
    events: { title: 'Events', component: Events },
    health: { title: 'System Health', component: Health },
  }

  const current = pages[page] || pages.overview
  const Component = current.component

  return (
    <div className="flex h-screen bg-navy-900 relative overflow-hidden">
      <div className="pointer-events-none absolute inset-0 bg-[radial-gradient(ellipse_80%_50%_at_50%_-20%,rgba(82,139,255,0.12),transparent)]" />
      
      <Sidebar current={page} onNavigate={setPage} />

      <main className="flex-1 flex flex-col overflow-hidden relative z-10">
        <Topbar
          title={current.title}
          onRefresh={() => setRefreshKey(k => k + 1)}
          health={health ?? undefined}
        />

        <div className="flex-1 overflow-auto">
          <div className="p-6 max-w-7xl mx-auto w-full">
            <Component key={page} />
          </div>
        </div>
      </main>

      <Toast />
    </div>
  )
}
