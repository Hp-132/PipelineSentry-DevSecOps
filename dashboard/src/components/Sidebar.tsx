import { useState } from 'react'
import { Menu, X, Home, AlertCircle, GitBranch, Beaker, FileText, Server, Settings, ShieldAlert, RotateCcw, Package, FileCheck } from 'lucide-react'
import { BrandLogo } from './BrandLogo'

interface SidebarProps {
  current: string
  onNavigate: (page: string) => void
}

export const Sidebar: React.FC<SidebarProps> = ({ current, onNavigate }) => {
  const [collapsed, setCollapsed] = useState(false)

  const links = [
    { id: 'overview', label: 'Overview', icon: Home },
    { id: 'alerts', label: 'Alerts', icon: AlertCircle },
    { id: 'incidents', label: 'Incidents', icon: GitBranch },
    { id: 'response', label: 'Response', icon: ShieldAlert },
    { id: 'recovery', label: 'Recovery', icon: RotateCcw },
    { id: 'supply-chain', label: 'Supply Chain', icon: Package },
    { id: 'policy', label: 'Policy', icon: FileCheck },
    { id: 'attack-lab', label: 'Attack Lab', icon: Beaker },
    { id: 'events', label: 'Events', icon: FileText },
    { id: 'health', label: 'System Health', icon: Server },
  ]

  return (
    <aside
      className={`${collapsed ? 'w-[4.5rem]' : 'w-60'} bg-navy-800/80 backdrop-blur-xl border-r border-white/10 flex flex-col transition-all duration-300 shrink-0`}
    >
      <div className="h-14 px-3 border-b border-white/10 flex items-center justify-between gap-2">
        <div className={`flex items-center gap-2.5 min-w-0 ${collapsed ? 'justify-center w-full' : ''}`}>
          <BrandLogo size={collapsed ? 32 : 36} className="shrink-0" />
          {!collapsed && (
            <div className="min-w-0">
              <p className="text-sm font-semibold text-slate-100 truncate leading-tight">PipelineSentry</p>
              <p className="text-[10px] text-slate-500 uppercase tracking-widest font-medium">Detection Platform</p>
            </div>
          )}
        </div>
        {!collapsed && (
          <button
            type="button"
            onClick={() => setCollapsed(true)}
            className="p-1.5 rounded-md text-slate-500 hover:text-slate-300 hover:bg-white/5 transition-colors"
            aria-label="Collapse sidebar"
          >
            <X size={18} />
          </button>
        )}
      </div>

      {collapsed && (
        <div className="px-2 pt-2">
          <button
            type="button"
            onClick={() => setCollapsed(false)}
            className="w-full p-2 rounded-lg text-slate-500 hover:text-slate-300 hover:bg-white/5 transition-colors flex justify-center"
            aria-label="Expand sidebar"
          >
            <Menu size={18} />
          </button>
        </div>
      )}

      <nav className="flex-1 p-2 space-y-0.5">
        {links.map(({ id, label, icon: Icon }) => {
          const active = current === id
          return (
            <button
              key={id}
              type="button"
              onClick={() => onNavigate(id)}
              className={`w-full flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium transition-colors ${
                active
                  ? 'sidebar-active text-slate-100'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-white/5 border-l-[3px] border-transparent'
              } ${collapsed ? 'justify-center px-2' : ''}`}
              title={collapsed ? label : undefined}
            >
              <Icon size={18} className={`shrink-0 ${active ? 'text-accent-blue' : ''}`} />
              {!collapsed && <span className="truncate">{label}</span>}
            </button>
          )
        })}
      </nav>

      <div className="p-2 border-t border-white/10">
        <button
          type="button"
          className={`w-full flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm text-slate-500 hover:text-slate-300 hover:bg-white/5 transition-colors ${collapsed ? 'justify-center px-2' : ''}`}
        >
          <Settings size={18} className="shrink-0" />
          {!collapsed && <span>Settings</span>}
        </button>
      </div>
    </aside>
  )
}
