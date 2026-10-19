import { ReactNode } from 'react'

interface MetricCardProps {
  title: string
  value: ReactNode
  subtitle?: string
  trend?: 'up' | 'down'
  icon?: ReactNode
}

export const MetricCard: React.FC<MetricCardProps> = ({ title, value, subtitle, icon }) => {
  return (
    <div className="metric-card">
      <div className="flex items-start justify-between gap-3 mb-3">
        <p className="text-[11px] font-medium text-slate-400 uppercase tracking-[0.12em]">{title}</p>
        {icon && (
          <div className="metric-card-icon shrink-0">
            {icon}
          </div>
        )}
      </div>
      <p className="text-3xl font-semibold text-slate-100 tabular-nums tracking-tight leading-none">{value}</p>
      {subtitle && <p className="text-xs text-slate-500 mt-2 leading-relaxed">{subtitle}</p>}
    </div>
  )
}
