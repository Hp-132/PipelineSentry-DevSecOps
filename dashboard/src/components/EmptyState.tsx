import { ReactNode } from 'react'
import { Database } from 'lucide-react'

interface EmptyStateProps {
  icon?: ReactNode
  title: string
  description: string
  action?: { label: string; onClick: () => void }
}

export const EmptyState: React.FC<EmptyStateProps> = ({
  icon = <Database className="w-16 h-16 text-accent-blue/30" />,
  title,
  description,
  action,
}) => (
  <div className="flex flex-col items-center justify-center py-12 px-4">
    {icon}
    <h3 className="mt-4 text-lg font-semibold text-slate-300">{title}</h3>
    <p className="mt-2 text-slate-400 text-sm max-w-md text-center">{description}</p>
    {action && (
      <button onClick={action.onClick} className="btn-primary mt-4">
        {action.label}
      </button>
    )}
  </div>
)
