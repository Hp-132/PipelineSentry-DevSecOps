import { Severity } from '@/types'

interface SeverityBadgeProps {
  severity: Severity
  size?: 'sm' | 'md'
}

export const SeverityBadge: React.FC<SeverityBadgeProps> = ({ severity, size = 'md' }) => {
  const classes = {
    critical: 'badge-critical',
    high: 'badge-high',
    med: 'badge-medium',
    low: 'badge-low',
  }

  const sizes = {
    sm: 'text-xs px-2 py-1',
    md: 'text-sm px-2.5 py-1',
  }

  return (
    <span className={`${classes[severity]} ${sizes[size]}`}>
      {severity.toUpperCase()}
    </span>
  )
}
