interface StatusIndicatorProps {
  status: 'healthy' | 'degraded' | 'unhealthy'
  label: string
}

export const StatusIndicator: React.FC<StatusIndicatorProps> = ({ status, label }) => {
  const classes = {
    healthy: 'status-healthy',
    degraded: 'status-degraded',
    unhealthy: 'status-unhealthy',
  }

  const textColor = {
    healthy: 'text-green-400',
    degraded: 'text-yellow-400',
    unhealthy: 'text-red-400',
  }

  return (
    <div className="flex items-center gap-2">
      <div className={classes[status]} />
      <span className={`text-sm font-medium ${textColor[status]}`}>{label}</span>
    </div>
  )
}
