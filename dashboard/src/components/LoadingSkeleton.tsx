export const LoadingSkeleton: React.FC<{ count?: number; height?: string }> = ({ count = 3, height = 'h-10' }) => (
  <div className="space-y-3">
    {Array(count).fill(0).map((_, i) => (
      <div key={i} className={`${height} bg-navy-700/50 rounded-lg animate-pulse`} />
    ))}
  </div>
)

export const LoadingGrid: React.FC = () => (
  <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
    {Array(4).fill(0).map((_, i) => (
      <div key={i} className="card">
        <div className="h-8 bg-navy-700/50 rounded animate-pulse mb-3" />
        <div className="h-6 bg-navy-700/30 rounded animate-pulse" />
      </div>
    ))}
  </div>
)
