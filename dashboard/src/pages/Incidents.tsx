import { EmptyState } from '@/components/EmptyState'
import { GitBranch } from 'lucide-react'

export const Incidents: React.FC = () => (
  <EmptyState
    icon={<GitBranch className="w-12 h-12 text-accent-blue/30" />}
    title="Correlated Incidents"
    description="Multi-layer incident analysis and correlation timeline. Select an alert to view its correlated run and timeline."
  />
)
