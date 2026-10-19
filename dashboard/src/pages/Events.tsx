import { EmptyState } from '@/components/EmptyState'
import { AlertCircle } from 'lucide-react'

export const Events: React.FC = () => (
  <EmptyState
    icon={<AlertCircle className="w-12 h-12 text-accent-blue/30" />}
    title="Event Explorer"
    description="Raw event inspection and debugging. Backend event records will appear here when the API exposes the necessary endpoints."
  />
)
