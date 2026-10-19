import { useEffect, useState } from 'react'
import { X, Check, AlertCircle } from 'lucide-react'

export type ToastType = 'success' | 'error' | 'info'

interface ToastMessage {
  id: string
  message: string
  type: ToastType
  duration?: number
}

let toastId = 0
const listeners: Set<(toast: ToastMessage) => void> = new Set()

export const useToast = () => ({
  success: (message: string) => {
    const id = String(toastId++)
    const toast: ToastMessage = { id, message, type: 'success', duration: 4000 }
    listeners.forEach(l => l(toast))
  },
  error: (message: string) => {
    const id = String(toastId++)
    const toast: ToastMessage = { id, message, type: 'error', duration: 6000 }
    listeners.forEach(l => l(toast))
  },
  info: (message: string) => {
    const id = String(toastId++)
    const toast: ToastMessage = { id, message, type: 'info', duration: 4000 }
    listeners.forEach(l => l(toast))
  },
})

export const Toast: React.FC = () => {
  const [toasts, setToasts] = useState<ToastMessage[]>([])

  useEffect(() => {
    const handler = (toast: ToastMessage) => {
      setToasts(prev => [...prev, toast])
      if (toast.duration) {
        setTimeout(() => {
          setToasts(prev => prev.filter(t => t.id !== toast.id))
        }, toast.duration)
      }
    }
    listeners.add(handler)
    return () => {
      listeners.delete(handler)
    }
  }, [])

  return (
    <div className="fixed bottom-4 right-4 space-y-2 z-50">
      {toasts.map(toast => (
        <div
          key={toast.id}
          className={`flex items-center gap-3 px-4 py-3 rounded-lg border backdrop-blur-xs glass animate-in fade-in slide-in-from-bottom-2 duration-200 ${
            toast.type === 'success'
              ? 'bg-green-500/10 border-green-500/30 text-green-300'
              : toast.type === 'error'
              ? 'bg-red-500/10 border-red-500/30 text-red-300'
              : 'bg-blue-500/10 border-blue-500/30 text-blue-300'
          }`}
        >
          {toast.type === 'success' && <Check size={18} />}
          {toast.type === 'error' && <AlertCircle size={18} />}
          {toast.type === 'info' && <AlertCircle size={18} />}
          <span className="text-sm font-medium">{toast.message}</span>
          <button
            onClick={() => setToasts(prev => prev.filter(t => t.id !== toast.id))}
            className="ml-auto hover:opacity-70 transition-opacity"
          >
            <X size={16} />
          </button>
        </div>
      ))}
    </div>
  )
}
