import { useEffect } from 'react'
import { useDashboard } from '../store/dashboard'

export default function CriticalAlert() {
  const { criticalAlert, dismissCriticalAlert } = useDashboard()

  useEffect(() => {
    if (!criticalAlert) return
    const t = setTimeout(dismissCriticalAlert, 7000)
    return () => clearTimeout(t)
  }, [criticalAlert, dismissCriticalAlert])

  if (!criticalAlert) return null

  return (
    <div className="critical-toast" onClick={dismissCriticalAlert}>
      <span className="critical-toast-icon">⚠</span>
      <div className="critical-toast-body">
        <strong>CRITICAL ALERT</strong>
        <span>{criticalAlert.source} — {criticalAlert.description ?? criticalAlert.title}</span>
      </div>
      <button className="critical-toast-close">✕</button>
    </div>
  )
}
