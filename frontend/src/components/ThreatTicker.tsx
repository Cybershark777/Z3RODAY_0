import { useDashboard } from '../store/dashboard'

export default function ThreatTicker() {
  const { liveEvents } = useDashboard()

  if (liveEvents.length === 0) return null

  // Duplicate for seamless loop
  const items = [...liveEvents.slice(0, 20), ...liveEvents.slice(0, 20)]

  const sevColor: Record<string, string> = {
    critical: '#ff6b6b',
    high: '#e3b341',
    medium: '#00e676',
    low: '#00bcd4',
  }

  return (
    <div className="ticker-wrapper">
      <span className="ticker-label">LIVE</span>
      <div className="ticker-track">
        <div className="ticker-inner" style={{ animationDuration: `${Math.max(80, items.length * 7)}s` }}>
          {items.map((e, i) => (
            <span key={`${e.id}-${i}`} className="ticker-item">
              <span
                className="ticker-sev"
                style={{ color: sevColor[e.severity] ?? '#4a5568' }}
              >
                [{e.severity?.toUpperCase()}]
              </span>{' '}
              {e.source}: {e.description ?? e.title}
              <span className="ticker-sep">◆</span>
            </span>
          ))}
        </div>
      </div>
    </div>
  )
}
