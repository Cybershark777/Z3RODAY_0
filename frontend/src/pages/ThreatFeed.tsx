import { useState } from 'react'
import { useDashboard } from '../store/dashboard'

const SEV_ORDER = ['critical', 'high', 'medium', 'low']

export default function ThreatFeed() {
  const [filter, setFilter] = useState<string | null>(null)
  const { liveEvents, wsConnected } = useDashboard()

  const filtered = filter ? liveEvents.filter((e) => e.severity === filter) : liveEvents

  const counts = liveEvents.reduce<Record<string, number>>((acc, e) => {
    acc[e.severity] = (acc[e.severity] ?? 0) + 1
    return acc
  }, {})

  return (
    <div className="tab-page">
      <div className="section-header">
        <h2>Live Threat Feed</h2>
        <p className="section-desc">
          Real-time CPS threat events streamed via WebSocket. Critical and high events are
          persisted to the database automatically.
        </p>
      </div>

      {/* Status & Stats */}
      <div style={{ display: 'flex', gap: '1rem', marginBottom: '1.5rem', flexWrap: 'wrap', alignItems: 'center' }}>
        <div className="ws-indicator">
          <span className={`dot ${wsConnected ? 'dot-green' : 'dot-red'}`} />
          {wsConnected ? 'WebSocket Connected' : 'Reconnecting...'}
        </div>
        <div style={{ display: 'flex', gap: '0.5rem' }}>
          {SEV_ORDER.map((sev) => (
            <div key={sev} className={`severity-badge sev-${sev}`}>
              {counts[sev] ?? 0} {sev}
            </div>
          ))}
        </div>
        <span style={{ marginLeft: 'auto', fontSize: '0.8rem', color: 'var(--text-muted)' }}>
          {liveEvents.length} total events (last 100)
        </span>
      </div>

      {/* Filter */}
      <div className="filters" style={{ marginBottom: '1rem' }}>
        <button className={`filter-btn${!filter ? ' active' : ''}`} onClick={() => setFilter(null)}>All</button>
        {SEV_ORDER.map((sev) => (
          <button
            key={sev}
            className={`filter-btn${filter === sev ? ' active' : ''}`}
            onClick={() => setFilter(sev)}
          >{sev}</button>
        ))}
      </div>

      {/* Events */}
      {filtered.length === 0 ? (
        <div style={{ padding: '2rem', textAlign: 'center', color: 'var(--text-muted)' }}>
          {wsConnected ? 'Waiting for events...' : 'Connecting to threat feed...'}
        </div>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
          {filtered.map((event) => (
            <div key={event.id} className="feed-event">
              <div style={{ flex: 1 }}>
                <div className="feed-event-header">
                  <span className={`severity-badge sev-${event.severity}`}>{event.severity}</span>
                  <span className="event-source">{event.source}</span>
                  {event.actor && (
                    <span style={{ fontSize: '0.78rem', color: 'var(--accent2)' }}>← {event.actor}</span>
                  )}
                  <span className="event-time" style={{ marginLeft: 'auto' }}>
                    {new Date(event.timestamp).toLocaleTimeString()}
                  </span>
                </div>
                <div className="event-desc">{event.description ?? event.title}</div>
                {event.score !== undefined && (
                  <div style={{ marginTop: 4, fontSize: '0.72rem', color: 'var(--text-muted)' }}>
                    Anomaly score: <span style={{ color: event.score > 0.7 ? '#ff6b6b' : '#3fb950' }}>
                      {(event.score * 100).toFixed(1)}%
                    </span>
                  </div>
                )}
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}
