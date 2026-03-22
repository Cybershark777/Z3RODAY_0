import { useQuery } from '@tanstack/react-query'
import { api } from '../services/api'
import LoadingSpinner from '../components/LoadingSpinner'

export default function PhysicalThreats() {
  const { data: incidents, isLoading } = useQuery({
    queryKey: ['incidents'],
    queryFn: api.incidents,
  })

  if (isLoading) return <LoadingSpinner message="Loading physical threat data..." />

  const physicalIncidents = (incidents?.incidents ?? []).filter(
    (inc: any) => inc.category === 'physical' || inc.source?.includes('sensor'),
  )

  return (
    <div className="tab-page">
      <div className="section-header">
        <h2>Physical / Environmental Threats</h2>
        <p className="section-desc">
          Physical security events, sensor anomalies, and environmental threat indicators affecting
          data center cyber-physical systems.
        </p>
      </div>

      <div className="purdue-section">
        <h3>Purdue Reference Model — Physical Threat Surface</h3>
        <div className="purdue-levels">
          {[
            { level: 0, label: 'Level 0 — Field Devices', desc: 'Sensors, actuators, PLCs directly interfacing physical processes. Direct manipulation attack surface.', color: '#ff6b6b' },
            { level: 1, label: 'Level 1 — Control', desc: 'PLC controllers, RTUs, safety instrumented systems. Primary OT threat target.', color: '#ffa94d' },
            { level: 2, label: 'Level 2 — Supervisory', desc: 'SCADA, HMI, DCS. Configuration and visibility layer.', color: '#ffd43b' },
            { level: 3, label: 'Level 3 — Operations', desc: 'Manufacturing ops, historians, operational databases.', color: '#69db7c' },
            { level: 4, label: 'Level 4/5 — Enterprise', desc: 'Corporate IT, ERP, cloud connectivity. Entry point for IT→OT attacks.', color: '#74c0fc' },
          ].map((l) => (
            <div key={l.level} className="purdue-level-card" style={{ borderLeft: `4px solid ${l.color}` }}>
              <div className="purdue-level-title">{l.label}</div>
              <div className="purdue-level-desc">{l.desc}</div>
            </div>
          ))}
        </div>
      </div>

      {physicalIncidents.length > 0 && (
        <div className="intel-section">
          <h3>Physical Sensor Incidents</h3>
          <div className="incident-list">
            {physicalIncidents.map((inc: any) => (
              <div key={inc.id} className={`incident-item sev-${inc.severity}`}>
                <div className="incident-header">
                  <span className={`severity-badge sev-${inc.severity}`}>{inc.severity}</span>
                  <span className="incident-title">{inc.title}</span>
                  <span className="incident-time">{inc.timestamp}</span>
                </div>
                {inc.description && <div className="incident-desc">{inc.description}</div>}
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}
