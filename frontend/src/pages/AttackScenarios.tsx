import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { api } from '../services/api'
import LoadingSpinner from '../components/LoadingSpinner'
import ErrorMessage from '../components/ErrorMessage'

export default function AttackScenarios() {
  const [selectedId, setSelectedId] = useState<string | null>(null)
  const { data: scenarios, isLoading, error } = useQuery({
    queryKey: ['scenarios'],
    queryFn: api.scenarios,
  })

  if (isLoading) return <LoadingSpinner message="Loading attack scenarios..." />
  if (error) return <ErrorMessage message="Failed to load scenarios" />

  const selected = (scenarios ?? []).find((s: any) => s.id === selectedId)

  return (
    <div className="tab-page">
      <div className="section-header">
        <h2>IT→OT Attack Kill Chains</h2>
        <p className="section-desc">
          Multi-stage attack scenarios traversing the Purdue Reference Model from enterprise IT to physical process.
        </p>
      </div>
      <div className="scenarios-layout">
        <div className="scenario-card-list">
          {(scenarios ?? []).map((s: any) => (
            <div
              key={s.id}
              className={`scenario-card${selectedId === s.id ? ' active' : ''}`}
              onClick={() => setSelectedId(s.id)}
            >
              <div className="scenario-card-title">{s.name}</div>
              <div className="scenario-card-meta">
                <span className={`severity-badge sev-${s.severity?.toLowerCase()}`}>{s.severity}</span>
                <span className="scenario-steps">{s.steps?.length ?? 0} steps</span>
              </div>
            </div>
          ))}
        </div>
        <div className="scenario-detail-panel">
          {selected ? (
            <div>
              <h3>{selected.name}</h3>
              <p className="section-desc">{selected.description}</p>
              <div className="kill-chain-steps">
                {(selected.steps ?? []).map((step: any, i: number) => (
                  <div key={i} className="kill-chain-step">
                    <div className="step-number">{i + 1}</div>
                    <div className="step-body">
                      <div className="step-phase">{step.phase}</div>
                      <div className="step-action">{step.action}</div>
                      {step.technique && (
                        <div className="step-technique">
                          <span className="technique-id">{step.technique}</span>
                        </div>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          ) : (
            <div className="scenario-placeholder">
              <p>Select a scenario to view the kill chain</p>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
