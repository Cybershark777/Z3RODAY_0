import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { api } from '../services/api'
import LoadingSpinner from '../components/LoadingSpinner'

export default function KillChainBuilder() {
  const [chain, setChain] = useState<any[]>([])
  const [expandedTactic, setExpandedTactic] = useState<string | null>(null)

  const { data, isLoading } = useQuery({
    queryKey: ['kill-chain'],
    queryFn: api.killChain,
  })

  const addToChain = (technique: any, tactic: any) => {
    if (chain.some((s) => s.technique.id === technique.id)) return
    setChain((prev) => [...prev, { tactic, technique }])
  }

  const removeFromChain = (techniqueId: string) => {
    setChain((prev) => prev.filter((s) => s.technique.id !== techniqueId))
  }

  if (isLoading) return <LoadingSpinner message="Loading kill chain techniques..." />

  const stages: any[] = data?.kill_chain ?? []

  return (
    <div className="tab-page">
      <div className="section-header">
        <h2>Kill Chain Builder</h2>
        <p className="section-desc">
          Compose custom ICS/OT attack kill chains using MITRE ATT&amp;CK for ICS techniques.
          Click techniques to add them to your chain.
        </p>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1.5rem' }}>
        {/* Technique Palette */}
        <div>
          <h3 style={{ marginBottom: '1rem', color: 'var(--accent)' }}>Technique Palette</h3>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
            {stages.map((stage: any) => (
              <div key={stage.tactic?.id} className="tactic-accordion">
                <button
                  className="tactic-accordion-header"
                  onClick={() => setExpandedTactic(
                    expandedTactic === stage.tactic?.id ? null : stage.tactic?.id
                  )}
                >
                  <span className="technique-id">{stage.tactic?.short_id}</span>
                  <span>{stage.tactic?.name}</span>
                  <span style={{ marginLeft: 'auto', opacity: 0.6 }}>
                    {(stage.techniques ?? []).length} techniques
                    {expandedTactic === stage.tactic?.id ? ' ▲' : ' ▼'}
                  </span>
                </button>
                {expandedTactic === stage.tactic?.id && (
                  <div className="tactic-accordion-body">
                    {(stage.techniques ?? []).map((tech: any) => (
                      <div
                        key={tech.id}
                        className="technique-card clickable"
                        onClick={() => addToChain(tech, stage.tactic)}
                        style={{
                          opacity: chain.some((s) => s.technique.id === tech.id) ? 0.4 : 1,
                          cursor: 'pointer',
                        }}
                      >
                        <span className="technique-id">{tech.id}</span>
                        <span className="technique-name">{tech.name}</span>
                        <span style={{ marginLeft: 'auto', color: 'var(--accent)' }}>+</span>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>

        {/* Built Chain */}
        <div>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
            <h3 style={{ color: 'var(--accent)' }}>
              Built Chain ({chain.length} steps)
            </h3>
            {chain.length > 0 && (
              <button className="filter-btn" onClick={() => setChain([])}>Clear</button>
            )}
          </div>

          {chain.length === 0 ? (
            <div style={{ padding: '2rem', textAlign: 'center', color: 'var(--text-muted)', border: '1px dashed var(--border)', borderRadius: 8 }}>
              Click techniques from the palette to build your kill chain
            </div>
          ) : (
            <div className="kill-chain-steps">
              {chain.map((step, i) => (
                <div key={step.technique.id} className="kill-chain-step">
                  <div className="step-number">{i + 1}</div>
                  <div className="step-body" style={{ flex: 1 }}>
                    <div className="step-phase">{step.tactic.name}</div>
                    <div className="step-action">
                      <a href={`https://attack.mitre.org/techniques/${step.technique.id}/`} target="_blank" rel="noopener noreferrer" style={{ textDecoration: 'none' }}>
                        <span className="technique-id" style={{ color: 'var(--accent)' }}>{step.technique.id} ↗</span>
                      </a>{' '}{step.technique.name}
                    </div>
                    {step.technique.description && (
                      <div style={{ fontSize: '0.8rem', color: 'var(--text-muted)', marginTop: 4 }}>
                        {step.technique.description.slice(0, 120)}...
                      </div>
                    )}
                  </div>
                  <button
                    onClick={() => removeFromChain(step.technique.id)}
                    style={{ background: 'none', border: 'none', cursor: 'pointer', color: '#ff6b6b', padding: '0 0.5rem' }}
                  >✕</button>
                </div>
              ))}
            </div>
          )}

          {chain.length > 0 && (
            <div style={{ marginTop: '1rem', padding: '0.75rem', background: 'var(--surface)', borderRadius: 6, fontSize: '0.82rem', color: 'var(--text-muted)' }}>
              <strong>Tactics covered:</strong>{' '}
              {[...new Set(chain.map((s) => s.tactic.name))].join(' → ')}
            </div>
          )}

          {chain.length > 0 && (
            <button
              className="export-btn"
              style={{ marginTop: '0.75rem' }}
              onClick={() => {
                const layer = {
                  name: 'CyberShark Kill Chain Export',
                  versions: { attack: '10', navigator: '4.8.2', layer: '4.4' },
                  domain: 'ics-attack',
                  techniques: chain.map((s) => ({
                    techniqueID: s.technique.id,
                    tactic: s.tactic.name?.toLowerCase().replace(/ /g, '-'),
                    color: '#00e676',
                    comment: s.technique.name,
                    enabled: true,
                  })),
                }
                const blob = new Blob([JSON.stringify(layer, null, 2)], { type: 'application/json' })
                const url = URL.createObjectURL(blob)
                const a = document.createElement('a')
                a.href = url
                a.download = 'kill-chain-navigator-layer.json'
                a.click()
                URL.revokeObjectURL(url)
              }}
            >
              ↓ Export MITRE Navigator Layer
            </button>
          )}
        </div>
      </div>
    </div>
  )
}
