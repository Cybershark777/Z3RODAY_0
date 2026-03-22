import { useQuery } from '@tanstack/react-query'
import { api } from '../services/api'
import LoadingSpinner from '../components/LoadingSpinner'
import ErrorMessage from '../components/ErrorMessage'

export default function MitreATTCK() {
  const { data: tactics, isLoading: tLoading, error: tError } = useQuery({
    queryKey: ['mitre-tactics'],
    queryFn: api.mitreTactics,
  })
  const { data: techniques, isLoading: techLoading } = useQuery({
    queryKey: ['mitre-techniques'],
    queryFn: api.mitreTechniques,
  })

  if (tLoading || techLoading) return <LoadingSpinner message="Loading MITRE ATT&CK ICS data..." />
  if (tError) return <ErrorMessage message="Failed to load MITRE data" />

  const techByTactic: Record<string, any[]> = {}
  for (const tech of (techniques ?? [])) {
    if (!techByTactic[tech.tactic_id]) techByTactic[tech.tactic_id] = []
    techByTactic[tech.tactic_id].push(tech)
  }

  return (
    <div className="tab-page">
      <div className="section-header">
        <h2>MITRE ATT&amp;CK for ICS</h2>
        <p className="section-desc">
          Tactics and techniques relevant to data center / cyber-physical environments.
        </p>
      </div>
      <div className="mitre-tactic-grid">
        {(tactics ?? []).map((tactic: any) => (
          <div key={tactic.id} className="tactic-column">
            <div className="tactic-header">
              <span className="tactic-id">{tactic.short_id}</span>
              <span className="tactic-name">{tactic.name}</span>
              <span className="tactic-count">{(techByTactic[tactic.id] ?? []).length}</span>
            </div>
            <div className="tactic-techniques">
              {(techByTactic[tactic.id] ?? []).map((tech: any) => (
                <div key={tech.id} className="technique-card" title={tech.description}>
                  <span className="technique-id">{tech.id}</span>
                  <span className="technique-name">{tech.name}</span>
                </div>
              ))}
            </div>
          </div>
        ))}
      </div>
    </div>
  )
}
