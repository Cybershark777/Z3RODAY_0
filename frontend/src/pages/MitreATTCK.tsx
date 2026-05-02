import { useState, useMemo } from 'react'
import { useQuery } from '@tanstack/react-query'
import { api } from '../services/api'
import LoadingSpinner from '../components/LoadingSpinner'
import ErrorMessage from '../components/ErrorMessage'

export default function MitreATTCK() {
  const [search, setSearch] = useState('')
  const [actorFilter, setActorFilter] = useState(false)

  const { data: tactics, isLoading: tLoading, error: tError } = useQuery({
    queryKey: ['mitre-tactics'],
    queryFn: api.mitreTactics,
  })
  const { data: techniques, isLoading: techLoading } = useQuery({
    queryKey: ['mitre-techniques'],
    queryFn: api.mitreTechniques,
  })

  const techByTactic = useMemo(() => {
    const map: Record<string, any[]> = {}
    for (const tech of (techniques ?? [])) {
      if (!map[tech.tactic_id]) map[tech.tactic_id] = []
      map[tech.tactic_id].push(tech)
    }
    return map
  }, [techniques])

  const totalTechniques = (techniques ?? []).length
  const attributedTechniques = useMemo(
    () => (techniques ?? []).filter((t: any) => (t.actor_count ?? 0) > 0).length,
    [techniques]
  )

  const filterTech = (tech: any) => {
    const q = search.toLowerCase()
    if (q && !tech.name?.toLowerCase().includes(q) && !tech.id?.toLowerCase().includes(q)) return false
    if (actorFilter && !(tech.actor_count > 0)) return false
    return true
  }

  if (tLoading || techLoading) return <LoadingSpinner message="Loading MITRE ATT&CK ICS data..." />
  if (tError) return <ErrorMessage message="Failed to load MITRE data" />

  return (
    <div className="tab-page">
      <div className="section-header">
        <h2>MITRE ATT&amp;CK for ICS</h2>
        <p className="section-desc">
          Full ICS tactics and techniques matrix. Green badges show how many tracked threat actors
          use each technique. Click any technique or tactic to view on MITRE ATT&amp;CK.
        </p>
      </div>

      <div style={{ display: 'flex', gap: '1rem', marginBottom: '1.25rem', flexWrap: 'wrap' }}>
        <div className="metric-card" style={{ minWidth: 160 }}>
          <div className="metric-label">Total Techniques</div>
          <div className="metric-value" style={{ fontSize: '1.6rem' }}>{totalTechniques}</div>
          <div className="metric-sub">ICS ATT&CK</div>
        </div>
        <div className="metric-card accent" style={{ minWidth: 160 }}>
          <div className="metric-label">Actor-Attributed</div>
          <div className="metric-value" style={{ fontSize: '1.6rem' }}>{attributedTechniques}</div>
          <div className="metric-sub">observed in the wild</div>
        </div>
        <div className="metric-card" style={{ minWidth: 160 }}>
          <div className="metric-label">Tactics</div>
          <div className="metric-value" style={{ fontSize: '1.6rem' }}>{(tactics ?? []).length}</div>
          <div className="metric-sub">ICS kill chain stages</div>
        </div>
      </div>

      <div style={{ display: 'flex', gap: '0.75rem', marginBottom: '1.25rem', flexWrap: 'wrap', alignItems: 'center' }}>
        <input
          className="intel-select"
          style={{ flex: 1, minWidth: 240 }}
          placeholder="Search by technique ID or name..."
          value={search}
          onChange={(e) => setSearch(e.target.value)}
        />
        <button
          className={`filter-btn${actorFilter ? ' active' : ''}`}
          onClick={() => setActorFilter((v) => !v)}
        >
          {actorFilter ? '✓ Actor-attributed only' : 'Actor-attributed only'}
        </button>
        {(search || actorFilter) && (
          <button className="filter-btn" onClick={() => { setSearch(''); setActorFilter(false) }}>Clear</button>
        )}
      </div>

      <div className="mitre-tactic-grid">
        {(tactics ?? []).map((tactic: any) => {
          const techs = (techByTactic[tactic.id] ?? []).filter(filterTech)
          if (techs.length === 0 && (search || actorFilter)) return null
          return (
            <div key={tactic.id} className="tactic-column">
              <div className="tactic-header">
                <a
                  href={`https://attack.mitre.org/tactics/${tactic.short_id ?? tactic.id}/`}
                  target="_blank"
                  rel="noopener noreferrer"
                  style={{ color: 'inherit', textDecoration: 'none' }}
                  title="View tactic on MITRE ATT&CK"
                >
                  <span className="tactic-id">{tactic.short_id}</span>
                </a>
                <span className="tactic-name">{tactic.name}</span>
                <span className="tactic-count">{techs.length}</span>
              </div>
              <div className="tactic-techniques">
                {techs.map((tech: any) => {
                  const actorCount = tech.actor_count ?? 0
                  const actorList = (tech.actor_names ?? []).join(', ')
                  return (
                    <a
                      key={tech.id}
                      href={`https://attack.mitre.org/techniques/${tech.id}/`}
                      target="_blank"
                      rel="noopener noreferrer"
                      style={{ textDecoration: 'none', display: 'block' }}
                      title={actorCount > 0 ? `Used by: ${actorList}` : tech.description}
                    >
                      <div
                        className="technique-card"
                        style={{
                          borderLeft: actorCount > 0 ? '3px solid var(--accent)' : undefined,
                          opacity: actorCount > 0 ? 1 : 0.65,
                        }}
                      >
                        <span className="technique-id">{tech.id}</span>
                        <span className="technique-name" style={{ flex: 1 }}>{tech.name}</span>
                        {actorCount > 0 && (
                          <span style={{
                            fontSize: '0.62rem',
                            background: 'var(--accent)',
                            color: '#000',
                            borderRadius: 10,
                            padding: '1px 5px',
                            fontWeight: 700,
                            flexShrink: 0,
                            marginLeft: 4,
                          }}>
                            {actorCount}
                          </span>
                        )}
                      </div>
                    </a>
                  )
                })}
              </div>
            </div>
          )
        })}
      </div>

      <div style={{ marginTop: '1rem', fontSize: '0.74rem', color: 'var(--text-muted)' }}>
        Green badge = number of tracked threat actors using this technique. Hover for actor names. All links open MITRE ATT&amp;CK for ICS.
      </div>
    </div>
  )
}
