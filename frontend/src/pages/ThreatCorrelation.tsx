import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { api } from '../services/api'
import LoadingSpinner from '../components/LoadingSpinner'
import ErrorMessage from '../components/ErrorMessage'

export default function ThreatCorrelation() {
  const [tooltip, setTooltip] = useState<{ x: number; y: number; text: string } | null>(null)
  const { data, isLoading, error } = useQuery({
    queryKey: ['correlations'],
    queryFn: api.correlations,
  })

  if (isLoading) return <LoadingSpinner message="Computing correlation matrix..." />
  if (error) return <ErrorMessage message="Failed to load correlation data" />

  const labels: any[] = data?.labels ?? []
  const cells: any[] = data?.cells ?? []

  const cellMap: Record<string, number> = {}
  for (const c of cells) cellMap[`${c.threat_a}::${c.threat_b}`] = c.score

  const getColor = (score: number) => {
    const h = Math.round((1 - score) * 120)
    return `hsl(${h}, 70%, 40%)`
  }

  return (
    <div className="tab-page">
      <div className="section-header">
        <h2>Threat Correlation Matrix</h2>
        <p className="section-desc">
          Jaccard similarity between threats based on shared MITRE ATT&amp;CK for ICS techniques.
        </p>
      </div>

      <div className="correlation-wrapper">
        <div className="correlation-matrix" style={{ overflowX: 'auto' }}>
          <table className="corr-table">
            <thead>
              <tr>
                <th />
                {labels.map((l) => (
                  <th key={l.id} className="corr-header" title={l.name}>
                    {l.id}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {labels.map((rowLabel) => (
                <tr key={rowLabel.id}>
                  <td className="corr-row-label" title={rowLabel.name}>
                    {rowLabel.id}
                  </td>
                  {labels.map((colLabel) => {
                    const score = cellMap[`${rowLabel.id}::${colLabel.id}`] ?? 0
                    return (
                      <td
                        key={colLabel.id}
                        className="corr-cell"
                        style={{ background: getColor(score) }}
                        onMouseEnter={(e) =>
                          setTooltip({
                            x: e.clientX,
                            y: e.clientY,
                            text: `${rowLabel.name} ↔ ${colLabel.name}: ${(score * 100).toFixed(1)}%`,
                          })
                        }
                        onMouseLeave={() => setTooltip(null)}
                      >
                        {rowLabel.id === colLabel.id ? '—' : (score * 100).toFixed(0)}
                      </td>
                    )
                  })}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {tooltip && (
        <div
          className="corr-tooltip"
          style={{ position: 'fixed', left: tooltip.x + 12, top: tooltip.y - 8 }}
        >
          {tooltip.text}
        </div>
      )}

      <div className="correlation-legend">
        <span className="legend-label">Low similarity</span>
        <div className="legend-gradient" />
        <span className="legend-label">High similarity</span>
      </div>
    </div>
  )
}
