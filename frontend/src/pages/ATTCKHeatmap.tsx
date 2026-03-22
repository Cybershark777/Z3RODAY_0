import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { api } from '../services/api'
import LoadingSpinner from '../components/LoadingSpinner'

export default function ATTCKHeatmap() {
  const [tooltip, setTooltip] = useState<{ x: number; y: number; text: string } | null>(null)
  const [selectedCell, setSelectedCell] = useState<{ actor: string; tactic: string; count: number } | null>(null)

  const { data, isLoading } = useQuery({
    queryKey: ['mitre-heatmap'],
    queryFn: api.mitreHeatmap,
  })

  if (isLoading) return <LoadingSpinner message="Loading ATT&CK heatmap..." />
  if (!data) return null

  const tactics: any[] = data.tactics ?? []
  const cells: any[] = data.cells ?? []

  // Group cells: actor → tactic → count
  const matrix: Record<string, Record<string, number>> = {}
  const actorSet = new Set<string>()
  for (const c of cells) {
    actorSet.add(c.actor)
    if (!matrix[c.actor]) matrix[c.actor] = {}
    matrix[c.actor][c.tactic_id] = c.count
  }
  const actors = [...actorSet].sort()

  const allCounts = cells.map((c) => c.count)
  const maxCount = Math.max(...allCounts, 1)

  const cellBg = (count: number) => {
    if (count === 0) return 'var(--surface2)'
    const ratio = count / maxCount
    if (ratio >= 0.8) return 'rgba(56,139,253,0.9)'
    if (ratio >= 0.5) return 'rgba(56,139,253,0.6)'
    if (ratio >= 0.25) return 'rgba(56,139,253,0.35)'
    return 'rgba(56,139,253,0.15)'
  }

  return (
    <div className="tab-page">
      <div className="section-header">
        <h2>ATT&amp;CK for ICS Heatmap</h2>
        <p className="section-desc">
          Technique usage per threat actor mapped to ICS tactics. Color intensity = relative technique count.
          Click a cell to inspect.
        </p>
      </div>

      <div className="heatmap-wrapper">
        <table className="heatmap-table">
          <thead>
            <tr>
              <th style={{ textAlign: 'left', minWidth: 130 }}>Actor \ Tactic</th>
              {tactics.map((t) => (
                <th key={t.id} title={t.name}>
                  {t.short_id ?? t.id?.slice(-4)}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {actors.map((actor) => (
              <tr key={actor}>
                <td className="heatmap-actor-label">{actor}</td>
                {tactics.map((tactic) => {
                  const count = matrix[actor]?.[tactic.id] ?? 0
                  return (
                    <td
                      key={tactic.id}
                      style={{ background: cellBg(count), color: count > 0 ? '#fff' : 'var(--border)' }}
                      title={`${actor} / ${tactic.name}: ${count} techniques`}
                      onMouseEnter={(e) => setTooltip({
                        x: e.clientX, y: e.clientY,
                        text: `${actor} → ${tactic.name}: ${count} technique${count !== 1 ? 's' : ''}`,
                      })}
                      onMouseLeave={() => setTooltip(null)}
                      onClick={() => setSelectedCell({ actor, tactic: tactic.name, count })}
                    >
                      {count > 0 ? count : ''}
                    </td>
                  )
                })}
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {tooltip && (
        <div
          className="corr-tooltip"
          style={{ position: 'fixed', left: tooltip.x + 12, top: tooltip.y - 8, zIndex: 200 }}
        >
          {tooltip.text}
        </div>
      )}

      {selectedCell && (
        <div style={{ marginTop: '1rem', padding: '0.75rem 1rem', background: 'var(--surface)', border: '1px solid var(--accent)', borderRadius: 6, fontSize: '0.85rem' }}>
          <strong>{selectedCell.actor}</strong> uses{' '}
          <strong>{selectedCell.count}</strong> technique{selectedCell.count !== 1 ? 's' : ''} in the{' '}
          <strong>{selectedCell.tactic}</strong> tactic.
          <button
            style={{ marginLeft: '1rem', background: 'none', border: 'none', cursor: 'pointer', color: 'var(--text-muted)' }}
            onClick={() => setSelectedCell(null)}
          >✕</button>
        </div>
      )}

      <div style={{ marginTop: '1rem', display: 'flex', gap: '0.75rem', alignItems: 'center', fontSize: '0.78rem', color: 'var(--text-muted)' }}>
        <span>Intensity:</span>
        {[0, 0.25, 0.5, 0.8].map((ratio) => (
          <span key={ratio} style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
            <span style={{ width: 16, height: 16, background: `rgba(56,139,253,${ratio === 0 ? 0.08 : ratio})`, display: 'inline-block', borderRadius: 2 }} />
            {ratio === 0 ? 'None' : `${(ratio * 100).toFixed(0)}%`}
          </span>
        ))}
      </div>
    </div>
  )
}
