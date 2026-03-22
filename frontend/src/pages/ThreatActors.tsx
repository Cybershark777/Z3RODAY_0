import { useRef, useEffect, useState } from 'react'
import * as d3 from 'd3'
import { useQuery } from '@tanstack/react-query'
import {
  Chart as ChartJS, CategoryScale, LinearScale, BarElement,
  RadialLinearScale, PointElement, LineElement, Filler, Title, Tooltip, Legend,
} from 'chart.js'
import { Bar, Radar } from 'react-chartjs-2'
import { api } from '../services/api'
import LoadingSpinner from '../components/LoadingSpinner'

ChartJS.register(CategoryScale, LinearScale, BarElement, RadialLinearScale, PointElement, LineElement, Filler, Title, Tooltip, Legend)

export default function ThreatActors() {
  const [selectedId, setSelectedId] = useState<string | null>(null)
  const [compareIds, setCompareIds] = useState<string[]>([])
  const timelineRef = useRef<SVGSVGElement>(null)

  const { data, isLoading } = useQuery({
    queryKey: ['threat-actors'],
    queryFn: api.threatActors,
  })

  const actors: any[] = data?.threat_actors ?? []
  const selected = actors.find((a) => a.id === selectedId)
  const compareActors = actors.filter((a) => compareIds.includes(a.id))

  const toggleCompare = (id: string) => {
    setCompareIds((prev) =>
      prev.includes(id) ? prev.filter((x) => x !== id) : prev.length < 2 ? [...prev, id] : prev
    )
  }

  // D3 timeline
  useEffect(() => {
    if (!actors.length || !timelineRef.current) return
    const actorsWithDates = actors.filter((a) => a.active_since || a.first_observed)
    if (!actorsWithDates.length) return

    const width = timelineRef.current.parentElement?.clientWidth ?? 800
    const rowH = 36
    const marginLeft = 140
    const marginRight = 20
    const height = actorsWithDates.length * rowH + 40

    const svg = d3.select(timelineRef.current)
    svg.selectAll('*').remove()
    svg.attr('width', width).attr('height', height)

    const minYear = 2005, maxYear = 2025
    const xScale = d3.scaleLinear()
      .domain([minYear, maxYear])
      .range([marginLeft, width - marginRight])

    // Year axis
    const g = svg.append('g')
    g.append('g')
      .attr('transform', `translate(0,${height - 20})`)
      .call(d3.axisBottom(xScale).ticks(10).tickFormat(d3.format('d')))
      .attr('color', '#8b949e')
      .select('.domain').remove()

    const parseYear = (s: string) => {
      const m = s?.match(/(\d{4})/)
      return m ? parseInt(m[1]) : null
    }

    actorsWithDates.forEach((actor, i) => {
      const y = i * rowH + 16
      const startYear = parseYear(actor.active_since ?? actor.first_observed) ?? minYear
      const endYear = actor.last_active ? (parseYear(actor.last_active) ?? maxYear) : maxYear
      const x1 = xScale(Math.max(startYear, minYear))
      const x2 = xScale(Math.min(endYear, maxYear))

      g.append('text')
        .attr('x', marginLeft - 8)
        .attr('y', y + 6)
        .attr('text-anchor', 'end')
        .attr('font-size', 11)
        .attr('fill', selectedId === actor.id ? '#388bfd' : '#8b949e')
        .text(actor.name.slice(0, 18))

      g.append('rect')
        .attr('x', x1).attr('y', y).attr('width', Math.max(x2 - x1, 6)).attr('height', 14)
        .attr('rx', 3)
        .attr('fill', actor.category === 'nation-state' ? '#ff6b6b' : '#388bfd')
        .attr('opacity', 0.7)
        .attr('cursor', 'pointer')
        .on('click', () => setSelectedId(actor.id))
        .append('title').text(`${actor.name}: ${startYear}–${endYear === maxYear ? 'present' : endYear}`)
    })
  }, [actors, selectedId])

  if (isLoading) return <LoadingSpinner message="Loading threat actor intelligence..." />

  // Radar chart data for comparison
  const getRadarData = (actorList: any[]) => {
    if (!actorList.length) return null
    const tactics = actorList[0]?.tactic_breakdown ?? []
    const labels = tactics.map((t: any) => t.tactic_name?.slice(0, 12) ?? '')
    return {
      labels,
      datasets: actorList.map((actor, i) => ({
        label: actor.name,
        data: actor.tactic_breakdown?.map((t: any) => t.count) ?? [],
        backgroundColor: `rgba(${i === 0 ? '56,139,253' : '188,140,255'},0.2)`,
        borderColor: i === 0 ? '#388bfd' : '#bc8cff',
        borderWidth: 2,
        pointRadius: 3,
      })),
    }
  }

  const radarData = compareActors.length > 0 ? getRadarData(compareActors) : null

  return (
    <div className="tab-page">
      <div className="section-header">
        <h2>Threat Actor Intelligence</h2>
        <p className="section-desc">
          Nation-state and criminal APT groups targeting ICS/OT critical infrastructure.
          Click actors to compare. Select up to 2 for radar comparison.
        </p>
      </div>

      {/* Actor Cards */}
      <div className="actors-grid">
        {actors.map((actor) => (
          <div
            key={actor.id}
            className={`actor-card${selectedId === actor.id ? ' selected' : ''}`}
            onClick={() => setSelectedId(selectedId === actor.id ? null : actor.id)}
          >
            <div className="actor-name">{actor.name}</div>
            <div className="actor-meta">
              {actor.nation_state && <span>{actor.nation_state}</span>}
              {actor.category && (
                <span className={`severity-badge ${actor.category === 'nation-state' ? 'sev-critical' : 'sev-medium'}`}>
                  {actor.category}
                </span>
              )}
              {actor.active_since && <span>Since {actor.active_since}</span>}
            </div>
            <div style={{ marginTop: '0.5rem', fontSize: '0.78rem', color: 'var(--text-muted)' }}>
              {actor.technique_count} techniques
            </div>
            <button
              className={`filter-btn${compareIds.includes(actor.id) ? ' active' : ''}`}
              style={{ marginTop: '0.5rem', fontSize: '0.72rem' }}
              onClick={(e) => { e.stopPropagation(); toggleCompare(actor.id) }}
            >
              {compareIds.includes(actor.id) ? '✓ Comparing' : 'Compare'}
            </button>
          </div>
        ))}
      </div>

      {/* Detail Panel */}
      {selected && (
        <div className="actor-detail-panel">
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '2rem' }}>
            {/* Left: Profile */}
            <div>
              <h3 style={{ marginBottom: '1rem' }}>{selected.name}</h3>
              {[
                ['Nation State', selected.nation_state],
                ['Category', selected.category],
                ['Motivation', selected.motivation],
                ['Active Since', selected.active_since],
                ['Aliases', selected.aliases?.join(', ')],
              ].filter(([, v]) => v).map(([label, value]) => (
                <div key={label as string} className="detail-row">
                  <span>{label}</span>
                  <span>{value as string}</span>
                </div>
              ))}

              {selected.target_sectors?.length > 0 && (
                <div style={{ marginTop: '1rem' }}>
                  <div style={{ fontSize: '0.78rem', color: 'var(--text-muted)', marginBottom: '0.5rem' }}>
                    Target Sectors
                  </div>
                  <div style={{ display: 'flex', gap: '0.4rem', flexWrap: 'wrap' }}>
                    {selected.target_sectors.map((s: string) => (
                      <span key={s} className="ioc-tag">{s}</span>
                    ))}
                  </div>
                </div>
              )}

              {selected.known_campaigns?.length > 0 && (
                <div style={{ marginTop: '1rem' }}>
                  <div style={{ fontSize: '0.78rem', color: 'var(--text-muted)', marginBottom: '0.5rem' }}>
                    Known Campaigns
                  </div>
                  {selected.known_campaigns.map((c: string) => (
                    <div key={c} style={{ fontSize: '0.82rem', padding: '0.2rem 0' }}>• {c}</div>
                  ))}
                </div>
              )}

              {selected.iocs?.length > 0 && (
                <div style={{ marginTop: '1rem' }}>
                  <div style={{ fontSize: '0.78rem', color: 'var(--text-muted)', marginBottom: '0.5rem' }}>
                    IOCs / Indicators
                  </div>
                  <div style={{ display: 'flex', gap: '0.3rem', flexWrap: 'wrap' }}>
                    {selected.iocs.map((ioc: string) => (
                      <span key={ioc} className="ioc-tag">{ioc}</span>
                    ))}
                  </div>
                </div>
              )}
            </div>

            {/* Right: Tactic Breakdown Chart */}
            <div>
              <h4 style={{ marginBottom: '1rem', color: 'var(--text-muted)', fontSize: '0.88rem' }}>
                ATT&amp;CK Tactic Breakdown
              </h4>
              {selected.tactic_breakdown?.length > 0 && (
                <div style={{ height: 240 }}>
                  <Bar
                    data={{
                      labels: selected.tactic_breakdown.map((t: any) => t.tactic_name?.slice(0, 12)),
                      datasets: [{
                        label: 'Techniques',
                        data: selected.tactic_breakdown.map((t: any) => t.count),
                        backgroundColor: 'rgba(56,139,253,0.7)',
                      }],
                    }}
                    options={{
                      responsive: true,
                      maintainAspectRatio: false,
                      plugins: { legend: { display: false } },
                      scales: {
                        x: { ticks: { color: '#8b949e', font: { size: 9 } }, grid: { color: '#30363d' } },
                        y: { ticks: { color: '#8b949e' }, grid: { color: '#30363d' } },
                      },
                    }}
                  />
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      {/* Comparison Radar */}
      {radarData && (
        <div className="ml-chart-section" style={{ marginTop: '1.5rem' }}>
          <h3>Actor Comparison: {compareActors.map((a) => a.name).join(' vs ')}</h3>
          <div style={{ height: 320, maxWidth: 500 }}>
            <Radar
              data={radarData}
              options={{
                responsive: true,
                maintainAspectRatio: false,
                plugins: { legend: { labels: { color: '#8b949e' } } },
                scales: {
                  r: {
                    ticks: { color: '#8b949e', backdropColor: 'transparent' },
                    grid: { color: '#30363d' },
                    pointLabels: { color: '#8b949e', font: { size: 9 } },
                  },
                },
              }}
            />
          </div>
        </div>
      )}

      {/* Campaign Timeline */}
      <div className="ml-chart-section" style={{ marginTop: '1.5rem' }}>
        <h3>Actor Activity Timeline</h3>
        <svg ref={timelineRef} style={{ width: '100%', overflow: 'visible' }} />
      </div>
    </div>
  )
}
