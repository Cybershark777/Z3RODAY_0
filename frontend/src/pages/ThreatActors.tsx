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

const NATION_FLAG: Record<string, string> = {
  Russia: '🇷🇺', China: '🇨🇳', Iran: '🇮🇷',
  'North Korea': '🇰🇵', Belarus: '🇧🇾', Unknown: '❓',
}

const RISK_COLOR: Record<string, string> = {
  critical: '#da3633',
  high: '#e3b341',
  medium: '#00e676',
  low: '#4a5568',
}

export default function ThreatActors() {
  const [selectedId, setSelectedId] = useState<string | null>(null)
  const [compareIds, setCompareIds] = useState<string[]>([])
  const [activeTab, setActiveTab] = useState<'profile' | 'campaigns' | 'ttps' | 'iocs'>('profile')
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
    const actorsWithDates = actors.filter((a) => a.active_since || a.first_observed || a.first_seen)
    if (!actorsWithDates.length) return

    const width = timelineRef.current.parentElement?.clientWidth ?? 800
    const rowH = 36
    const marginLeft = 160
    const marginRight = 20
    const height = actorsWithDates.length * rowH + 40

    const svg = d3.select(timelineRef.current)
    svg.selectAll('*').remove()
    svg.attr('width', width).attr('height', height)

    const minYear = 2005, maxYear = 2026
    const xScale = d3.scaleLinear()
      .domain([minYear, maxYear])
      .range([marginLeft, width - marginRight])

    const g = svg.append('g')
    g.append('g')
      .attr('transform', `translate(0,${height - 20})`)
      .call(d3.axisBottom(xScale).ticks(10).tickFormat(d3.format('d')))
      .attr('color', '#4a5568')
      .select('.domain').remove()

    const parseYear = (s: string) => {
      const m = s?.match(/(\d{4})/)
      return m ? parseInt(m[1]) : null
    }

    actorsWithDates.forEach((actor, i) => {
      const y = i * rowH + 16
      const startYear = parseYear(actor.active_since ?? actor.first_seen ?? '') ?? minYear
      const isActive = actor.active !== false
      const endYear = isActive ? maxYear : (parseYear(actor.last_active ?? '') ?? maxYear - 2)
      const x1 = xScale(Math.max(startYear, minYear))
      const x2 = xScale(Math.min(endYear, maxYear))
      const risk = actor.risk_level ?? 'medium'
      const color = RISK_COLOR[risk] ?? '#00e676'

      g.append('text')
        .attr('x', marginLeft - 8)
        .attr('y', y + 6)
        .attr('text-anchor', 'end')
        .attr('font-size', 11)
        .attr('fill', selectedId === actor.id ? 'var(--accent)' : '#6b7280')
        .text(actor.name.slice(0, 20))

      g.append('rect')
        .attr('x', x1).attr('y', y).attr('width', Math.max(x2 - x1, 6)).attr('height', 14)
        .attr('rx', 3)
        .attr('fill', color)
        .attr('opacity', isActive ? 0.8 : 0.4)
        .attr('cursor', 'pointer')
        .on('click', () => { setSelectedId(actor.id); setActiveTab('profile') })
        .append('title').text(`${actor.name}: ${startYear}–${isActive ? 'present' : endYear}`)

      // Active pulse indicator
      if (isActive) {
        g.append('circle')
          .attr('cx', x2).attr('cy', y + 7).attr('r', 4)
          .attr('fill', color)
          .attr('opacity', 0.9)
      }
    })
  }, [actors, selectedId])

  if (isLoading) return <LoadingSpinner message="Loading threat actor intelligence..." />

  const radarData = compareActors.length > 0 ? (() => {
    const tactics = compareActors[0]?.tactic_breakdown ?? []
    const labels = tactics.map((t: any) => t.tactic_name?.slice(0, 12) ?? '')
    return {
      labels,
      datasets: compareActors.map((actor, i) => ({
        label: actor.name,
        data: actor.tactic_breakdown?.map((t: any) => t.count) ?? [],
        backgroundColor: `rgba(${i === 0 ? '0,230,118' : '0,188,212'},0.15)`,
        borderColor: i === 0 ? '#00e676' : '#00bcd4',
        borderWidth: 2,
        pointRadius: 3,
      })),
    }
  })() : null

  return (
    <div className="tab-page">
      <div className="section-header">
        <h2>Threat Actor Intelligence</h2>
        <p className="section-desc">
          Nation-state and criminal APT groups targeting ICS/OT critical infrastructure.
          Sources: Dragos, Mandiant, CISA, Microsoft MSTIC, CrowdStrike.
        </p>
      </div>

      {/* Actor Cards */}
      <div className="actors-grid">
        {actors.map((actor) => {
          const risk = actor.risk_level ?? 'medium'
          const nation = actor.nation_state ?? actor.nation ?? 'Unknown'
          const flag = NATION_FLAG[nation] ?? '🌐'
          return (
            <div
              key={actor.id}
              className={`actor-card${selectedId === actor.id ? ' selected' : ''}`}
              onClick={() => { setSelectedId(selectedId === actor.id ? null : actor.id); setActiveTab('profile') }}
            >
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
                <div className="actor-name">{actor.name}</div>
                <span style={{ fontSize: '1.2rem' }}>{flag}</span>
              </div>
              <div className="actor-meta" style={{ marginTop: '0.4rem' }}>
                <span className={`severity-badge sev-${risk}`}>{risk.toUpperCase()}</span>
                {actor.active === false && (
                  <span className="intel-badge" style={{ color: '#6b7280', borderColor: '#6b7280' }}>Inactive</span>
                )}
                {actor.active !== false && (
                  <span className="intel-badge" style={{ color: '#00e676', borderColor: '#00e676' }}>Active</span>
                )}
              </div>
              <div style={{ marginTop: '0.4rem', fontSize: '0.78rem', color: 'var(--text-muted)' }}>
                {nation} · Since {actor.active_since ?? actor.first_seen}
              </div>
              <div style={{ marginTop: '0.3rem', fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                {actor.technique_count} techniques · {(actor.known_campaigns ?? []).length} campaigns
              </div>
              <button
                className={`filter-btn${compareIds.includes(actor.id) ? ' active' : ''}`}
                style={{ marginTop: '0.6rem', fontSize: '0.72rem' }}
                onClick={(e) => { e.stopPropagation(); toggleCompare(actor.id) }}
              >
                {compareIds.includes(actor.id) ? '✓ Comparing' : 'Compare'}
              </button>
            </div>
          )
        })}
      </div>

      {/* Detail Panel */}
      {selected && (
        <div className="actor-detail-panel">
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
              <span style={{ fontSize: '1.8rem' }}>
                {NATION_FLAG[selected.nation_state ?? selected.nation ?? ''] ?? '🌐'}
              </span>
              <div>
                <h3 style={{ marginBottom: '0.2rem' }}>{selected.name}</h3>
                <div style={{ display: 'flex', gap: '0.4rem', flexWrap: 'wrap' }}>
                  {(selected.aliases ?? []).slice(0, 4).map((alias: string) => (
                    <span key={alias} className="intel-badge" style={{ fontSize: '0.7rem' }}>{alias}</span>
                  ))}
                  {(selected.aliases ?? []).length > 4 && (
                    <span className="intel-badge" style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>
                      +{selected.aliases.length - 4} more
                    </span>
                  )}
                </div>
              </div>
            </div>
            <button className="filter-btn" onClick={() => setSelectedId(null)}>✕ Close</button>
          </div>

          {/* Sub-tabs */}
          <div className="filters" style={{ marginBottom: '1.25rem' }}>
            {(['profile', 'campaigns', 'ttps', 'iocs'] as const).map((tab) => (
              <button
                key={tab}
                className={`filter-btn${activeTab === tab ? ' active' : ''}`}
                onClick={() => setActiveTab(tab)}
              >
                {tab === 'profile' ? 'Profile' : tab === 'campaigns' ? `Campaigns (${(selected.known_campaigns ?? []).length})` : tab === 'ttps' ? 'TTPs' : `IOCs (${(selected.iocs ?? []).length})`}
              </button>
            ))}
          </div>

          {/* Profile Tab */}
          {activeTab === 'profile' && (
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '2rem' }}>
              <div>
                {[
                  ['Nation State', selected.nation_state ?? selected.nation],
                  ['Category', selected.category],
                  ['Motivation', selected.motivation],
                  ['Active Since', selected.active_since ?? selected.first_seen],
                  ['Status', selected.active === false ? 'Inactive / Dormant' : 'Active'],
                ].filter(([, v]) => v).map(([label, value]) => (
                  <div key={label as string} className="detail-row">
                    <span>{label}</span>
                    <span style={{ color: label === 'Status' && value === 'Active' ? '#00e676' : undefined }}>
                      {value as string}
                    </span>
                  </div>
                ))}

                {(selected.target_sectors ?? selected.targeted_sectors ?? []).length > 0 && (
                  <div style={{ marginTop: '1rem' }}>
                    <div style={{ fontSize: '0.78rem', color: 'var(--text-muted)', marginBottom: '0.5rem' }}>Target Sectors</div>
                    <div style={{ display: 'flex', gap: '0.4rem', flexWrap: 'wrap' }}>
                      {(selected.target_sectors ?? selected.targeted_sectors).map((s: string) => (
                        <span key={s} className="ioc-tag">{s}</span>
                      ))}
                    </div>
                  </div>
                )}

                {(selected.regions ?? selected.targeted_regions ?? []).length > 0 && (
                  <div style={{ marginTop: '1rem' }}>
                    <div style={{ fontSize: '0.78rem', color: 'var(--text-muted)', marginBottom: '0.5rem' }}>Targeted Regions</div>
                    <div style={{ display: 'flex', gap: '0.4rem', flexWrap: 'wrap' }}>
                      {(selected.regions ?? selected.targeted_regions).map((r: string) => (
                        <span key={r} className="intel-badge">{r}</span>
                      ))}
                    </div>
                  </div>
                )}

                {selected.description && (
                  <div style={{ marginTop: '1rem', fontSize: '0.82rem', lineHeight: 1.6, color: 'var(--text-muted)', borderLeft: '2px solid var(--accent)', paddingLeft: '0.75rem' }}>
                    {selected.description}
                  </div>
                )}

                {selected.source_note && (
                  <div style={{ marginTop: '1rem', fontSize: '0.72rem', color: '#6b7280', paddingTop: '0.75rem', borderTop: '1px solid var(--border)' }}>
                    <strong style={{ color: 'var(--text-muted)' }}>Sources: </strong>{selected.source_note}
                  </div>
                )}
              </div>

              {/* Tactic Breakdown Chart */}
              <div>
                <h4 style={{ marginBottom: '1rem', color: 'var(--text-muted)', fontSize: '0.88rem' }}>
                  ATT&amp;CK ICS Tactic Breakdown
                </h4>
                {(selected.tactic_breakdown ?? []).some((t: any) => t.count > 0) ? (
                  <div style={{ height: 240 }}>
                    <Bar
                      data={{
                        labels: selected.tactic_breakdown
                          .filter((t: any) => t.count > 0)
                          .map((t: any) => t.tactic_name?.slice(0, 14)),
                        datasets: [{
                          label: 'Techniques',
                          data: selected.tactic_breakdown
                            .filter((t: any) => t.count > 0)
                            .map((t: any) => t.count),
                          backgroundColor: 'rgba(0,230,118,0.6)',
                          borderColor: '#00e676',
                          borderWidth: 1,
                          borderRadius: 3,
                        }],
                      }}
                      options={{
                        responsive: true,
                        maintainAspectRatio: false,
                        plugins: { legend: { display: false } },
                        scales: {
                          x: { ticks: { color: '#4a5568', font: { size: 9 } }, grid: { color: '#1c1c1c' } },
                          y: { ticks: { color: '#4a5568' }, grid: { color: '#1c1c1c' } },
                        },
                      }}
                    />
                  </div>
                ) : (
                  <div style={{ fontSize: '0.82rem', color: 'var(--text-muted)', marginTop: '1rem' }}>
                    Technique-to-tactic mapping requires ICS ATT&CK data in the database.
                    <br /><br />
                    <strong style={{ color: 'var(--text)' }}>{selected.technique_count} ICS ATT&CK techniques</strong> attributed to this actor.
                    <div style={{ marginTop: '0.75rem', display: 'flex', gap: '0.3rem', flexWrap: 'wrap' }}>
                      {(selected.mitre_techniques ?? selected.techniques ?? []).slice(0, 12).map((id: string) => (
                        <a
                          key={id}
                          href={`https://attack.mitre.org/techniques/${id}/`}
                          target="_blank"
                          rel="noopener noreferrer"
                          style={{ textDecoration: 'none' }}
                        >
                          <code style={{ fontSize: '0.7rem', color: 'var(--accent)', opacity: 0.85 }}
                            onMouseEnter={e => (e.currentTarget.style.opacity = '1')}
                            onMouseLeave={e => (e.currentTarget.style.opacity = '0.85')}
                          >{id} ↗</code>
                        </a>
                      ))}
                      {(selected.mitre_techniques ?? selected.techniques ?? []).length > 12 && (
                        <span style={{ fontSize: '0.72rem', color: 'var(--text-muted)' }}>
                          +{(selected.mitre_techniques ?? selected.techniques).length - 12} more
                        </span>
                      )}
                    </div>
                  </div>
                )}
              </div>
            </div>
          )}

          {/* Campaigns Tab */}
          {activeTab === 'campaigns' && (
            <div>
              {(selected.known_campaigns ?? []).length === 0 ? (
                <div className="error-state">No campaigns documented</div>
              ) : (
                <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
                  {(selected.known_campaigns ?? []).map((c: any, i: number) => {
                    const isObj = typeof c === 'object' && c !== null
                    const name = isObj ? c.name : c
                    const year = isObj ? c.year : null
                    const desc = isObj ? c.description : null
                    const impact = isObj ? c.impact : null
                    return (
                      <div key={i} style={{ padding: '1rem', background: 'var(--surface2)', borderRadius: 6, borderLeft: '3px solid var(--accent)' }}>
                        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '0.5rem' }}>
                          <strong style={{ fontSize: '0.9rem' }}>{name}</strong>
                          {year && <span className="intel-badge">{year}</span>}
                        </div>
                        {desc && (
                          <div style={{ fontSize: '0.82rem', color: 'var(--text-muted)', lineHeight: 1.6, marginBottom: impact ? '0.5rem' : 0 }}>
                            {desc}
                          </div>
                        )}
                        {impact && (
                          <div style={{ fontSize: '0.8rem', padding: '0.4rem 0.6rem', background: 'rgba(218,54,51,0.08)', border: '1px solid rgba(218,54,51,0.2)', borderRadius: 4, marginTop: '0.5rem' }}>
                            <strong style={{ color: '#da3633' }}>Impact: </strong>
                            <span style={{ color: 'var(--text-muted)' }}>{impact}</span>
                          </div>
                        )}
                      </div>
                    )
                  })}
                </div>
              )}
            </div>
          )}

          {/* TTPs Tab */}
          {activeTab === 'ttps' && (
            <div>
              {selected.ttp_summary && (
                <div style={{ marginBottom: '1.5rem', padding: '1rem', background: 'var(--surface2)', borderRadius: 6, borderLeft: '3px solid var(--accent)', fontSize: '0.85rem', lineHeight: 1.7, color: 'var(--text-muted)' }}>
                  {selected.ttp_summary}
                </div>
              )}
              <div style={{ marginBottom: '0.75rem', fontSize: '0.78rem', color: 'var(--text-muted)' }}>
                All ATT&CK ICS Techniques — click to view on MITRE ATT&CK
              </div>
              <div style={{ display: 'flex', gap: '0.4rem', flexWrap: 'wrap' }}>
                {(selected.mitre_techniques ?? selected.techniques ?? []).map((id: string) => (
                  <a
                    key={id}
                    href={`https://attack.mitre.org/techniques/${id}/`}
                    target="_blank"
                    rel="noopener noreferrer"
                    style={{ textDecoration: 'none' }}
                  >
                    <code
                      style={{ fontSize: '0.75rem', color: 'var(--accent)', opacity: 0.85, cursor: 'pointer' }}
                      onMouseEnter={e => (e.currentTarget.style.opacity = '1')}
                      onMouseLeave={e => (e.currentTarget.style.opacity = '0.85')}
                    >{id} ↗</code>
                  </a>
                ))}
              </div>
            </div>
          )}

          {/* IOCs Tab */}
          {activeTab === 'iocs' && (
            <div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '0.4rem' }}>
                {(selected.iocs ?? []).map((ioc: string, i: number) => (
                  <div key={i} style={{ display: 'flex', gap: '0.5rem', alignItems: 'flex-start', padding: '0.5rem 0.75rem', background: 'var(--surface2)', borderRadius: 4, fontSize: '0.82rem' }}>
                    <span style={{ color: 'var(--accent)', flexShrink: 0, marginTop: 1 }}>◆</span>
                    <span style={{ color: 'var(--text-muted)', lineHeight: 1.5 }}>{ioc}</span>
                  </div>
                ))}
              </div>
              {selected.source_note && (
                <div style={{ marginTop: '1.25rem', fontSize: '0.72rem', color: '#6b7280', paddingTop: '0.75rem', borderTop: '1px solid var(--border)' }}>
                  <strong style={{ color: 'var(--text-muted)' }}>Sources: </strong>{selected.source_note}
                </div>
              )}

              {/* STIX 2.1 Export */}
              <div style={{ marginTop: '1.25rem', paddingTop: '1rem', borderTop: '1px solid var(--border)' }}>
                <div style={{ fontSize: '0.74rem', color: 'var(--text-muted)', marginBottom: '0.5rem' }}>
                  Export this actor as a <strong>STIX 2.1 Bundle</strong> (Intrusion Set + Attack Patterns + Relationships) for use with MISP, OpenCTI, or Splunk SIEM.
                </div>
                <button
                  className="export-btn"
                  onClick={async () => {
                    try {
                      const res = await fetch(`/api/stix/actor/${selected.id}`)
                      const bundle = await res.json()
                      const blob = new Blob([JSON.stringify(bundle, null, 2)], { type: 'application/json' })
                      const url = URL.createObjectURL(blob)
                      const a = document.createElement('a')
                      a.href = url
                      a.download = `stix-${selected.id}.json`
                      a.click()
                      URL.revokeObjectURL(url)
                    } catch (e) {
                      console.error('STIX export failed', e)
                    }
                  }}
                >
                  ↓ Export STIX 2.1 Bundle
                </button>
              </div>
            </div>
          )}
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
                plugins: { legend: { labels: { color: '#4a5568' } } },
                scales: {
                  r: {
                    ticks: { color: '#4a5568', backdropColor: 'transparent' },
                    grid: { color: '#1c1c1c' },
                    pointLabels: { color: '#4a5568', font: { size: 9 } },
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
        <p style={{ fontSize: '0.78rem', color: 'var(--text-muted)', marginBottom: '0.75rem' }}>
          Red = nation-state critical · Yellow = high · Green = medium · Solid dot = currently active
        </p>
        <svg ref={timelineRef} style={{ width: '100%', overflow: 'visible' }} />
      </div>
    </div>
  )
}
