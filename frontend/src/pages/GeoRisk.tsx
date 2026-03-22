import { useRef, useEffect, useState } from 'react'
import * as d3 from 'd3'
import * as topojson from 'topojson-client'
import { useQuery } from '@tanstack/react-query'
import { api } from '../services/api'
import LoadingSpinner from '../components/LoadingSpinner'

const ALPHA2_TO_NUM: Record<string, number> = {
  CN: 156, RU: 643, US: 840, IR: 364, KP: 408, UA: 804, DE: 276, GB: 826,
  FR: 250, IL: 376, IN: 356, BR: 76, AU: 36, CA: 124, JP: 392, KR: 410,
  NG: 566, PK: 586, SA: 682, TR: 792, SY: 760, BY: 112, VN: 704, ID: 360,
}

const ROLE_COLORS = {
  origin: d3.scaleLinear<string>().domain([0, 1]).range(['#2d1b1b', '#ff4444']),
  target: d3.scaleLinear<string>().domain([0, 1]).range(['#1b1b2d', '#4477ff']),
  both: d3.scaleLinear<string>().domain([0, 1]).range(['#1b2d1b', '#44ffaa']),
}

export default function GeoRisk() {
  const svgRef = useRef<SVGSVGElement>(null)
  const [view, setView] = useState<'all' | 'origin' | 'target'>('all')
  const [selected, setSelected] = useState<any>(null)

  const { data, isLoading } = useQuery({
    queryKey: ['geo-risk'],
    queryFn: api.geoRisk,
  })

  useEffect(() => {
    if (!data || !svgRef.current) return

    const countries: any[] = data.countries ?? []
    const countryMap: Record<number, any> = {}
    for (const c of countries) {
      const num = ALPHA2_TO_NUM[c.code]
      if (num) countryMap[num] = c
    }

    const width = 900, height = 480
    const svg = d3.select(svgRef.current)
    svg.selectAll('*').remove()
    svg.attr('viewBox', `0 0 ${width} ${height}`)

    const projection = d3.geoNaturalEarth1()
      .scale(155)
      .translate([width / 2, height / 2])
    const path = d3.geoPath(projection)

    const zoom = d3.zoom<SVGSVGElement, unknown>()
      .scaleExtent([0.5, 8])
      .on('zoom', (e) => g.attr('transform', e.transform))
    svg.call(zoom)

    const g = svg.append('g')

    // Sphere
    g.append('path')
      .datum({ type: 'Sphere' } as any)
      .attr('d', path as any)
      .attr('fill', '#0a0f1e')
      .attr('stroke', '#1a2744')

    // Graticule
    g.append('path')
      .datum(d3.geoGraticule()())
      .attr('d', path as any)
      .attr('fill', 'none')
      .attr('stroke', '#1a2744')
      .attr('stroke-width', 0.3)

    fetch('https://cdn.jsdelivr.net/npm/world-atlas@2/countries-110m.json')
      .then((r) => r.json())
      .then((world: any) => {
        const feats = (topojson.feature(world, world.objects.countries) as any).features

        g.selectAll('path.country')
          .data(feats)
          .join('path')
          .attr('class', 'country')
          .attr('d', path as any)
          .attr('stroke', '#1a2744')
          .attr('stroke-width', 0.3)
          .attr('fill', (d: any) => {
            const c = countryMap[+d.id]
            if (!c) return '#1c2340'
            const score = (c.threat_score ?? 50) / 100
            const role = c.role
            if (view === 'origin' && role === 'target') return '#1c2340'
            if (view === 'target' && role === 'origin') return '#1c2340'
            return ROLE_COLORS[role as keyof typeof ROLE_COLORS]?.(score) ?? '#3a6ea5'
          })
          .attr('cursor', (d: any) => countryMap[+d.id] ? 'pointer' : 'default')
          .on('click', (_e, d: any) => {
            const c = countryMap[+d.id]
            if (c) setSelected(c)
          })
          .append('title')
          .text((d: any) => {
            const c = countryMap[+d.id]
            return c ? `${c.name} — ${c.role} (score: ${c.threat_score ?? 'N/A'})` : ''
          })
      })
  }, [data, view])

  if (isLoading) return <LoadingSpinner message="Loading geo risk data..." />

  return (
    <div className="tab-page">
      <div className="section-header">
        <h2>Global Threat Risk Map</h2>
        <p className="section-desc">
          Geographic threat origin and target distribution for ICS/OT cyber attacks.
        </p>
      </div>

      <div className="network-controls">
        {(['all', 'origin', 'target'] as const).map((v) => (
          <button
            key={v}
            className={`filter-btn${view === v ? ' active' : ''}`}
            onClick={() => setView(v)}
          >{v.charAt(0).toUpperCase() + v.slice(1)}</button>
        ))}
        <span style={{ marginLeft: 'auto', fontSize: '0.8rem', color: 'var(--text-muted)' }}>
          <span style={{ color: '#ff4444' }}>■</span> Origin &nbsp;
          <span style={{ color: '#4477ff' }}>■</span> Target &nbsp;
          <span style={{ color: '#44ffaa' }}>■</span> Both
        </span>
      </div>

      <div style={{ display: 'flex', gap: '1rem' }}>
        <svg ref={svgRef} style={{ flex: 1, background: '#0a0f1e', borderRadius: 8 }} />
        {selected && (
          <div className="georisk-detail-panel">
            <div style={{ display: 'flex', justifyContent: 'space-between' }}>
              <h4>{selected.name}</h4>
              <button onClick={() => setSelected(null)} style={{ background: 'none', border: 'none', cursor: 'pointer', color: '#888' }}>✕</button>
            </div>
            <div className="detail-row"><span>Code:</span><span>{selected.code}</span></div>
            <div className="detail-row">
              <span>Role:</span>
              <span className={`severity-badge sev-${selected.role === 'origin' ? 'critical' : 'medium'}`}>
                {selected.role}
              </span>
            </div>
            {selected.threat_score && (
              <div className="detail-row"><span>Threat Score:</span><span>{selected.threat_score}/100</span></div>
            )}
            {selected.targeting_actors?.length > 0 && (
              <div>
                <div style={{ color: 'var(--text-muted)', fontSize: '0.8rem', marginTop: '0.75rem' }}>Known Actors</div>
                {selected.targeting_actors.map((a: string) => (
                  <div key={a} className="ioc-tag">{a}</div>
                ))}
              </div>
            )}
            {selected.notable_incidents?.length > 0 && (
              <div>
                <div style={{ color: 'var(--text-muted)', fontSize: '0.8rem', marginTop: '0.75rem' }}>Notable Incidents</div>
                {selected.notable_incidents.map((inc: string, i: number) => (
                  <div key={i} style={{ fontSize: '0.82rem', padding: '0.2rem 0' }}>• {inc}</div>
                ))}
              </div>
            )}
            {selected.notes && (
              <div style={{ fontSize: '0.82rem', color: 'var(--text-muted)', marginTop: '0.5rem' }}>
                {selected.notes}
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  )
}
