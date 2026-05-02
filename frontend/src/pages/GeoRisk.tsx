import { useRef, useEffect, useState } from 'react'
import * as d3 from 'd3'
import * as topojson from 'topojson-client'
import { useQuery } from '@tanstack/react-query'
import { api } from '../services/api'
import LoadingSpinner from '../components/LoadingSpinner'

const ALPHA2_TO_NUM: Record<string, number> = {
  CN: 156, RU: 643, US: 840, IR: 364, KP: 408, UA: 804, DE: 276, GB: 826,
  FR: 250, IL: 376, IN: 356, BR: 76,  AU: 36,  CA: 124, JP: 392, KR: 410,
  NG: 566, PK: 586, SA: 682, TR: 792, SY: 760, BY: 112, VN: 704, ID: 360,
  AE: 784, BH: 48,  TW: 158, NL: 528,
}

const ROLE_COLORS = {
  threat_origin: d3.scaleLinear<string>().domain([0, 1]).range(['#2d1b1b', '#ff4444']),
  threat_target: d3.scaleLinear<string>().domain([0, 1]).range(['#1b1b2d', '#4477ff']),
  both:          d3.scaleLinear<string>().domain([0, 1]).range(['#1b2d1b', '#44ffaa']),
  // fallback aliases
  origin: d3.scaleLinear<string>().domain([0, 1]).range(['#2d1b1b', '#ff4444']),
  target: d3.scaleLinear<string>().domain([0, 1]).range(['#1b1b2d', '#4477ff']),
}

const CRIT_INFRA_SECTORS = new Set([
  'energy', 'water', 'oil_gas', 'nuclear', 'transportation',
  'telecommunications', 'power_grid', 'data_center', 'port_infrastructure',
  'petrochemical', 'semiconductor', 'chemicals',
])

const DATA_CENTER_SECTORS = new Set([
  'data_center', 'telecommunications', 'cloud', 'semiconductor',
])

type ViewMode = 'all' | 'origin' | 'target' | 'critical'

export default function GeoRisk() {
  const svgRef = useRef<SVGSVGElement>(null)
  const [view, setView] = useState<ViewMode>('all')
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

    const width = 900, height = 500
    const cx = width / 2, cy = height / 2
    const radius = 220

    const svg = d3.select(svgRef.current)
    svg.selectAll('*').remove()
    svg.attr('viewBox', `0 0 ${width} ${height}`)

    // Inject pulse animation
    const styleEl = document.getElementById('globe-pulse-style') ?? document.createElement('style')
    styleEl.id = 'globe-pulse-style'
    styleEl.textContent = `
      @keyframes globe-pulse {
        0%   { r: 6px;  opacity: 0.9; }
        70%  { r: 18px; opacity: 0.0; }
        100% { r: 6px;  opacity: 0.0; }
      }
      @keyframes globe-pulse-data {
        0%   { r: 5px;  opacity: 0.8; }
        70%  { r: 14px; opacity: 0.0; }
        100% { r: 5px;  opacity: 0.0; }
      }
      .crit-ring { animation: globe-pulse 2s ease-out infinite; }
      .data-ring { animation: globe-pulse-data 1.6s ease-out infinite 0.4s; }
    `
    if (!document.getElementById('globe-pulse-style')) document.head.appendChild(styleEl)

    // Radial glow
    const defs = svg.append('defs')
    const radialGrad = defs.append('radialGradient').attr('id', 'globe-glow')
    radialGrad.append('stop').attr('offset', '0%').attr('stop-color', '#1a3a6e').attr('stop-opacity', 0.6)
    radialGrad.append('stop').attr('offset', '100%').attr('stop-color', '#0a0f1e').attr('stop-opacity', 0)
    svg.append('ellipse')
      .attr('cx', cx).attr('cy', cy + radius * 0.05)
      .attr('rx', radius * 1.15).attr('ry', radius * 0.18)
      .attr('fill', 'url(#globe-glow)')

    const projection = d3.geoOrthographic()
      .scale(radius)
      .translate([cx, cy])
      .clipAngle(90)
      .rotate([0, -20])

    const path = d3.geoPath(projection)
    const graticule = d3.geoGraticule()

    const g = svg.append('g')

    // Ocean sphere
    const sphere = g.append('path')
      .datum({ type: 'Sphere' } as any)
      .attr('d', path as any)
      .attr('fill', '#071020')
      .attr('stroke', '#2244aa')
      .attr('stroke-width', 1.5)

    // Graticule lines
    const graticuleEl = g.append('path')
      .datum(graticule())
      .attr('d', path as any)
      .attr('fill', 'none')
      .attr('stroke', '#1a2744')
      .attr('stroke-width', 0.3)

    // Tooltip
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    let tooltip: any = d3.select<HTMLDivElement, unknown>('#globe-tooltip')
    if (tooltip.empty()) {
      tooltip = d3.select(svgRef.current!.parentElement!)
        .append('div')
        .attr('id', 'globe-tooltip')
        .style('position', 'absolute')
        .style('pointer-events', 'none')
        .style('background', 'rgba(10,15,30,0.92)')
        .style('border', '1px solid #1e3a6e')
        .style('border-radius', '6px')
        .style('padding', '6px 10px')
        .style('font-size', '0.78rem')
        .style('color', '#cdd6f4')
        .style('display', 'none')
        .style('z-index', '10')
    }

    fetch('https://cdn.jsdelivr.net/npm/world-atlas@2/countries-110m.json')
      .then((r) => r.json())
      .then((world: any) => {
        const feats = (topojson.feature(world, world.objects.countries) as any).features

        const isCritInfra = (c: any) => {
          const sectors: string[] = c?.primary_sectors ?? []
          return sectors.some((s) => CRIT_INFRA_SECTORS.has(s))
        }
        const isDataCenter = (c: any) => {
          const sectors: string[] = c?.primary_sectors ?? []
          return sectors.some((s) => DATA_CENTER_SECTORS.has(s))
        }

        const getFill = (d: any) => {
          const c = countryMap[+d.id]
          if (!c) return view === 'critical' ? '#0e1830' : '#1a2d5a'
          const score = (c.threat_score ?? 50) / 100
          const role: string = c.role ?? ''

          if (view === 'origin' && role !== 'threat_origin' && role !== 'origin') return '#1a2d5a'
          if (view === 'target' && role !== 'threat_target' && role !== 'target') return '#1a2d5a'
          if (view === 'critical') {
            if (!isCritInfra(c)) return '#0e1830'
            // Bright orange-amber for critical infra
            return c.threat_level === 'critical' ? '#ff6600' : '#cc8800'
          }

          const colorKey = (role === 'threat_origin' || role === 'origin') ? 'origin'
            : (role === 'threat_target' || role === 'target') ? 'target'
            : 'both'
          return ROLE_COLORS[colorKey as keyof typeof ROLE_COLORS]?.(score) ?? '#3a6ea5'
        }

        const getStroke = (d: any) => {
          const c = countryMap[+d.id]
          if (!c || view !== 'critical') return '#1a2744'
          if (isCritInfra(c)) return c.threat_level === 'critical' ? '#ffaa00' : '#cc6600'
          return '#1a2744'
        }

        const getStrokeWidth = (d: any) => {
          const c = countryMap[+d.id]
          if (c && view === 'critical' && isCritInfra(c)) return 1.2
          return 0.3
        }

        const countryPaths = g.selectAll<SVGPathElement, any>('path.country')
          .data(feats)
          .join('path')
          .attr('class', 'country')
          .attr('d', path as any)
          .attr('stroke', getStroke)
          .attr('stroke-width', getStrokeWidth)
          .attr('fill', getFill)
          .attr('cursor', (d: any) => countryMap[+d.id] ? 'pointer' : 'default')
          .on('mouseover', function (event, d: any) {
            const c = countryMap[+d.id]
            if (!c) return
            d3.select(this).attr('stroke', '#aabbff').attr('stroke-width', 1.5)
            const parentRect = svgRef.current!.parentElement!.getBoundingClientRect()
            const sectors: string[] = c.primary_sectors ?? []
            const critSectors = sectors.filter((s) => CRIT_INFRA_SECTORS.has(s))
            const dataSectors = sectors.filter((s) => DATA_CENTER_SECTORS.has(s))
            tooltip
              .style('display', 'block')
              .style('left', `${event.clientX - parentRect.left + 12}px`)
              .style('top', `${event.clientY - parentRect.top - 10}px`)
              .html(`
                <strong>${c.name}</strong><br/>
                Role: ${c.role ?? 'N/A'} &nbsp;|&nbsp; Score: <strong>${c.threat_score ?? 'N/A'}/100</strong><br/>
                Threat Level: <span style="color:${c.threat_level === 'critical' ? '#ff4444' : c.threat_level === 'high' ? '#ffaa00' : '#44ffaa'}">${c.threat_level ?? 'N/A'}</span>
                ${critSectors.length ? `<br/><span style="color:#ffaa00">⚡ Infra: ${critSectors.join(', ')}</span>` : ''}
                ${dataSectors.length ? `<br/><span style="color:#44aaff">🖥 Data/Telecom: ${dataSectors.join(', ')}</span>` : ''}
              `)
          })
          .on('mousemove', function (event) {
            const parentRect = svgRef.current!.parentElement!.getBoundingClientRect()
            tooltip
              .style('left', `${event.clientX - parentRect.left + 12}px`)
              .style('top', `${event.clientY - parentRect.top - 10}px`)
          })
          .on('mouseout', function (_e, d: any) {
            d3.select(this).attr('stroke', getStroke(d)).attr('stroke-width', getStrokeWidth(d))
            tooltip.style('display', 'none')
          })
          .on('click', (_e, d: any) => {
            const c = countryMap[+d.id]
            if (c) setSelected(c)
          })

        // Country code labels for tracked countries
        const trackedFeats = feats.filter((d: any) => countryMap[+d.id])
        const labels = g.selectAll<SVGTextElement, any>('text.country-label')
          .data(trackedFeats)
          .join('text')
          .attr('class', 'country-label')
          .attr('text-anchor', 'middle')
          .attr('fill', '#cdd6f4')
          .attr('font-size', '9px')
          .attr('font-family', 'monospace')
          .attr('pointer-events', 'none')
          .attr('paint-order', 'stroke')
          .attr('stroke', '#071020')
          .attr('stroke-width', 2.5)
          .attr('stroke-linejoin', 'round')
          .text((d: any) => countryMap[+d.id]?.code ?? '')
          .attr('transform', (d: any) => `translate(${path.centroid(d)})`)

        // Pulsing rings for critical infra countries (always visible regardless of view)
        const critFeats = feats.filter((d: any) => {
          const c = countryMap[+d.id]
          return c && isCritInfra(c)
        })
        const dataFeats = feats.filter((d: any) => {
          const c = countryMap[+d.id]
          return c && isDataCenter(c)
        })

        // Outer critical infra ring (amber)
        const critRings = g.selectAll<SVGCircleElement, any>('circle.crit-ring')
          .data(critFeats)
          .join('circle')
          .attr('class', 'crit-ring')
          .attr('r', 6)
          .attr('fill', 'none')
          .attr('stroke', '#ffaa00')
          .attr('stroke-width', 1.5)
          .attr('pointer-events', 'none')
          .attr('cx', (d: any) => path.centroid(d)[0])
          .attr('cy', (d: any) => path.centroid(d)[1])

        // Inner data center ring (cyan)
        const dataRings = g.selectAll<SVGCircleElement, any>('circle.data-ring')
          .data(dataFeats)
          .join('circle')
          .attr('class', 'data-ring')
          .attr('r', 5)
          .attr('fill', 'none')
          .attr('stroke', '#00ccff')
          .attr('stroke-width', 1.2)
          .attr('pointer-events', 'none')
          .attr('cx', (d: any) => path.centroid(d)[0])
          .attr('cy', (d: any) => path.centroid(d)[1])

        // ── Auto-rotation ──────────────────────────────────────────────
        let rotX = 0
        let isDragging = false
        let animFrame: number

        const isVisible = (d: any) => {
          const centroid = path.centroid(d)
          return !isNaN(centroid[0]) && !isNaN(centroid[1])
        }

        const redraw = () => {
          sphere.attr('d', path({ type: 'Sphere' } as any))
          graticuleEl.attr('d', path(graticule()))
          countryPaths.attr('d', path as any)
          labels
            .attr('transform', (d: any) => `translate(${path.centroid(d)})`)
            .attr('display', (d: any) => isVisible(d) ? null : 'none')
          critRings
            .attr('cx', (d: any) => path.centroid(d)[0])
            .attr('cy', (d: any) => path.centroid(d)[1])
            .attr('display', (d: any) => isVisible(d) ? null : 'none')
          dataRings
            .attr('cx', (d: any) => path.centroid(d)[0])
            .attr('cy', (d: any) => path.centroid(d)[1])
            .attr('display', (d: any) => isVisible(d) ? null : 'none')
        }

        const rotate = () => {
          if (!isDragging) {
            rotX += 0.2
            projection.rotate([rotX, -20])
            redraw()
          }
          animFrame = requestAnimationFrame(rotate)
        }
        animFrame = requestAnimationFrame(rotate)

        // ── Drag to rotate ─────────────────────────────────────────────
        let dragStart: [number, number] | null = null
        let rotateStart: [number, number, number] = [0, -20, 0]

        svg.call(
          d3.drag<SVGSVGElement, unknown>()
            .on('start', (event) => {
              isDragging = true
              dragStart = [event.x, event.y]
              rotateStart = projection.rotate() as [number, number, number]
              tooltip.style('display', 'none')
            })
            .on('drag', (event) => {
              if (!dragStart) return
              const dx = event.x - dragStart[0]
              const dy = event.y - dragStart[1]
              projection.rotate([rotateStart[0] + dx * 0.4, rotateStart[1] - dy * 0.4])
              rotX = projection.rotate()[0]
              redraw()
            })
            .on('end', () => {
              isDragging = false
              dragStart = null
            })
        )

        return () => {
          cancelAnimationFrame(animFrame)
          tooltip.remove()
        }
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
        {(['all', 'origin', 'target', 'critical'] as ViewMode[]).map((v) => (
          <button
            key={v}
            className={`filter-btn${view === v ? ' active' : ''}`}
            onClick={() => setView(v)}
          >
            {v === 'critical' ? '⚡ Critical Infra' : v.charAt(0).toUpperCase() + v.slice(1)}
          </button>
        ))}
        <span style={{ marginLeft: 'auto', fontSize: '0.8rem', color: 'var(--text-muted)' }}>
          <span style={{ color: '#ff4444' }}>■</span> Origin &nbsp;
          <span style={{ color: '#4477ff' }}>■</span> Target &nbsp;
          <span style={{ color: '#44ffaa' }}>■</span> Both &nbsp;
          <span style={{ color: '#ffaa00' }}>◎</span> Infra &nbsp;
          <span style={{ color: '#00ccff' }}>◎</span> Data/Telecom
        </span>
      </div>

      <div style={{ display: 'flex', gap: '1rem', position: 'relative' }}>
        <svg ref={svgRef} style={{ flex: 1, background: '#0a0f1e', borderRadius: 8, minHeight: 500 }} />
        {selected && (
          <div className="georisk-detail-panel">
            <div style={{ display: 'flex', justifyContent: 'space-between' }}>
              <h4>{selected.name}</h4>
              <button onClick={() => setSelected(null)} style={{ background: 'none', border: 'none', cursor: 'pointer', color: '#888' }}>✕</button>
            </div>
            <div className="detail-row"><span>Code:</span><span>{selected.code}</span></div>
            <div className="detail-row">
              <span>Role:</span>
              <span className={`severity-badge sev-${selected.role === 'threat_origin' || selected.role === 'origin' ? 'critical' : 'medium'}`}>
                {selected.role}
              </span>
            </div>
            <div className="detail-row">
              <span>Threat Level:</span>
              <span className={`severity-badge sev-${selected.threat_level}`}>{selected.threat_level}</span>
            </div>
            {selected.threat_score && (
              <div className="detail-row"><span>Threat Score:</span><span>{selected.threat_score}/100</span></div>
            )}
            {selected.primary_sectors?.length > 0 && (
              <div>
                <div style={{ color: 'var(--text-muted)', fontSize: '0.8rem', marginTop: '0.75rem' }}>Targeted Sectors</div>
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: '4px', marginTop: '4px' }}>
                  {selected.primary_sectors.map((s: string) => (
                    <span
                      key={s}
                      className="ioc-tag"
                      style={{
                        borderColor: CRIT_INFRA_SECTORS.has(s) ? '#ffaa00' : undefined,
                        color: DATA_CENTER_SECTORS.has(s) ? '#00ccff' : undefined,
                      }}
                    >{s}</span>
                  ))}
                </div>
              </div>
            )}
            {selected.primary_actors?.length > 0 && (
              <div>
                <div style={{ color: 'var(--text-muted)', fontSize: '0.8rem', marginTop: '0.75rem' }}>Known Actors</div>
                {selected.primary_actors.map((a: string) => (
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
