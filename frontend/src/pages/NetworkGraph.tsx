import { useRef, useEffect, useState } from 'react'
import * as d3 from 'd3'
import { useQuery } from '@tanstack/react-query'
import { api } from '../services/api'
import LoadingSpinner from '../components/LoadingSpinner'

const NODE_COLORS: Record<string, string> = {
  actor: '#ff6b6b',
  threat: '#ff8c42',
  sector: '#ffd43b',
  purdue_level: '#00bcd4',
  technique: '#74c0fc',
  vulnerability: '#69db7c',
}

export default function NetworkGraph() {
  const svgRef = useRef<SVGSVGElement>(null)
  const containerRef = useRef<HTMLDivElement>(null)
  const [filter, setFilter] = useState<string | null>(null)
  const [selected, setSelected] = useState<any>(null)

  const { data, isLoading } = useQuery({
    queryKey: ['network-graph'],
    queryFn: api.networkGraph,
  })

  useEffect(() => {
    if (!data || !svgRef.current || !containerRef.current) return

    const rect = containerRef.current.getBoundingClientRect()
    const width = rect.width || 900
    const height = 600

    const svg = d3.select(svgRef.current)
    svg.selectAll('*').remove()
    svg.attr('width', width).attr('height', height)

    let nodes: any[] = [...(data.nodes ?? [])]
    let links: any[] = [...(data.links ?? [])]

    if (filter) {
      nodes = nodes.filter((n: any) => n.type === filter)
      const nodeIds = new Set(nodes.map((n: any) => n.id))
      links = links.filter((l: any) => nodeIds.has(l.source) && nodeIds.has(l.target))
    }

    // Pre-compute degrees
    const degree: Record<string, number> = {}
    for (const l of links) {
      degree[l.source] = (degree[l.source] ?? 0) + 1
      degree[l.target] = (degree[l.target] ?? 0) + 1
    }

    const defs = svg.append('defs')
    defs.append('marker')
      .attr('id', 'arrow')
      .attr('viewBox', '0 -5 10 10')
      .attr('refX', 18).attr('refY', 0)
      .attr('markerWidth', 6).attr('markerHeight', 6)
      .attr('orient', 'auto')
      .append('path').attr('d', 'M0,-5L10,0L0,5').attr('fill', '#555')

    const g = svg.append('g')

    svg.call(
      d3.zoom<SVGSVGElement, unknown>().scaleExtent([0.2, 4]).on('zoom', (e) => {
        g.attr('transform', e.transform)
      }),
    )

    // Background rect for deselect
    svg.insert('rect', ':first-child')
      .attr('width', width).attr('height', height)
      .attr('fill', 'transparent')
      .on('click', () => setSelected(null))

    const simulation = d3.forceSimulation(nodes)
      .force('link', d3.forceLink(links).id((d: any) => d.id).distance(80))
      .force('charge', d3.forceManyBody().strength(-200))
      .force('center', d3.forceCenter(width / 2, height / 2))
      .force('collision', d3.forceCollide(20))

    const link = g.append('g')
      .selectAll('line')
      .data(links)
      .join('line')
      .attr('stroke', '#444')
      .attr('stroke-width', 1.5)
      .attr('marker-end', 'url(#arrow)')

    const node = g.append('g')
      .selectAll('circle')
      .data(nodes)
      .join('circle')
      .attr('r', (d: any) => 6 + Math.min(degree[d.id] ?? 0, 8) * 1.5)
      .attr('fill', (d: any) => NODE_COLORS[d.type] ?? '#888')
      .attr('stroke', '#1a1a2e')
      .attr('stroke-width', 1.5)
      .attr('cursor', 'pointer')
      .on('click', (e, d) => { e.stopPropagation(); setSelected(d) })
      .call(
        (d3.drag<SVGCircleElement, any>()
          .on('start', (e, d) => { if (!e.active) simulation.alphaTarget(0.3).restart(); d.fx = d.x; d.fy = d.y })
          .on('drag', (e, d) => { d.fx = e.x; d.fy = e.y })
          .on('end', (e, d) => { if (!e.active) simulation.alphaTarget(0); d.fx = null; d.fy = null })) as any,
      )

    const label = g.append('g')
      .selectAll('text')
      .data(nodes.filter((d: any) => (degree[d.id] ?? 0) >= 3 || ['actor', 'sector'].includes(d.type)))
      .join('text')
      .attr('font-size', 10)
      .attr('fill', '#ccc')
      .attr('text-anchor', 'middle')
      .attr('dy', -10)
      .text((d: any) => d.label)

    node.append('title').text((d: any) => `${d.label} (${d.type})`)

    simulation.on('tick', () => {
      link
        .attr('x1', (d: any) => d.source.x)
        .attr('y1', (d: any) => d.source.y)
        .attr('x2', (d: any) => d.target.x)
        .attr('y2', (d: any) => d.target.y)
      node.attr('cx', (d: any) => d.x).attr('cy', (d: any) => d.y)
      label.attr('x', (d: any) => d.x).attr('y', (d: any) => d.y)
    })
  }, [data, filter])

  const nodeTypes = data
    ? [...new Set((data.nodes ?? []).map((n: any) => n.type))] as string[]
    : []

  if (isLoading) return <LoadingSpinner message="Loading network graph..." />

  return (
    <div className="tab-page">
      <div className="section-header">
        <h2>Threat Relationship Network</h2>
        <p className="section-desc">
          Force-directed graph of threat actors, techniques, sectors, and ICS Purdue levels.
        </p>
      </div>

      <div className="network-controls">
        <button
          className={`filter-btn${!filter ? ' active' : ''}`}
          onClick={() => setFilter(null)}
        >All</button>
        {nodeTypes.map((t) => (
          <button
            key={t}
            className={`filter-btn${filter === t ? ' active' : ''}`}
            onClick={() => setFilter(t)}
            style={{ borderColor: NODE_COLORS[t] ?? '#888' }}
          >
            {t.replace('_', ' ')}
          </button>
        ))}
      </div>

      <div style={{ display: 'flex', gap: '1rem' }}>
        <div ref={containerRef} style={{ flex: 1, minHeight: 600, position: 'relative' }}>
          <svg ref={svgRef} style={{ width: '100%', height: 600, background: 'var(--surface)' }} />
        </div>
        {selected && (
          <div className="georisk-detail-panel" style={{ width: 260 }}>
            <h4>{selected.label}</h4>
            <div className="detail-row"><span>Type:</span><span>{selected.type}</span></div>
            {selected.sector && <div className="detail-row"><span>Sector:</span><span>{selected.sector}</span></div>}
            {selected.ip && <div className="detail-row"><span>IP:</span><span>{selected.ip}</span></div>}
            {selected.purdue_level !== undefined && (
              <div className="detail-row"><span>Purdue Level:</span><span>{selected.purdue_level}</span></div>
            )}
          </div>
        )}
      </div>
    </div>
  )
}
