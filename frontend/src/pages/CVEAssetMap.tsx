import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { api } from '../services/api'
import LoadingSpinner from '../components/LoadingSpinner'

const PURDUE_LABELS: Record<number, string> = {
  0: 'Level 0 — Field Devices',
  1: 'Level 1 — Control',
  2: 'Level 2 — Supervisory',
  3: 'Level 3 — Operations',
  4: 'Level 4/5 — Enterprise',
}

const CVSS_COLOR = (score: number) => {
  if (score >= 9) return '#ff4444'
  if (score >= 7) return '#ff8c42'
  if (score >= 4) return '#ffd43b'
  return '#69db7c'
}

export default function CVEAssetMap() {
  const [levelFilter, setLevelFilter] = useState<number | null>(null)
  const [kevOnly, setKevOnly] = useState(false)

  const { data, isLoading } = useQuery({
    queryKey: ['cve-asset-map'],
    queryFn: api.cveAssetMap,
  })

  if (isLoading) return <LoadingSpinner message="Loading CVE asset map..." />

  let cves: any[] = data?.cves ?? []
  if (levelFilter !== null) cves = cves.filter((c) => c.purdue_level === levelFilter)
  if (kevOnly) cves = cves.filter((c) => c.kev)

  // Group by vendor for summary
  const vendorCounts: Record<string, number> = {}
  for (const c of cves) vendorCounts[c.vendor] = (vendorCounts[c.vendor] ?? 0) + 1

  return (
    <div className="tab-page">
      <div className="section-header">
        <h2>CVE → ICS Asset Map</h2>
        <p className="section-desc">
          25 critical ICS/OT CVEs mapped to vendors, products, and Purdue Reference Model levels.
          KEV = CISA Known Exploited Vulnerabilities.
        </p>
      </div>

      {/* Purdue level filter */}
      <div className="network-controls" style={{ marginBottom: '1rem' }}>
        <button
          className={`filter-btn${levelFilter === null ? ' active' : ''}`}
          onClick={() => setLevelFilter(null)}
        >All Levels</button>
        {[0, 1, 2, 3, 4].map((l) => (
          <button
            key={l}
            className={`filter-btn${levelFilter === l ? ' active' : ''}`}
            onClick={() => setLevelFilter(l)}
          >Level {l}</button>
        ))}
        <label style={{ marginLeft: 'auto', display: 'flex', alignItems: 'center', gap: '0.5rem', cursor: 'pointer' }}>
          <input type="checkbox" checked={kevOnly} onChange={(e) => setKevOnly(e.target.checked)} />
          KEV only
        </label>
      </div>

      {/* Vendor summary */}
      <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap', marginBottom: '1rem' }}>
        {Object.entries(vendorCounts).sort((a, b) => b[1] - a[1]).map(([vendor, count]) => (
          <div key={vendor} className="ioc-tag">
            {vendor} ({count})
          </div>
        ))}
      </div>

      {/* CVE table */}
      <table className="intel-table">
        <thead>
          <tr>
            <th>CVE ID</th>
            <th>Vendor</th>
            <th>Product</th>
            <th>CVSS</th>
            <th>Purdue Level</th>
            <th>KEV</th>
            <th>Description</th>
          </tr>
        </thead>
        <tbody>
          {cves.map((cve: any) => (
            <tr key={cve.cve}>
              <td><code>{cve.cve}</code></td>
              <td>{cve.vendor}</td>
              <td>{cve.product}</td>
              <td>
                <span
                  className="cvss-badge"
                  style={{ background: CVSS_COLOR(cve.cvss), color: '#000', fontWeight: 700 }}
                >
                  {cve.cvss}
                </span>
              </td>
              <td>
                <span style={{ fontSize: '0.8rem' }}>{PURDUE_LABELS[cve.purdue_level]}</span>
              </td>
              <td>
                {cve.kev && (
                  <span className="severity-badge sev-critical" style={{ fontSize: '0.7rem' }}>KEV</span>
                )}
              </td>
              <td className="desc-text">{cve.description}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}
