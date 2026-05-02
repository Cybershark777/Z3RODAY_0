import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { api } from '../services/api'
import LoadingSpinner from '../components/LoadingSpinner'
import ErrorMessage from '../components/ErrorMessage'

const CVE_KEYWORDS = [
  { value: 'scada', label: 'SCADA' },
  { value: 'plc', label: 'PLC' },
  { value: 'ics', label: 'ICS' },
  { value: 'industrial+control', label: 'Industrial Control' },
  { value: 'modbus', label: 'Modbus' },
  { value: 'siemens', label: 'Siemens' },
  { value: 'rockwell', label: 'Rockwell' },
]

export default function LiveIntel() {
  const [cveKeyword, setCveKeyword] = useState('')
  const [cveEnabled, setCveEnabled] = useState(false)
  const [iocInput, setIocInput] = useState('')
  const [iocQuery, setIocQuery] = useState('')

  const { data: kevData, isLoading: kevLoading, error: kevError } = useQuery({
    queryKey: ['kev'],
    queryFn: api.kev,
  })
  const { data: otxData } = useQuery({ queryKey: ['otx'], queryFn: api.otx })
  const { data: cveData, isLoading: cveLoading, error: cveError } = useQuery({
    queryKey: ['cve', cveKeyword],
    queryFn: () => api.cve(cveKeyword),
    enabled: cveEnabled && !!cveKeyword,
  })
  const { data: iocData, isLoading: iocLoading } = useQuery({
    queryKey: ['ioc-search', iocQuery],
    queryFn: () => api.iocSearch(iocQuery),
    enabled: !!iocQuery,
  })

  const vulns: any[] = kevData?.vulnerabilities ?? []

  return (
    <div className="tab-page">
      <div className="section-header">
        <h2>Live Threat Intelligence</h2>
        <p className="section-desc">
          Real-time data from CISA KEV, NIST NVD, AlienVault OTX, and multi-source IOC search.
        </p>
      </div>

      {otxData && (
        <div className="otx-notice">
          {otxData.active
            ? `✔ AlienVault OTX: ${otxData.count} active pulses`
            : `ℹ AlienVault OTX: ${otxData.notice ?? 'Not configured'}`}
        </div>
      )}

      {/* ── Global IOC Search ───────────────────────────────────────────── */}
      <div className="intel-section">
        <div className="intel-section-header">
          <h3>Global IOC Search</h3>
          <span className="intel-badge">ThreatFox · GreyNoise · Feodo · MalwareBazaar · KEV</span>
        </div>
        <p style={{ fontSize: '0.82rem', color: 'var(--text-muted)', marginBottom: '0.75rem' }}>
          Enter an IP address, file hash (MD5/SHA256), domain, or CVE ID to search across all threat intelligence feeds simultaneously.
        </p>
        <div style={{ display: 'flex', gap: '0.75rem', marginBottom: '1rem' }}>
          <input
            className="intel-select"
            style={{ flex: 1 }}
            placeholder="IP, hash, domain, or CVE-XXXX-XXXXX..."
            value={iocInput}
            onChange={(e) => setIocInput(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && iocInput && setIocQuery(iocInput)}
          />
          <button
            className="primary-btn"
            disabled={!iocInput}
            onClick={() => setIocQuery(iocInput)}
          >
            Search All Feeds
          </button>
          {iocQuery && (
            <button className="filter-btn" onClick={() => { setIocQuery(''); setIocInput('') }}>Clear</button>
          )}
        </div>

        {iocLoading && <LoadingSpinner message={`Querying feeds for ${iocQuery}...`} />}

        {iocData && !iocLoading && (
          <div>
            <div style={{ marginBottom: '0.75rem', fontSize: '0.82rem', color: 'var(--text-muted)' }}>
              Results for: <strong style={{ color: 'var(--accent)' }}>{iocData.query}</strong>
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
              {(iocData.results ?? []).map((r: any, i: number) => (
                <div key={i} style={{ padding: '0.75rem 1rem', background: 'var(--surface2)', borderRadius: 6, borderLeft: '3px solid var(--border)' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '0.4rem' }}>
                    <strong style={{ color: 'var(--accent)', fontSize: '0.85rem' }}>{r.source}</strong>
                    {r.error && <span className="severity-badge sev-low">Error</span>}
                  </div>
                  {r.error ? (
                    <div style={{ fontSize: '0.78rem', color: '#ff6b6b' }}>{r.error}</div>
                  ) : (
                    <pre style={{ fontSize: '0.72rem', color: 'var(--text-muted)', margin: 0, overflow: 'auto', maxHeight: 200, whiteSpace: 'pre-wrap', wordBreak: 'break-all' }}>
                      {JSON.stringify(r.data, null, 2)}
                    </pre>
                  )}
                </div>
              ))}
            </div>
          </div>
        )}
      </div>

      {/* ── CISA KEV ────────────────────────────────────────────────────── */}
      <div className="intel-section">
        <div className="intel-section-header">
          <h3>
            <a href="https://www.cisa.gov/known-exploited-vulnerabilities-catalog" target="_blank" rel="noopener noreferrer" style={{ color: 'inherit', textDecoration: 'none' }}>
              CISA KEV — ICS/OT Relevant Entries ↗
            </a>
          </h3>
          <span className="intel-badge">{kevLoading ? 'Loading...' : `${vulns.length} entries`}</span>
        </div>
        {kevLoading && <LoadingSpinner message="Loading CISA KEV catalog..." />}
        {kevError && <ErrorMessage message="Failed to load CISA KEV data" />}
        {!kevLoading && !kevError && (
          <table className="intel-table">
            <thead>
              <tr><th>CVE ID</th><th>Vendor</th><th>Product</th><th>Date Added</th><th>Due Date</th><th>Action Required</th></tr>
            </thead>
            <tbody>
              {vulns.slice(0, 50).map((v: any, i: number) => (
                <tr key={i}>
                  <td>
                    <a href={`https://nvd.nist.gov/vuln/detail/${v.cveID}`} target="_blank" rel="noopener noreferrer" style={{ textDecoration: 'none' }}>
                      <code style={{ color: 'var(--accent)' }}>{v.cveID} ↗</code>
                    </a>
                  </td>
                  <td>{v.vendorProject}</td>
                  <td>{v.product}</td>
                  <td>{v.dateAdded}</td>
                  <td style={{ color: '#e3b341' }}>{v.dueDate}</td>
                  <td className="action-text">{v.requiredAction}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      {/* ── NVD CVE Lookup ──────────────────────────────────────────────── */}
      <div className="intel-section">
        <div className="intel-section-header">
          <h3>NVD CVE Lookup</h3>
          <span className="intel-badge">NVD API v2</span>
        </div>
        <div className="cve-controls">
          <label>Select keyword:</label>
          <select
            className="intel-select"
            value={cveKeyword}
            onChange={(e) => { setCveKeyword(e.target.value); setCveEnabled(false) }}
          >
            <option value="">-- Choose --</option>
            {CVE_KEYWORDS.map((k) => (
              <option key={k.value} value={k.value}>{k.label}</option>
            ))}
          </select>
          <button className="primary-btn" disabled={!cveKeyword} onClick={() => setCveEnabled(true)}>
            Search CVEs
          </button>
        </div>
        {cveLoading && <LoadingSpinner message="Querying NVD..." />}
        {cveError && <ErrorMessage message="NVD query failed — rate limited or unavailable" />}
        {cveData?.vulnerabilities && (
          <table className="intel-table">
            <thead>
              <tr><th>CVE ID</th><th>CVSS</th><th>Description</th></tr>
            </thead>
            <tbody>
              {cveData.vulnerabilities.slice(0, 20).map((item: any, i: number) => {
                const cve = item.cve
                const metrics = cve?.metrics?.cvssMetricV31?.[0]?.cvssData
                return (
                  <tr key={i}>
                    <td>
                      <a href={`https://nvd.nist.gov/vuln/detail/${cve?.id}`} target="_blank" rel="noopener noreferrer" style={{ textDecoration: 'none' }}>
                        <code style={{ color: 'var(--accent)' }}>{cve?.id} ↗</code>
                      </a>
                    </td>
                    <td>
                      {metrics ? (
                        <span className={`cvss-badge cvss-${metrics.baseSeverity?.toLowerCase()}`}>
                          {metrics.baseScore}
                        </span>
                      ) : '—'}
                    </td>
                    <td className="desc-text">{cve?.descriptions?.[0]?.value}</td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        )}
      </div>
    </div>
  )
}
