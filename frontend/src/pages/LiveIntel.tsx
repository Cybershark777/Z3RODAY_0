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

  const { data: kevData, isLoading: kevLoading, error: kevError } = useQuery({
    queryKey: ['kev'],
    queryFn: api.kev,
  })

  const { data: otxData } = useQuery({
    queryKey: ['otx'],
    queryFn: api.otx,
  })

  const { data: cveData, isLoading: cveLoading, error: cveError } = useQuery({
    queryKey: ['cve', cveKeyword],
    queryFn: () => api.cve(cveKeyword),
    enabled: cveEnabled && !!cveKeyword,
  })

  const vulns: any[] = kevData?.vulnerabilities ?? []

  return (
    <div className="tab-page">
      <div className="section-header">
        <h2>Live Threat Intelligence</h2>
        <p className="section-desc">
          Real-time data from CISA KEV catalog, NIST NVD, and AlienVault OTX.
        </p>
      </div>

      {/* OTX Status */}
      {otxData && (
        <div className={`otx-notice${otxData.active ? '' : ''}`}>
          {otxData.active
            ? `✔ AlienVault OTX: ${otxData.count} active pulses`
            : `ℹ AlienVault OTX: ${otxData.notice ?? 'Not configured'}`}
        </div>
      )}

      {/* CISA KEV */}
      <div className="intel-section">
        <div className="intel-section-header">
          <h3>CISA KEV — ICS/OT Relevant Entries</h3>
          <span className="intel-badge">{kevLoading ? 'Loading...' : `${vulns.length} entries`}</span>
        </div>
        {kevLoading && <LoadingSpinner message="Loading CISA KEV catalog..." />}
        {kevError && <ErrorMessage message="Failed to load CISA KEV data" />}
        {!kevLoading && !kevError && (
          <table className="intel-table">
            <thead>
              <tr>
                <th>CVE ID</th>
                <th>Vendor</th>
                <th>Product</th>
                <th>Date Added</th>
                <th>Due Date</th>
                <th>Action Required</th>
              </tr>
            </thead>
            <tbody>
              {vulns.slice(0, 50).map((v: any, i: number) => (
                <tr key={i}>
                  <td><code>{v.cveID}</code></td>
                  <td>{v.vendorProject}</td>
                  <td>{v.product}</td>
                  <td>{v.dateAdded}</td>
                  <td>{v.dueDate}</td>
                  <td className="action-text">{v.requiredAction}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      {/* NVD CVE Lookup */}
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
          <button
            className="primary-btn"
            disabled={!cveKeyword}
            onClick={() => setCveEnabled(true)}
          >
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
                    <td><code>{cve?.id}</code></td>
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
