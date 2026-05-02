import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { api } from '../services/api'
import LoadingSpinner from '../components/LoadingSpinner'

type Source = 'overview' | 'threatfox' | 'feodo' | 'urlhaus' | 'malwarebazaar' | 'cisa' | 'greynoise' | 'shodan'

const PLATFORM_URLS: Record<string, string> = {
  ThreatFox:       'https://threatfox.abuse.ch',
  'Feodo Tracker': 'https://feodotracker.abuse.ch',
  URLhaus:         'https://urlhaus.abuse.ch',
  MalwareBazaar:   'https://bazaar.abuse.ch',
  'CISA ICS-CERT': 'https://www.cisa.gov/ics-advisories',
  GreyNoise:       'https://www.greynoise.io',
  Shodan:          'https://www.shodan.io',
}

const SHODAN_PROTOCOLS = ['modbus', 's7', 'dnp3', 'bacnet', 'enip', 'iec104']

export default function ThreatIntelPlatforms() {
  const [activeSource, setActiveSource] = useState<Source>('overview')
  const [iocSearch, setIocSearch] = useState('')
  const [iocQuery, setIocQuery] = useState('')
  const [shodanProtocol, setShodanProtocol] = useState('modbus')
  const [ipLookup, setIpLookup] = useState('')
  const [ipQuery, setIpQuery] = useState('')

  const { data: summary } = useQuery({ queryKey: ['intel-summary'], queryFn: api.intelSummary })
  const { data: tfData, isLoading: tfLoading } = useQuery({ queryKey: ['threatfox-iocs'], queryFn: api.threatFoxIOCs, enabled: activeSource === 'threatfox' })
  const { data: tfSearch } = useQuery({ queryKey: ['threatfox-search', iocQuery], queryFn: () => api.threatFoxSearch(iocQuery), enabled: !!iocQuery && activeSource === 'threatfox' })
  const { data: feodoData, isLoading: feodoLoading } = useQuery({ queryKey: ['feodo'], queryFn: api.feodoBlocklist, enabled: activeSource === 'feodo' })
  const { data: urlhausData, isLoading: urlhausLoading } = useQuery({ queryKey: ['urlhaus'], queryFn: api.urlhausRecent, enabled: activeSource === 'urlhaus' })
  const { data: mbData, isLoading: mbLoading } = useQuery({ queryKey: ['malwarebazaar'], queryFn: api.malwareBazaar, enabled: activeSource === 'malwarebazaar' })
  const { data: cisaData, isLoading: cisaLoading } = useQuery({ queryKey: ['cisa-advisories'], queryFn: api.cisaAdvisories, enabled: activeSource === 'cisa' })
  const { data: gnData, isLoading: gnLoading } = useQuery({ queryKey: ['greynoise-ics'], queryFn: api.greyNoiseICS, enabled: activeSource === 'greynoise' })
  const { data: gnIPData } = useQuery({ queryKey: ['greynoise-ip', ipQuery], queryFn: () => api.greyNoiseIP(ipQuery), enabled: !!ipQuery && activeSource === 'greynoise' })
  const { data: shodanData, isLoading: shodanLoading } = useQuery({ queryKey: ['shodan-ics', shodanProtocol], queryFn: () => api.shodanICS(shodanProtocol), enabled: activeSource === 'shodan' })

  const sources = summary?.sources ?? []
  const configuredKeys = summary?.configured_keys ?? {}

  return (
    <div className="tab-page">
      <div className="section-header">
        <h2>Threat Intelligence Platforms</h2>
        <p className="section-desc">
          Live feeds from Abuse.ch (ThreatFox, Feodo, URLhaus, MalwareBazaar), CISA ICS-CERT,
          GreyNoise, and Shodan — enriched and filtered for ICS/OT relevance.
        </p>
      </div>

      {/* Source tabs */}
      <div className="filters" style={{ marginBottom: '1.5rem' }}>
        {([
          { id: 'overview', label: '⬡ Overview' },
          { id: 'threatfox', label: '☠ ThreatFox' },
          { id: 'feodo', label: '🛡 Feodo' },
          { id: 'urlhaus', label: '🔗 URLhaus' },
          { id: 'malwarebazaar', label: '🧬 MalwareBazaar' },
          { id: 'cisa', label: '📋 CISA ICS' },
          { id: 'greynoise', label: '📡 GreyNoise' },
          { id: 'shodan', label: '🔍 Shodan' },
        ] as { id: Source; label: string }[]).map((s) => (
          <button
            key={s.id}
            className={`filter-btn${activeSource === s.id ? ' active' : ''}`}
            onClick={() => setActiveSource(s.id)}
          >{s.label}</button>
        ))}
      </div>

      {/* ── Overview ─────────────────────────────────────────────────────── */}
      {activeSource === 'overview' && (
        <div>
          <div style={{ display: 'flex', gap: '0.75rem', marginBottom: '1.5rem', flexWrap: 'wrap' }}>
            {(['GREYNOISE_API_KEY', 'SHODAN_API_KEY', 'OTX_API_KEY'] as string[]).map((key) => (
              <div key={key} className="metric-card" style={{ minWidth: 200 }}>
                <div className="metric-label">{key}</div>
                <div style={{ fontSize: '0.9rem', marginTop: '0.4rem' }}>
                  {configuredKeys[key]
                    ? <span style={{ color: '#00e676' }}>✔ Configured</span>
                    : <span style={{ color: '#ff6b6b' }}>✗ Not set</span>}
                </div>
              </div>
            ))}
          </div>

          <div className="dataset-grid">
            {sources.map((s: any) => (
              <div
                key={s.name}
                className="dataset-card"
                style={{ cursor: 'pointer', borderColor: s.ics_focused ? 'var(--accent)' : undefined }}
                onClick={() => setActiveSource(s.endpoint.split('/').pop() as Source)}
              >
                <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '0.5rem' }}>
                  <div className="dataset-name">
                    {PLATFORM_URLS[s.name] ? (
                      <a
                        href={PLATFORM_URLS[s.name]}
                        target="_blank"
                        rel="noopener noreferrer"
                        onClick={(e) => e.stopPropagation()}
                        style={{ color: 'inherit', textDecoration: 'none', borderBottom: '1px dashed var(--accent)', paddingBottom: 1 }}
                      >{s.name} ↗</a>
                    ) : s.name}
                  </div>
                  <div style={{ display: 'flex', gap: '0.3rem' }}>
                    {s.ics_focused && <span className="intel-badge" style={{ borderColor: 'var(--accent)', color: 'var(--accent2)' }}>ICS</span>}
                    {s.free && <span className="intel-badge" style={{ borderColor: '#00e676', color: '#00e676' }}>Free</span>}
                  </div>
                </div>
                <div className="dataset-desc">{s.description}</div>
                <div style={{ marginTop: '0.75rem', display: 'flex', gap: '0.5rem', flexWrap: 'wrap' }}>
                  <span className="intel-badge">↻ {s.update_freq}</span>
                  {s.live_key_env && (
                    <span className="intel-badge" style={{ borderColor: configuredKeys[s.live_key_env] ? '#00e676' : '#e3b341', color: configuredKeys[s.live_key_env] ? '#00e676' : '#e3b341' }}>
                      {configuredKeys[s.live_key_env] ? '✔ Live' : `Set ${s.live_key_env}`}
                    </span>
                  )}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* ── ThreatFox ─────────────────────────────────────────────────────── */}
      {activeSource === 'threatfox' && (
        <div>
          <SourceHeader name="ThreatFox" desc="Active malware C2 servers and IOCs from Abuse.ch. ICS-relevant entries highlighted." badge={tfData?.total} />
          <div style={{ display: 'flex', gap: '0.75rem', marginBottom: '1rem' }}>
            <input
              className="intel-select"
              style={{ flex: 1 }}
              placeholder="Search IOC (IP, domain, hash)..."
              value={iocSearch}
              onChange={(e) => setIocSearch(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && setIocQuery(iocSearch)}
            />
            <button className="primary-btn" onClick={() => setIocQuery(iocSearch)} disabled={!iocSearch}>
              Search
            </button>
          </div>

          {tfSearch?.result && (
            <div className="intel-section" style={{ marginBottom: '1rem' }}>
              <strong>Search result for: {iocQuery}</strong>
              <pre style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: '0.5rem', overflow: 'auto', maxHeight: 200 }}>
                {JSON.stringify(tfSearch.result, null, 2)}
              </pre>
            </div>
          )}

          {tfLoading ? <LoadingSpinner message="Fetching ThreatFox IOCs..." /> : (
            <IOCTable iocs={tfData?.iocs ?? []} />
          )}
        </div>
      )}

      {/* ── Feodo ─────────────────────────────────────────────────────────── */}
      {activeSource === 'feodo' && (
        <div>
          <SourceHeader name="Feodo Tracker" desc="Botnet C2 IP blocklist. ICS-relevant entries (Emotet, TrickBot, EKANS) flagged." badge={feodoData?.total} />
          {feodoData?.ics_total > 0 && (
            <div style={{ marginBottom: '1rem', padding: '0.6rem 1rem', background: 'rgba(218,54,51,0.1)', border: '1px solid #da3633', borderRadius: 6, fontSize: '0.85rem' }}>
              ⚠ <strong>{feodoData.ics_total}</strong> ICS-relevant C2 entries detected in current blocklist
            </div>
          )}
          {feodoLoading ? <LoadingSpinner message="Fetching Feodo blocklist..." /> : (
            <table className="intel-table">
              <thead><tr><th>IP</th><th>Port</th><th>Malware</th><th>Country</th><th>First Seen</th><th>Last Online</th><th>ICS Flag</th></tr></thead>
              <tbody>
                {(feodoData?.blocklist ?? []).slice(0, 100).map((e: any, i: number) => (
                  <tr key={i}>
                    <td>
                      <a href={`https://feodotracker.abuse.ch/browse.php?search=${e.ip_address}`} target="_blank" rel="noopener noreferrer" style={{ textDecoration: 'none' }}>
                        <code style={{ color: 'var(--accent)' }}>{e.ip_address} ↗</code>
                      </a>
                    </td>
                    <td>{e.port}</td>
                    <td><span className="severity-badge sev-high">{e.malware}</span></td>
                    <td>{e.country}</td>
                    <td style={{ fontSize: '0.75rem' }}>{e.first_seen}</td>
                    <td style={{ fontSize: '0.75rem' }}>{e.last_online ?? '—'}</td>
                    <td>{e.ics_relevant ? <span className="severity-badge sev-critical">ICS</span> : ''}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      )}

      {/* ── URLhaus ───────────────────────────────────────────────────────── */}
      {activeSource === 'urlhaus' && (
        <div>
          <SourceHeader name="URLhaus" desc="Malicious URL distribution sites from Abuse.ch." badge={urlhausData?.total} />
          {urlhausData?.ics_total > 0 && (
            <div style={{ marginBottom: '1rem', padding: '0.6rem 1rem', background: 'rgba(218,54,51,0.1)', border: '1px solid #da3633', borderRadius: 6, fontSize: '0.85rem' }}>
              ⚠ <strong>{urlhausData.ics_total}</strong> ICS-tagged malicious URLs in current feed
            </div>
          )}
          {urlhausLoading ? <LoadingSpinner message="Fetching URLhaus feed..." /> : (
            <table className="intel-table">
              <thead><tr><th>URL</th><th>Status</th><th>Threat</th><th>Tags</th><th>Added</th></tr></thead>
              <tbody>
                {(urlhausData?.urls ?? []).slice(0, 80).map((u: any, i: number) => (
                  <tr key={i}>
                    <td style={{ maxWidth: 300, fontSize: '0.75rem', wordBreak: 'break-all' }}>
                      {u.id ? (
                        <a href={`https://urlhaus.abuse.ch/url/${u.id}/`} target="_blank" rel="noopener noreferrer" style={{ color: 'var(--accent)', textDecoration: 'none' }}>
                          {u.url} ↗
                        </a>
                      ) : u.url}
                    </td>
                    <td><span className={`severity-badge ${u.url_status === 'online' ? 'sev-critical' : 'sev-low'}`}>{u.url_status}</span></td>
                    <td>{u.threat}</td>
                    <td style={{ fontSize: '0.75rem' }}>{Array.isArray(u.tags) ? u.tags.join(', ') : u.tags}</td>
                    <td style={{ fontSize: '0.75rem' }}>{u.date_added?.slice(0, 10)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      )}

      {/* ── MalwareBazaar ─────────────────────────────────────────────────── */}
      {activeSource === 'malwarebazaar' && (
        <div>
          <SourceHeader name="MalwareBazaar" desc="Recent malware samples. ICS/OT-relevant families (TRITON, Industroyer, EKANS, PIPEDREAM) highlighted." badge={mbData?.total} />
          {mbData?.ics_total > 0 && (
            <div style={{ marginBottom: '1rem', padding: '0.6rem 1rem', background: 'rgba(218,54,51,0.1)', border: '1px solid #da3633', borderRadius: 6, fontSize: '0.85rem' }}>
              ⚠ <strong>{mbData.ics_total}</strong> ICS-relevant malware samples in last 100
            </div>
          )}
          {mbLoading ? <LoadingSpinner message="Fetching MalwareBazaar samples..." /> : (
            <table className="intel-table">
              <thead><tr><th>SHA256</th><th>Family</th><th>File Type</th><th>Tags</th><th>First Seen</th><th>ICS</th></tr></thead>
              <tbody>
                {(mbData?.samples ?? []).slice(0, 60).map((s: any, i: number) => (
                  <tr key={i}>
                    <td>
                      <a href={`https://bazaar.abuse.ch/sample/${s.sha256_hash}/`} target="_blank" rel="noopener noreferrer" style={{ textDecoration: 'none' }}>
                        <code style={{ fontSize: '0.68rem', color: 'var(--accent)' }}>{s.sha256_hash?.slice(0, 16)}... ↗</code>
                      </a>
                    </td>
                    <td><span className="severity-badge sev-high">{s.signature ?? '—'}</span></td>
                    <td style={{ fontSize: '0.75rem' }}>{s.file_type}</td>
                    <td style={{ fontSize: '0.72rem' }}>{Array.isArray(s.tags) ? s.tags.slice(0, 3).join(', ') : '—'}</td>
                    <td style={{ fontSize: '0.75rem' }}>{s.first_seen?.slice(0, 10)}</td>
                    <td>{(mbData?.ics_samples ?? []).some((x: any) => x.sha256_hash === s.sha256_hash) ? <span className="severity-badge sev-critical">ICS</span> : ''}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      )}

      {/* ── CISA ICS Advisories ───────────────────────────────────────────── */}
      {activeSource === 'cisa' && (
        <div>
          <SourceHeader name="CISA ICS-CERT Advisories" desc="Official ICS security advisories from the Cybersecurity and Infrastructure Security Agency." badge={cisaData?.total} />
          {cisaLoading ? <LoadingSpinner message="Fetching CISA advisories..." /> : (
            <div className="reference-list">
              {(cisaData?.advisories ?? []).map((a: any, i: number) => (
                <div key={i} className="reference-item">
                  <div className="ref-title">
                    <a href={a.link} target="_blank" rel="noopener noreferrer">{a.title}</a>
                  </div>
                  <div style={{ display: 'flex', gap: '0.5rem', margin: '0.3rem 0' }}>
                    <span className="intel-badge">{a.pub_date}</span>
                    {a.id && <span className="intel-badge">{a.id}</span>}
                  </div>
                  {a.summary && <div className="ref-authors">{a.summary}</div>}
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* ── GreyNoise ─────────────────────────────────────────────────────── */}
      {activeSource === 'greynoise' && (
        <div>
          <SourceHeader
            name="GreyNoise"
            desc={gnData?.live ? 'Live ICS protocol scanner detection.' : 'Static dataset — set GREYNOISE_API_KEY in backend/.env for live data.'}
            badge={gnData?.total}
            live={gnData?.live}
          />
          <div style={{ display: 'flex', gap: '0.75rem', marginBottom: '1rem' }}>
            <input
              className="intel-select"
              style={{ flex: 1 }}
              placeholder="Check an IP against GreyNoise (community API, free)..."
              value={ipLookup}
              onChange={(e) => setIpLookup(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && setIpQuery(ipLookup)}
            />
            <button className="primary-btn" onClick={() => setIpQuery(ipLookup)} disabled={!ipLookup}>
              Lookup
            </button>
          </div>

          {gnIPData && (
            <div className="intel-section" style={{ marginBottom: '1rem' }}>
              <div style={{ display: 'flex', gap: '1rem', alignItems: 'center', flexWrap: 'wrap' }}>
                <strong><code>{ipQuery}</code></strong>
                {gnIPData.classification && (
                  <span className={`severity-badge ${gnIPData.classification === 'malicious' ? 'sev-critical' : gnIPData.classification === 'benign' ? 'sev-low' : 'sev-medium'}`}>
                    {gnIPData.classification}
                  </span>
                )}
                {gnIPData.name && <span>{gnIPData.name}</span>}
                {gnIPData.noise !== undefined && <span className="intel-badge">{gnIPData.noise ? 'Background Noise' : 'Targeted'}</span>}
                {gnIPData.riot && <span className="intel-badge" style={{ borderColor: '#00e676', color: '#00e676' }}>RIOT (Trusted)</span>}
              </div>
              {gnIPData.message && <div style={{ marginTop: '0.5rem', fontSize: '0.82rem', color: 'var(--text-muted)' }}>{gnIPData.message}</div>}
            </div>
          )}

          {gnLoading ? <LoadingSpinner message="Fetching GreyNoise ICS scanners..." /> : (
            <table className="intel-table">
              <thead><tr><th>IP</th><th>Classification</th><th>Name</th><th>Tags</th><th>Country</th><th>Last Seen</th></tr></thead>
              <tbody>
                {(gnData?.scanners ?? []).map((s: any, i: number) => (
                  <tr key={i}>
                    <td>
                      <a href={`https://www.greynoise.io/viz/ip/${s.ip}`} target="_blank" rel="noopener noreferrer" style={{ textDecoration: 'none' }}>
                        <code style={{ color: 'var(--accent)' }}>{s.ip} ↗</code>
                      </a>
                    </td>
                    <td>
                      <span className={`severity-badge ${s.classification === 'malicious' ? 'sev-critical' : 'sev-medium'}`}>
                        {s.classification}
                      </span>
                    </td>
                    <td style={{ fontSize: '0.82rem' }}>{s.name ?? '—'}</td>
                    <td style={{ fontSize: '0.75rem' }}>{Array.isArray(s.tags) ? s.tags.join(', ') : s.tags}</td>
                    <td>{s.country_code}</td>
                    <td style={{ fontSize: '0.75rem' }}>{s.last_seen}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      )}

      {/* ── Shodan ────────────────────────────────────────────────────────── */}
      {activeSource === 'shodan' && (
        <div>
          <SourceHeader
            name="Shodan"
            desc={shodanData?.live ? 'Live internet-exposed ICS devices.' : 'Static dataset — set SHODAN_API_KEY in backend/.env for live data.'}
            badge={shodanData?.total}
            live={shodanData?.live}
          />
          <div className="filters" style={{ marginBottom: '1rem' }}>
            {SHODAN_PROTOCOLS.map((p) => (
              <button
                key={p}
                className={`filter-btn${shodanProtocol === p ? ' active' : ''}`}
                onClick={() => setShodanProtocol(p)}
              >{p.toUpperCase()}</button>
            ))}
          </div>
          {shodanLoading ? <LoadingSpinner message="Querying Shodan..." /> : (
            <table className="intel-table">
              <thead><tr><th>IP</th><th>Port</th><th>Protocol</th><th>Product</th><th>Org</th><th>Country</th><th>CVEs</th></tr></thead>
              <tbody>
                {(shodanData?.matches ?? []).map((m: any, i: number) => (
                  <tr key={i}>
                    <td>
                      <a href={`https://www.shodan.io/host/${m.ip_str}`} target="_blank" rel="noopener noreferrer" style={{ textDecoration: 'none' }}>
                        <code style={{ color: 'var(--accent)' }}>{m.ip_str} ↗</code>
                      </a>
                    </td>
                    <td>{m.port}</td>
                    <td><span className="severity-badge sev-medium">{m.protocol}</span></td>
                    <td style={{ fontSize: '0.82rem' }}>{m.product ?? m._shodan?.module ?? '—'}</td>
                    <td style={{ fontSize: '0.82rem' }}>{m.org ?? '—'}</td>
                    <td>{m.country_code ?? m.location?.country_code ?? '—'}</td>
                    <td>
                      {(m.vulns ?? []).map((v: string) => (
                        <a key={v} href={`https://nvd.nist.gov/vuln/detail/${v}`} target="_blank" rel="noopener noreferrer" style={{ textDecoration: 'none' }}>
                          <code style={{ display: 'block', fontSize: '0.7rem', color: '#ff6b6b' }}>{v} ↗</code>
                        </a>
                      ))}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      )}
    </div>
  )
}

// ── Sub-components ──────────────────────────────────────────────────────────

function SourceHeader({ name, desc, badge, live }: { name: string; desc: string; badge?: number; live?: boolean }) {
  return (
    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '1rem' }}>
      <div>
        <h3 style={{ marginBottom: '0.3rem' }}>{name}</h3>
        <p className="section-desc">{desc}</p>
      </div>
      <div style={{ display: 'flex', gap: '0.5rem', flexShrink: 0 }}>
        {badge !== undefined && <span className="intel-badge">{badge} entries</span>}
        {live !== undefined && (
          <span className="intel-badge" style={{ borderColor: live ? '#00e676' : '#e3b341', color: live ? '#00e676' : '#e3b341' }}>
            {live ? '● Live' : '● Static'}
          </span>
        )}
      </div>
    </div>
  )
}

function IOCTable({ iocs }: { iocs: any[] }) {
  if (!iocs.length) return <div className="error-state">No IOCs returned</div>
  return (
    <table className="intel-table">
      <thead>
        <tr><th>IOC Value</th><th>IOC Type</th><th>Threat Type</th><th>Malware</th><th>Confidence</th><th>Tags</th><th>First Seen</th></tr>
      </thead>
      <tbody>
        {iocs.slice(0, 100).map((ioc: any, i: number) => (
          <tr key={i}>
            <td>
              <a
                href={`https://threatfox.abuse.ch/ioc/${ioc.id}/`}
                target="_blank"
                rel="noopener noreferrer"
                style={{ textDecoration: 'none' }}
              >
                <code style={{ fontSize: '0.72rem', color: 'var(--accent)', opacity: 0.85 }}
                  onMouseEnter={e => (e.currentTarget.style.opacity = '1')}
                  onMouseLeave={e => (e.currentTarget.style.opacity = '0.85')}
                >{ioc.ioc} ↗</code>
              </a>
            </td>
            <td><span className="intel-badge">{ioc.ioc_type}</span></td>
            <td>{ioc.threat_type}</td>
            <td><span className="severity-badge sev-high">{ioc.malware_printable}</span></td>
            <td>
              <div style={{ width: 60, height: 6, background: 'var(--surface2)', borderRadius: 3 }}>
                <div style={{ width: `${ioc.confidence_level ?? 0}%`, height: '100%', background: '#00e676', borderRadius: 3 }} />
              </div>
            </td>
            <td style={{ fontSize: '0.72rem' }}>{Array.isArray(ioc.tags) ? ioc.tags?.join(', ') : ioc.tags ?? '—'}</td>
            <td style={{ fontSize: '0.72rem' }}>{ioc.first_seen?.slice(0, 10)}</td>
          </tr>
        ))}
      </tbody>
    </table>
  )
}
