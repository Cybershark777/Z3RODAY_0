import { useState, useMemo } from 'react'
import { useQuery } from '@tanstack/react-query'
import {
  Chart as ChartJS, CategoryScale, LinearScale, BarElement,
  ArcElement, Title, Tooltip, Legend,
} from 'chart.js'
import { Bar, Doughnut } from 'react-chartjs-2'
import { api } from '../services/api'
import LoadingSpinner from '../components/LoadingSpinner'
import { useCountUp } from '../hooks/useCountUp'

ChartJS.register(CategoryScale, LinearScale, BarElement, ArcElement, Title, Tooltip, Legend)

const CHART_OPTS = {
  responsive: true,
  maintainAspectRatio: false,
  plugins: { legend: { labels: { color: '#4a5568' } } },
  scales: {
    x: { ticks: { color: '#4a5568' }, grid: { color: '#1c1c1c' } },
    y: { ticks: { color: '#4a5568' }, grid: { color: '#1c1c1c' } },
  },
}

// ── Risk Gauge ─────────────────────────────────────────────────────────────
function RiskGauge({ score }: { score: number }) {
  const r = 58
  const cx = 90
  const cy = 82
  const arcLen = Math.PI * r
  const fillLen = (score / 100) * arcLen
  const dashOffset = arcLen - fillLen

  const color =
    score >= 75 ? '#da3633' :
    score >= 50 ? '#e3b341' :
    '#00e676'

  const label =
    score >= 75 ? 'HIGH RISK' :
    score >= 50 ? 'ELEVATED' :
    'NOMINAL'

  return (
    <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center' }}>
      <svg width="180" height="100" viewBox="0 0 180 100">
        {/* BG arc */}
        <path
          d={`M ${cx - r},${cy} A ${r},${r} 0 0 1 ${cx + r},${cy}`}
          fill="none" stroke="var(--surface3)" strokeWidth="14" strokeLinecap="round"
        />
        {/* Value arc */}
        <path
          d={`M ${cx - r},${cy} A ${r},${r} 0 0 1 ${cx + r},${cy}`}
          fill="none" stroke={color} strokeWidth="14" strokeLinecap="round"
          strokeDasharray={`${arcLen}`}
          strokeDashoffset={`${dashOffset}`}
          style={{ transition: 'stroke-dashoffset 1.2s cubic-bezier(0.25,1,0.5,1), stroke 0.5s ease' }}
          filter={`drop-shadow(0 0 6px ${color})`}
        />
        <text x={cx} y={cy - 12} textAnchor="middle" fill="var(--text)" fontSize="26" fontWeight="700">
          {score}
        </text>
        <text x={cx} y={cy + 6} textAnchor="middle" fill="var(--text-muted)" fontSize="10" letterSpacing="1">
          RISK SCORE
        </text>
        <text x={cx} y={cy + 20} textAnchor="middle" fill={color} fontSize="9" fontWeight="600" letterSpacing="1">
          {label}
        </text>
      </svg>
    </div>
  )
}

// ── Attack Timeline ────────────────────────────────────────────────────────
function AttackTimeline({ threats }: { threats: any[] }) {
  const sorted = [...threats]
    .sort((a, b) => (b.event_count ?? 0) - (a.event_count ?? 0))
    .slice(0, 12)

  const sevColor: Record<string, string> = {
    Critical: '#da3633',
    High: '#e3b341',
    Medium: '#00e676',
    Low: '#00bcd4',
  }

  return (
    <div className="timeline-wrapper">
      <div className="timeline-track">
        {sorted.map((t, i) => {
          const sev = t.severity?.level ?? 'Low'
          const color = sevColor[sev] ?? '#00bcd4'
          return (
            <div key={t.id} className="timeline-node" style={{ animationDelay: `${i * 80}ms` }}>
              <div className="timeline-dot" style={{ background: color, boxShadow: `0 0 8px ${color}` }} />
              <div className="timeline-line" />
              <div className="timeline-card">
                <span className="timeline-sev" style={{ color }}>{sev}</span>
                <span className="timeline-name">{t.full_name?.slice(0, 22) ?? t.id}</span>
                <span className="timeline-count">{(t.event_count ?? 0).toLocaleString()} events</span>
              </div>
            </div>
          )
        })}
      </div>
    </div>
  )
}

// ── CSV Export ─────────────────────────────────────────────────────────────
function exportCSV(threats: any[]) {
  const headers = ['ID', 'Name', 'Layer', 'Severity', 'Event Count', 'Affected Systems', 'MITRE ICS IDs', 'Dataset']
  const rows = threats.map((t) => [
    t.id,
    `"${t.full_name ?? ''}"`,
    t.layer,
    t.severity?.level ?? '',
    t.event_count ?? 0,
    `"${(t.affected_systems ?? []).join('; ')}"`,
    `"${(t.mitre_ics_ids ?? []).join(', ')}"`,
    t.dataset_ref ?? '',
  ])
  const csv = [headers.join(','), ...rows.map((r) => r.join(','))].join('\n')
  const blob = new Blob([csv], { type: 'text/csv' })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = `cps-threats-${new Date().toISOString().slice(0, 10)}.csv`
  a.click()
  URL.revokeObjectURL(url)
}

// ── Animated Metric Card ───────────────────────────────────────────────────
function MetricCard({ label, rawValue, sub, accent }: {
  label: string
  rawValue: number
  sub: string
  accent?: boolean
}) {
  const animated = useCountUp(rawValue)
  return (
    <div className={`metric-card${accent ? ' accent' : ''}`}>
      <div className="metric-label">{label}</div>
      <div className="metric-value metric-animated">{animated || rawValue || '—'}</div>
      <div className="metric-sub">{sub}</div>
    </div>
  )
}

// ── Main Component ─────────────────────────────────────────────────────────
export default function Overview() {
  const [filter, setFilter] = useState('all')

  const { data: threats, isLoading: tLoading } = useQuery({
    queryKey: ['threats'],
    queryFn: api.threats,
  })
  const { data: mlData } = useQuery({
    queryKey: ['ml-detection'],
    queryFn: api.mlDetection,
    staleTime: 10 * 60 * 1000,
  })

  if (tLoading) return <LoadingSpinner message="Loading overview data..." />

  const allThreats: any[] = threats ?? []

  const filteredThreats = allThreats.filter((t) => {
    if (filter === 'all') return true
    if (filter === 'IT') return t.layer === 'IT'
    if (filter === 'OT') return t.layer === 'OT'
    if (filter === 'critical') return t.severity?.level === 'Critical'
    return true
  })

  // Risk score: weighted by severity
  const sevWeights: Record<string, number> = { Critical: 100, High: 65, Medium: 35, Low: 10 }
  const riskScore = allThreats.length
    ? Math.round(
        allThreats.reduce((sum, t) => sum + (sevWeights[t.severity?.level ?? 'Low'] ?? 10), 0) /
        allThreats.length
      )
    : 0

  // Bar chart: threat volume by category
  const barData = {
    labels: allThreats.map((t) => t.full_name?.slice(0, 18) ?? t.id),
    datasets: [{
      label: 'Event Count',
      data: allThreats.map((t) => t.event_count ?? 0),
      backgroundColor: allThreats.map((t) =>
        t.layer === 'IT' ? 'rgba(0,230,118,0.55)' : 'rgba(0,188,212,0.55)'
      ),
      borderColor: allThreats.map((t) =>
        t.layer === 'IT' ? '#00e676' : '#00bcd4'
      ),
      borderWidth: 1,
      borderRadius: 3,
    }],
  }

  // Donut: IT vs OT
  const itCount = allThreats.filter((t) => t.layer === 'IT').length
  const otCount = allThreats.filter((t) => t.layer === 'OT').length
  const bothCount = allThreats.length - itCount - otCount
  const donutData = {
    labels: ['IT', 'OT', 'Both'],
    datasets: [{
      data: [itCount, otCount, bothCount],
      backgroundColor: ['rgba(0,230,118,0.65)', 'rgba(0,188,212,0.65)', 'rgba(227,179,65,0.65)'],
      borderColor: ['#00e676', '#00bcd4', '#e3b341'],
      borderWidth: 1,
    }],
  }

  // MTTD/MTTR comparison
  const cmpData = mlData?.comparisons
    ? {
        labels: mlData.comparisons.map((c: any) => `Window ${c.window}`),
        datasets: [
          {
            label: 'Baseline MTTD (min)',
            data: mlData.comparisons.map((c: any) => c.baseline_mttd),
            backgroundColor: 'rgba(227,179,65,0.7)',
            borderColor: '#e3b341',
            borderWidth: 1,
            borderRadius: 3,
          },
          {
            label: 'ML-SOAR MTTD (min)',
            data: mlData.comparisons.map((c: any) => c.ml_mttd),
            backgroundColor: 'rgba(0,180,255,0.6)',
            borderColor: '#00e676',
            borderWidth: 1,
            borderRadius: 3,
          },
        ],
      }
    : null

  // Derive MTTD/MTTR from ML comparisons (average across windows)
  const avgBaseMTTD = mlData?.comparisons?.length
    ? Math.round(mlData.comparisons.reduce((s: number, c: any) => s + c.baseline_mttd, 0) / mlData.comparisons.length)
    : 0
  const avgMlMTTD = mlData?.comparisons?.length
    ? Math.round(mlData.comparisons.reduce((s: number, c: any) => s + c.ml_mttd, 0) / mlData.comparisons.length * 10) / 10
    : 0

  return (
    <div className="tab-page">
      {/* Top row: metrics + gauge */}
      <div style={{ display: 'flex', gap: '1rem', marginBottom: '1.5rem', flexWrap: 'wrap', alignItems: 'flex-start' }}>
        <div className="metrics-bar" style={{ flex: 1, marginBottom: 0 }}>
          <MetricCard label="MTTD (Baseline)" rawValue={avgBaseMTTD} sub="minutes avg" />
          <MetricCard label="MTTD (ML-SOAR)" rawValue={avgMlMTTD} sub="minutes avg" accent />
          <MetricCard label="MTTR (Baseline)" rawValue={avgBaseMTTD ? Math.round(avgBaseMTTD * 2.4) : 0} sub="minutes est." />
          <MetricCard label="MTTR (ML-SOAR)" rawValue={avgMlMTTD ? Math.round(avgMlMTTD * 2.4) : 0} sub="minutes est." accent />
          <MetricCard
            label="Detection Accuracy"
            rawValue={mlData?.accuracy ? Math.round(mlData.accuracy * 100) : 0}
            sub="% ML-SOAR"
            accent
          />
          <MetricCard
            label="False Positive Rate"
            rawValue={mlData?.false_positive_rate ? Math.round(mlData.false_positive_rate * 100) : 0}
            sub="% ML-SOAR"
          />
        </div>
        <div className="chart-card" style={{ minWidth: 200, flexShrink: 0, display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center' }}>
          <h2 style={{ marginBottom: '0.75rem' }}>Overall Risk</h2>
          <RiskGauge score={riskScore} />
          <div style={{ marginTop: '0.5rem', fontSize: '0.75rem', color: 'var(--text-muted)', textAlign: 'center' }}>
            {allThreats.length} active threat classes
          </div>
        </div>
      </div>

      {/* Attack Timeline */}
      <div className="chart-card" style={{ marginBottom: '1.5rem' }}>
        <h2>Attack Event Timeline — Top Threats by Volume</h2>
        <AttackTimeline threats={allThreats} />
      </div>

      {/* Charts Row */}
      <div className="charts-row">
        <div className="chart-card">
          <h2>Threat Volume by Category</h2>
          <div style={{ height: 220 }}>
            <Bar data={barData} options={CHART_OPTS as any} />
          </div>
        </div>
        <div className="chart-card chart-card-sm">
          <h2>IT vs OT Layer Distribution</h2>
          <div style={{ height: 220 }}>
            <Doughnut
              data={donutData}
              options={{
                responsive: true,
                maintainAspectRatio: false,
                plugins: { legend: { position: 'bottom', labels: { color: '#4a5568' } } },
              }}
            />
          </div>
        </div>
        {cmpData && (
          <div className="chart-card chart-card-sm">
            <h2>MTTD / MTTR Comparison</h2>
            <div style={{ height: 220 }}>
              <Bar
                data={cmpData}
                options={{ ...CHART_OPTS as any, plugins: { ...CHART_OPTS.plugins, title: { display: false } } }}
              />
            </div>
          </div>
        )}
      </div>

      {/* Threat Table */}
      <div className="table-section">
        <div className="table-header">
          <h2>Active Threat Intelligence</h2>
          <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center', flexWrap: 'wrap' }}>
            <div className="filters">
              {['all', 'IT', 'OT', 'critical'].map((f) => (
                <button
                  key={f}
                  className={`filter-btn${filter === f ? ' active' : ''}`}
                  onClick={() => setFilter(f)}
                >
                  {f === 'all' ? 'All' : f === 'critical' ? 'Critical' : `${f} Layer`}
                </button>
              ))}
            </div>
            <button className="export-btn" onClick={() => exportCSV(filteredThreats)} title="Export CSV">
              ↓ Export CSV
            </button>
          </div>
        </div>
        <table>
          <thead>
            <tr>
              <th>Threat</th>
              <th>Layer</th>
              <th>Severity</th>
              <th>Event Count</th>
              <th>Affected Systems</th>
              <th>MITRE ICS IDs</th>
              <th>Dataset</th>
            </tr>
          </thead>
          <tbody>
            {filteredThreats.map((t: any) => (
              <tr key={t.id}>
                <td style={{ fontWeight: 500 }}>{t.full_name}</td>
                <td>
                  <span style={{ color: t.layer === 'IT' ? '#00e676' : '#00bcd4' }}>{t.layer}</span>
                </td>
                <td>
                  <span className={`severity-badge sev-${t.severity?.level?.toLowerCase()}`}>
                    {t.severity?.level}
                  </span>
                </td>
                <td>{t.event_count?.toLocaleString()}</td>
                <td className="desc-text">{(t.affected_systems ?? []).join(', ')}</td>
                <td>
                  {(t.mitre_ics_ids ?? []).slice(0, 3).map((id: string) => (
                    <a
                      key={id}
                      href={`https://attack.mitre.org/techniques/${id}/`}
                      target="_blank"
                      rel="noopener noreferrer"
                      title={`View ${id} on MITRE ATT&CK`}
                      style={{ marginRight: 4, textDecoration: 'none' }}
                    >
                      <code style={{
                        color: 'var(--accent)',
                        borderColor: 'var(--accent)',
                        opacity: 0.85,
                        transition: 'opacity 0.15s',
                      }}
                        onMouseEnter={e => (e.currentTarget.style.opacity = '1')}
                        onMouseLeave={e => (e.currentTarget.style.opacity = '0.85')}
                      >{id}</code>
                    </a>
                  ))}
                  {(t.mitre_ics_ids ?? []).length > 3 && (
                    <span style={{ color: 'var(--text-muted)', fontSize: '0.75rem' }}>
                      +{t.mitre_ics_ids.length - 3}
                    </span>
                  )}
                </td>
                <td style={{ fontSize: '0.78rem', color: 'var(--text-muted)' }}>{t.dataset_ref}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}
