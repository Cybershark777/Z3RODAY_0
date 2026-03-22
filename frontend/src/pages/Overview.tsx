import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import {
  Chart as ChartJS, CategoryScale, LinearScale, BarElement,
  ArcElement, Title, Tooltip, Legend,
} from 'chart.js'
import { Bar, Doughnut } from 'react-chartjs-2'
import { api } from '../services/api'
import LoadingSpinner from '../components/LoadingSpinner'

ChartJS.register(CategoryScale, LinearScale, BarElement, ArcElement, Title, Tooltip, Legend)

const CHART_OPTS = {
  responsive: true,
  maintainAspectRatio: false,
  plugins: { legend: { labels: { color: '#8b949e' } } },
  scales: {
    x: { ticks: { color: '#8b949e' }, grid: { color: '#30363d' } },
    y: { ticks: { color: '#8b949e' }, grid: { color: '#30363d' } },
  },
}

export default function Overview() {
  const [filter, setFilter] = useState('all')

  const { data: threats, isLoading: tLoading } = useQuery({
    queryKey: ['threats'],
    queryFn: api.threats,
  })
  const { data: metrics, isLoading: mLoading } = useQuery({
    queryKey: ['metrics'],
    queryFn: api.metrics,
  })
  const { data: mlData } = useQuery({
    queryKey: ['ml-detection'],
    queryFn: api.mlDetection,
    staleTime: 10 * 60 * 1000,
  })

  if (tLoading || mLoading) return <LoadingSpinner message="Loading overview data..." />

  const m = metrics ?? {}
  const allThreats: any[] = threats ?? []

  const filteredThreats = allThreats.filter((t) => {
    if (filter === 'all') return true
    if (filter === 'IT') return t.layer === 'IT'
    if (filter === 'OT') return t.layer === 'OT'
    if (filter === 'critical') return t.severity?.level === 'Critical'
    return true
  })

  // Bar chart: threat volume by category
  const barData = {
    labels: allThreats.map((t) => t.full_name?.slice(0, 18) ?? t.id),
    datasets: [{
      label: 'Event Count',
      data: allThreats.map((t) => t.event_count ?? 0),
      backgroundColor: allThreats.map((t) =>
        t.layer === 'IT' ? 'rgba(56,139,253,0.7)' : 'rgba(188,140,255,0.7)'
      ),
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
      backgroundColor: ['#388bfd', '#bc8cff', '#e3b341'],
      borderWidth: 0,
    }],
  }

  // MTTD/MTTR comparison bar chart
  const cmpData = mlData?.comparisons
    ? {
        labels: mlData.comparisons.map((c: any) => `Window ${c.window}`),
        datasets: [
          {
            label: 'Baseline MTTD (min)',
            data: mlData.comparisons.map((c: any) => c.baseline_mttd),
            backgroundColor: 'rgba(227,179,65,0.7)',
          },
          {
            label: 'ML-SOAR MTTD (min)',
            data: mlData.comparisons.map((c: any) => c.ml_mttd),
            backgroundColor: 'rgba(56,139,253,0.7)',
          },
        ],
      }
    : null

  const val = (key: string) => m[key]?.value ?? '—'

  return (
    <div className="tab-page">
      {/* Metrics Bar */}
      <div className="metrics-bar">
        <div className="metric-card">
          <div className="metric-label">MTTD (Baseline)</div>
          <div className="metric-value">{val('mttd_baseline')}</div>
          <div className="metric-sub">minutes</div>
        </div>
        <div className="metric-card accent">
          <div className="metric-label">MTTD (ML-SOAR)</div>
          <div className="metric-value">{val('mttd_ml')}</div>
          <div className="metric-sub">minutes</div>
        </div>
        <div className="metric-card">
          <div className="metric-label">MTTR (Baseline)</div>
          <div className="metric-value">{val('mttr_baseline')}</div>
          <div className="metric-sub">minutes</div>
        </div>
        <div className="metric-card accent">
          <div className="metric-label">MTTR (ML-SOAR)</div>
          <div className="metric-value">{val('mttr_ml')}</div>
          <div className="metric-sub">minutes</div>
        </div>
        <div className="metric-card">
          <div className="metric-label">Detection Accuracy</div>
          <div className="metric-value">
            {mlData?.accuracy ? `${(mlData.accuracy * 100).toFixed(1)}%` : val('accuracy')}
          </div>
          <div className="metric-sub">ML-SOAR</div>
        </div>
        <div className="metric-card">
          <div className="metric-label">False Positive Rate</div>
          <div className="metric-value">
            {mlData?.false_positive_rate ? `${(mlData.false_positive_rate * 100).toFixed(1)}%` : val('fpr')}
          </div>
          <div className="metric-sub">ML-SOAR</div>
        </div>
      </div>

      {/* Charts */}
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
                plugins: { legend: { position: 'bottom', labels: { color: '#8b949e' } } },
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
                  <span style={{ color: t.layer === 'IT' ? '#388bfd' : '#bc8cff' }}>{t.layer}</span>
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
                    <code key={id} style={{ marginRight: 4 }}>{id}</code>
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
