import { useState, useEffect, useRef, useCallback } from 'react'
import { useQuery } from '@tanstack/react-query'
import {
  Chart as ChartJS, CategoryScale, LinearScale, LineElement, PointElement,
  BarElement, Title, Tooltip, Legend, Filler,
} from 'chart.js'
import { Line, Bar, Scatter } from 'react-chartjs-2'
import { api, createSensorStreamSocket } from '../services/api'
import LoadingSpinner from '../components/LoadingSpinner'

ChartJS.register(CategoryScale, LinearScale, LineElement, PointElement, BarElement, Title, Tooltip, Legend, Filler)

const DARK = {
  scales: {
    x: { ticks: { color: '#4a5568' }, grid: { color: '#1c1c1c' } },
    y: { ticks: { color: '#4a5568' }, grid: { color: '#1c1c1c' } },
  },
  plugins: { legend: { labels: { color: '#8a9bb0' } } },
} as any

const ATTACK_TYPE_LABELS: Record<string, string> = {
  single_actuator:   'Single Actuator Spike',
  coordinated_multi: 'Coordinated Multi-Sensor',
  slow_drift:        'Gradual Drift (Slow-Poison)',
}

const MODEL_INFO = [
  { key: 'zscore',     label: 'Z-Score',          color: '#00e676', accKey: 'accuracy',       fprKey: 'false_positive_rate', mttdKey: 'zscore',     desc: 'Rolling max Z-score across sensors (window=60). Fast to detect sharp spikes.' },
  { key: 'iso_forest', label: 'Isolation Forest',  color: '#00bcd4', accKey: 'accuracy_if',    fprKey: 'fpr_if',              mttdKey: 'iso_forest', desc: 'Liu et al. (2008) isolation depth simulation. Excels at multi-dimensional anomalies.' },
  { key: 'drift',      label: 'Dual-Window Drift', color: '#e3b341', accKey: 'accuracy_drift',  fprKey: 'fpr_drift',           mttdKey: 'drift',      desc: 'Short-window mean vs long-window baseline. Uniquely detects slow-poison attacks.' },
  { key: 'baseline',   label: 'Signature Baseline',color: '#ff6b6b', accKey: 'accuracy_baseline',fprKey: 'fpr_baseline',      mttdKey: 'baseline',   desc: 'Static threshold rules — current OT/ICS industry standard.' },
]

// Ring buffer for live stream chart
const STREAM_WINDOW = 80

type StreamReading = {
  step: number
  readings: Record<string, number>
  z_scores: Record<string, number>
  drift_scores: Record<string, number>
  if_scores: Record<string, number>
  max_z: number
  max_drift: number
  max_if: number
  is_attack: boolean
  atk_remaining: number
  alert_level: 'normal' | 'warning' | 'critical'
}

export default function MLSoar() {
  const [tab, setTab] = useState<'overview' | 'live' | 'compare' | 'stats'>('overview')

  const { data, isLoading } = useQuery({
    queryKey: ['ml-detection'],
    queryFn: api.mlDetection,
    staleTime: 10 * 60 * 1000,
  })

  if (isLoading) return <LoadingSpinner message="Loading ML-SOAR analysis..." />
  if (!data) return null

  return (
    <div className="tab-page">
      <div className="section-header">
        <h2>ML-SOAR: Anomaly Detection Engine</h2>
        <p className="section-desc">
          Multi-model ICS anomaly detection on synthetic SWaT dataset. Compares Z-Score, Isolation Forest,
          and Dual-Window Drift detection with bootstrap confidence intervals and live sensor streaming.
        </p>
      </div>

      {/* Tab nav */}
      <div style={{ display: 'flex', gap: '0.5rem', marginBottom: '1.5rem', flexWrap: 'wrap' }}>
        {[
          { id: 'overview', label: 'Overview' },
          { id: 'live',     label: '⚡ Live Stream' },
          { id: 'compare',  label: 'Model Comparison' },
          { id: 'stats',    label: 'Statistical Analysis' },
        ].map((t) => (
          <button
            key={t.id}
            className={`filter-btn${tab === t.id ? ' active' : ''}`}
            style={{ padding: '0.45rem 1rem', fontWeight: tab === t.id ? 700 : 400 }}
            onClick={() => setTab(t.id as any)}
          >{t.label}</button>
        ))}
      </div>

      {tab === 'overview' && <OverviewTab data={data} />}
      {tab === 'live'     && <LiveStreamTab />}
      {tab === 'compare'  && <CompareTab data={data} />}
      {tab === 'stats'    && <StatsTab data={data} />}
    </div>
  )
}

/* ── Overview Tab ──────────────────────────────────────────────────────────── */
function OverviewTab({ data }: { data: any }) {
  const steps = Array.from({ length: data.steps }, (_, i) => i)
  const sparse = (_: any, i: number) => i % 5 === 0

  const sensorChart = {
    labels: steps.filter(sparse),
    datasets: data.sensors.slice(0, 3).map((s: any, i: number) => ({
      label: `${s.name} (${s.unit})`,
      data: data.series[s.name].filter(sparse),
      borderColor: ['#00e676','#00bcd4','#e3b341'][i],
      borderWidth: 1.5, pointRadius: 0, tension: 0.3,
    })),
  }

  const anomalyChart = {
    labels: steps.filter(sparse),
    datasets: [
      { label: 'Z-Score', data: data.z_scores.filter(sparse), borderColor: '#00e676', borderWidth: 1.5, pointRadius: 0, tension: 0.3, fill: false },
      { label: 'Isolation Forest', data: data.if_scores.filter(sparse), borderColor: '#00bcd4', borderWidth: 1.5, pointRadius: 0, tension: 0.3, fill: false },
      { label: 'Drift', data: data.drift_scores.filter(sparse), borderColor: '#e3b341', borderWidth: 1.5, pointRadius: 0, tension: 0.3, fill: false },
    ],
  }

  const mttdChart = {
    labels: (data.comparisons ?? []).map((c: any) => `Attack ${c.window}`),
    datasets: [
      { label: 'Baseline (min)', data: (data.comparisons ?? []).map((c: any) => c.baseline_mttd), backgroundColor: 'rgba(255,107,107,0.7)' },
      { label: 'Z-Score (min)',  data: (data.comparisons ?? []).map((c: any) => c.ml_mttd),       backgroundColor: 'rgba(0,230,118,0.7)' },
    ],
  }

  const s = data.mttd_summary ?? {}
  return (
    <>
      {/* Metric cards */}
      <div className="metrics-bar" style={{ marginBottom: '1.5rem' }}>
        {MODEL_INFO.map((m) => (
          <div key={m.key} className={`metric-card${m.key === 'zscore' ? ' accent' : ''}`}>
            <div className="metric-label">{m.label}</div>
            <div className="metric-value" style={{ color: m.color }}>
              {data[m.accKey] ? (data[m.accKey] * 100).toFixed(1) + '%' : '—'}
            </div>
            <div className="metric-sub">accuracy</div>
          </div>
        ))}
      </div>

      {/* MTTD summary with CI */}
      {s.zscore && (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4,1fr)', gap: '0.75rem', marginBottom: '1.5rem' }}>
          {[
            { label: 'Baseline MTTD', m: s.baseline, color: '#ff6b6b' },
            { label: 'Z-Score MTTD',  m: s.zscore,   color: '#00e676' },
            { label: 'IF MTTD',       m: s.iso_forest, color: '#00bcd4' },
            { label: 'Drift MTTD',    m: s.drift,    color: '#e3b341' },
          ].map(({ label, m, color }) => (
            <div key={label} className="metric-card">
              <div className="metric-label">{label}</div>
              <div className="metric-value" style={{ fontSize: '1.3rem', color }}>{m.mean} min</div>
              <div className="metric-sub" style={{ fontSize: '0.7rem' }}>
                95% CI [{m.ci_lo} – {m.ci_hi}]
              </div>
            </div>
          ))}
        </div>
      )}

      <div className="ml-chart-section">
        <h3>SWaT Sensor Time Series</h3>
        <div style={{ height: 200 }}>
          <Line data={sensorChart} options={{ ...DARK, responsive: true, maintainAspectRatio: false }} />
        </div>
        <div style={{ marginTop: '0.4rem', fontSize: '0.74rem', color: 'var(--text-muted)' }}>
          Attack windows: steps 120–160 (single actuator) · 270–310 (coordinated) · 400–450 (slow drift) | Train: 0–299 · Val: 300–399 · Test: 400–499
        </div>
      </div>

      <div className="ml-chart-section">
        <h3>All 3 Anomaly Scores — Comparison</h3>
        <div style={{ height: 200 }}>
          <Line data={anomalyChart} options={{ ...DARK, responsive: true, maintainAspectRatio: false }} />
        </div>
      </div>

      <div className="charts-row">
        <div className="chart-card">
          <h2>MTTD: Baseline vs Z-Score (minutes)</h2>
          <div style={{ height: 220 }}>
            <Bar data={mttdChart} options={{ ...DARK, responsive: true, maintainAspectRatio: false }} />
          </div>
        </div>
        <div className="chart-card chart-card-sm">
          <h2>ROC Curves (AUC comparison)</h2>
          <div style={{ height: 220 }}>
            <Scatter
              data={{
                datasets: [
                  { label: 'Z-Score',    data: (data.roc_points ?? []).map((p: any) => ({ x: p.fpr, y: p.tpr })),       borderColor: '#00e676', showLine: true, pointRadius: 2, fill: false },
                  { label: 'Iso Forest', data: (data.roc_if_points ?? []).map((p: any) => ({ x: p.fpr, y: p.tpr })),    borderColor: '#00bcd4', showLine: true, pointRadius: 2, fill: false },
                  { label: 'Drift',      data: (data.roc_drift_points ?? []).map((p: any) => ({ x: p.fpr, y: p.tpr })), borderColor: '#e3b341', showLine: true, pointRadius: 2, fill: false },
                  { label: 'Random',     data: [{ x: 0, y: 0 }, { x: 1, y: 1 }], borderColor: '#333', borderDash: [4, 4], showLine: true, pointRadius: 0, fill: false },
                ],
              }}
              options={{
                responsive: true, maintainAspectRatio: false,
                scales: {
                  x: { min: 0, max: 1, title: { display: true, text: 'FPR', color: '#4a5568' }, ticks: { color: '#4a5568' }, grid: { color: '#1c1c1c' } },
                  y: { min: 0, max: 1, title: { display: true, text: 'TPR', color: '#4a5568' }, ticks: { color: '#4a5568' }, grid: { color: '#1c1c1c' } },
                },
                plugins: { legend: { labels: { color: '#8a9bb0' } } },
              }}
            />
          </div>
        </div>
      </div>
    </>
  )
}

/* ── Live Stream Tab ───────────────────────────────────────────────────────── */
function LiveStreamTab() {
  const [buffer, setBuffer] = useState<StreamReading[]>([])
  const [connected, setConnected] = useState(false)
  const [alertLevel, setAlertLevel] = useState<string>('normal')
  const [isAttack, setIsAttack] = useState(false)
  const [atkRemaining, setAtkRemaining] = useState(0)
  const wsRef = useRef<WebSocket | null>(null)

  const connect = useCallback(() => {
    if (wsRef.current) wsRef.current.close()
    const ws = createSensorStreamSocket(
      (d: StreamReading) => {
        setBuffer((prev) => {
          const next = [...prev, d]
          return next.length > STREAM_WINDOW ? next.slice(-STREAM_WINDOW) : next
        })
        setAlertLevel(d.alert_level)
        setIsAttack(d.is_attack)
        setAtkRemaining(d.atk_remaining)
      },
      () => setConnected(false),
    )
    ws.onopen = () => setConnected(true)
    wsRef.current = ws
  }, [])

  useEffect(() => {
    connect()
    return () => wsRef.current?.close()
  }, [connect])

  const injectAttack = () => {
    wsRef.current?.send(JSON.stringify({ action: 'inject_attack' }))
  }

  const labels = buffer.map((r) => r.step)

  const scoreChart = {
    labels,
    datasets: [
      { label: 'Z-Score',   data: buffer.map((r) => r.max_z),     borderColor: '#00e676', borderWidth: 1.5, pointRadius: 0, tension: 0.2, fill: false },
      { label: 'IF Score',  data: buffer.map((r) => r.max_if),    borderColor: '#00bcd4', borderWidth: 1.5, pointRadius: 0, tension: 0.2, fill: false },
      { label: 'Drift',     data: buffer.map((r) => r.max_drift),  borderColor: '#e3b341', borderWidth: 1.5, pointRadius: 0, tension: 0.2, fill: false },
    ],
  }

  const sensorChart = {
    labels,
    datasets: ['FIT-101', 'LIT-101'].map((name, i) => ({
      label: name,
      data: buffer.map((r) => r.readings[name] ?? null),
      borderColor: ['#00e676','#00bcd4'][i],
      borderWidth: 1.5, pointRadius: 0, tension: 0.2, fill: false,
    })),
  }

  const alertColor = { normal: '#00e676', warning: '#e3b341', critical: '#ff6b6b' }[alertLevel] ?? '#00e676'
  const last = buffer[buffer.length - 1]

  return (
    <div>
      {/* Status bar */}
      <div style={{ display: 'flex', gap: '1rem', alignItems: 'center', marginBottom: '1.25rem', flexWrap: 'wrap' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          <div style={{ width: 10, height: 10, borderRadius: '50%', background: connected ? '#00e676' : '#ff6b6b' }} />
          <span style={{ fontSize: '0.82rem', color: 'var(--text-muted)' }}>
            {connected ? 'Live — streaming sensor data' : 'Disconnected'}
          </span>
        </div>
        <div style={{ padding: '0.3rem 0.9rem', borderRadius: 20, background: alertColor + '22', border: `1px solid ${alertColor}`, color: alertColor, fontWeight: 700, fontSize: '0.8rem', textTransform: 'uppercase' }}>
          {alertLevel}
        </div>
        {isAttack && (
          <div style={{ color: '#ff6b6b', fontWeight: 700, fontSize: '0.82rem', animation: 'pulse 1s infinite' }}>
            ⚠ ATTACK ACTIVE — {atkRemaining} steps remaining
          </div>
        )}
        <div style={{ marginLeft: 'auto', display: 'flex', gap: '0.5rem' }}>
          <button className="primary-btn" onClick={injectAttack} disabled={!connected || isAttack}>
            Inject Attack
          </button>
          {!connected && <button className="filter-btn" onClick={connect}>Reconnect</button>}
        </div>
      </div>

      {/* Live score gauges */}
      {last && (
        <div className="metrics-bar" style={{ marginBottom: '1.25rem' }}>
          {[
            { label: 'Z-Score',        value: last.max_z,     thresh: 2.5,  color: '#00e676' },
            { label: 'Isolation Forest', value: last.max_if,  thresh: 0.68, color: '#00bcd4' },
            { label: 'Drift Score',    value: last.max_drift,  thresh: 1.2,  color: '#e3b341' },
          ].map(({ label, value, thresh, color }) => {
            const triggered = value > thresh
            return (
              <div key={label} className={`metric-card${triggered ? ' accent' : ''}`} style={{ borderColor: triggered ? color : undefined }}>
                <div className="metric-label">{label}</div>
                <div className="metric-value" style={{ fontSize: '1.5rem', color: triggered ? color : 'var(--text)' }}>
                  {value.toFixed(3)}
                </div>
                <div className="metric-sub">threshold: {thresh} {triggered ? '⚠ ALERT' : '✓ normal'}</div>
              </div>
            )
          })}
        </div>
      )}

      <div className="ml-chart-section">
        <h3>Live Anomaly Scores — All 3 Models</h3>
        <div style={{ height: 200 }}>
          <Line data={scoreChart} options={{ ...DARK, responsive: true, maintainAspectRatio: false, animation: { duration: 0 } }} />
        </div>
      </div>

      <div className="ml-chart-section">
        <h3>Live Sensor Readings (FIT-101 · LIT-101)</h3>
        <div style={{ height: 180 }}>
          <Line data={sensorChart} options={{ ...DARK, responsive: true, maintainAspectRatio: false, animation: { duration: 0 } }} />
        </div>
      </div>

      <div style={{ marginTop: '1rem', padding: '0.75rem 1rem', background: 'var(--surface)', borderRadius: 6, fontSize: '0.78rem', color: 'var(--text-muted)', lineHeight: 1.6 }}>
        <strong style={{ color: 'var(--accent)' }}>How it works:</strong> Each tick (500ms) generates a new SWaT sensor reading.
        Z-Score uses a 60-step rolling window. Isolation Forest simulates Liu et al. (2008) path-length isolation scoring.
        Dual-Window Drift compares a 30-step short window against a 150-step long baseline — uniquely effective against slow-poison attacks that evade Z-score.
        Click <strong>Inject Attack</strong> to trigger a 20-second synthetic attack and watch all 3 detectors respond.
      </div>
    </div>
  )
}

/* ── Compare Tab ───────────────────────────────────────────────────────────── */
function CompareTab({ data }: { data: any }) {
  const breakdown: any[] = data.attack_breakdown ?? []

  return (
    <div>
      {/* Model cards */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2,1fr)', gap: '1rem', marginBottom: '1.5rem' }}>
        {MODEL_INFO.map((m) => (
          <div key={m.key} className="metric-card" style={{ borderLeft: `3px solid ${m.color}`, padding: '1rem' }}>
            <div style={{ fontWeight: 700, color: m.color, marginBottom: '0.4rem' }}>{m.label}</div>
            <div style={{ fontSize: '0.78rem', color: 'var(--text-muted)', marginBottom: '0.75rem' }}>{m.desc}</div>
            <div style={{ display: 'flex', gap: '1.5rem' }}>
              <div>
                <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>Accuracy</div>
                <div style={{ fontSize: '1.1rem', fontWeight: 700, color: m.color }}>
                  {data[m.accKey] ? (data[m.accKey] * 100).toFixed(1) + '%' : '—'}
                </div>
              </div>
              <div>
                <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>FPR</div>
                <div style={{ fontSize: '1.1rem', fontWeight: 700 }}>
                  {data[m.fprKey] ? (data[m.fprKey] * 100).toFixed(1) + '%' : '—'}
                </div>
              </div>
              <div>
                <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>Avg MTTD</div>
                <div style={{ fontSize: '1.1rem', fontWeight: 700 }}>
                  {data.mttd_summary?.[m.mttdKey]?.mean ?? '—'} min
                </div>
              </div>
            </div>
          </div>
        ))}
      </div>

      {/* Per-attack-type breakdown table */}
      <h3 style={{ color: 'var(--accent)', marginBottom: '0.75rem' }}>Per-Attack-Type MTTD Breakdown</h3>
      <p style={{ fontSize: '0.78rem', color: 'var(--text-muted)', marginBottom: '1rem' }}>
        Each attack type exploits different statistical properties. No single model dominates — illustrating the need for ensemble detection.
      </p>
      <table className="intel-table">
        <thead>
          <tr>
            <th>Attack</th>
            <th>Type</th>
            <th>Baseline</th>
            <th style={{ color: '#00e676' }}>Z-Score</th>
            <th style={{ color: '#00bcd4' }}>Iso Forest</th>
            <th style={{ color: '#e3b341' }}>Drift</th>
            <th>Best Model</th>
          </tr>
        </thead>
        <tbody>
          {breakdown.map((row: any) => {
            const mttds = { 'Z-Score': row.z_mttd, 'Iso Forest': row.if_mttd, 'Drift': row.drift_mttd }
            const best = Object.entries(mttds).reduce((a, b) => a[1] < b[1] ? a : b)
            return (
              <tr key={row.window}>
                <td><strong>{row.label}</strong></td>
                <td><span style={{ fontSize: '0.74rem', color: 'var(--text-muted)' }}>{ATTACK_TYPE_LABELS[row.attack_type] ?? row.attack_type}</span></td>
                <td style={{ color: '#ff6b6b' }}>{row.baseline_mttd} min</td>
                <td style={{ color: '#00e676' }}>
                  {row.z_mttd} min
                  <span style={{ fontSize: '0.68rem', color: 'var(--text-muted)', marginLeft: 4 }}>↓{row.z_improvement}%</span>
                </td>
                <td style={{ color: '#00bcd4' }}>
                  {row.if_mttd} min
                  <span style={{ fontSize: '0.68rem', color: 'var(--text-muted)', marginLeft: 4 }}>↓{row.if_improvement}%</span>
                </td>
                <td style={{ color: '#e3b341' }}>
                  {row.drift_mttd} min
                  <span style={{ fontSize: '0.68rem', color: 'var(--text-muted)', marginLeft: 4 }}>↓{row.drift_improvement}%</span>
                </td>
                <td><span style={{ background: 'var(--accent)', color: '#000', borderRadius: 4, padding: '2px 6px', fontSize: '0.72rem', fontWeight: 700 }}>{best[0]}</span></td>
              </tr>
            )
          })}
        </tbody>
      </table>

      <div style={{ marginTop: '1rem', padding: '0.75rem 1rem', background: 'var(--surface)', borderRadius: 6, fontSize: '0.78rem', color: 'var(--text-muted)', lineHeight: 1.7 }}>
        <strong style={{ color: 'var(--accent)' }}>Key finding:</strong> Z-Score and Isolation Forest both excel at fast, sharp anomalies (single actuator spikes, coordinated attacks).
        Dual-Window Drift uniquely detects slow-poison attacks — attacks that gradually shift sensor readings to avoid triggering rolling-window detectors.
        This motivates an ensemble approach combining all three for production ICS deployments.
      </div>
    </div>
  )
}

/* ── Statistical Analysis Tab ──────────────────────────────────────────────── */
function StatsTab({ data }: { data: any }) {
  const split = data.split_info ?? {}
  const s = data.mttd_summary ?? {}
  const breakdown: any[] = data.attack_breakdown ?? []

  return (
    <div>
      {/* Train/Val/Test split */}
      <h3 style={{ color: 'var(--accent)', marginBottom: '0.75rem' }}>Train / Validation / Test Split</h3>
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3,1fr)', gap: '1rem', marginBottom: '1.5rem' }}>
        {[
          { label: 'Training Set',   steps: `Steps 0–${split.train_end}`,   attacks: 'Attacks 1–2',       note: 'Model fitting & rolling baseline establishment' },
          { label: 'Validation Set', steps: `Steps ${split.train_end+1}–${split.val_end}`, attacks: 'Attack 2 tail',  note: 'Threshold τ tuning via Youden Index maximisation' },
          { label: 'Test Set',       steps: `Steps ${split.val_end+1}–${split.test_end}`, attacks: 'Attack 3',       note: 'Final reported metrics — never used for tuning' },
        ].map(({ label, steps, attacks, note }) => (
          <div key={label} className="metric-card" style={{ padding: '1rem' }}>
            <div style={{ fontWeight: 700, color: 'var(--accent)', marginBottom: '0.3rem' }}>{label}</div>
            <div style={{ fontSize: '0.82rem', marginBottom: '0.25rem' }}>{steps}</div>
            <div style={{ fontSize: '0.74rem', color: '#e3b341', marginBottom: '0.4rem' }}>{attacks}</div>
            <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)' }}>{note}</div>
          </div>
        ))}
      </div>

      {/* Bootstrap CI table */}
      <h3 style={{ color: 'var(--accent)', marginBottom: '0.75rem' }}>Bootstrap Confidence Intervals (n=1,000 resamples)</h3>
      <p style={{ fontSize: '0.78rem', color: 'var(--text-muted)', marginBottom: '1rem' }}>
        MTTD estimates with 95% bootstrap confidence intervals. Narrower intervals indicate more consistent detection across attack scenarios.
      </p>
      <table className="intel-table" style={{ marginBottom: '1.5rem' }}>
        <thead>
          <tr><th>Model</th><th>Mean MTTD</th><th>95% CI Lower</th><th>95% CI Upper</th><th>CI Width</th><th>Improvement vs Baseline</th></tr>
        </thead>
        <tbody>
          {s.baseline && [
            { label: 'Signature Baseline', m: s.baseline,   color: '#ff6b6b', key: 'baseline' },
            { label: 'Z-Score',            m: s.zscore,     color: '#00e676', key: 'zscore' },
            { label: 'Isolation Forest',   m: s.iso_forest, color: '#00bcd4', key: 'iso_forest' },
            { label: 'Dual-Window Drift',  m: s.drift,      color: '#e3b341', key: 'drift' },
          ].map(({ label, m, color }) => {
            const width = (m.ci_hi - m.ci_lo).toFixed(2)
            const improv = label !== 'Signature Baseline'
              ? ((1 - m.mean / s.baseline.mean) * 100).toFixed(1) + '%'
              : '—'
            return (
              <tr key={label}>
                <td style={{ color }}><strong>{label}</strong></td>
                <td style={{ color }}>{m.mean} min</td>
                <td>{m.ci_lo} min</td>
                <td>{m.ci_hi} min</td>
                <td style={{ color: 'var(--text-muted)' }}>±{width} min</td>
                <td style={{ color: label !== 'Signature Baseline' ? '#00e676' : 'var(--text-muted)' }}>{improv}</td>
              </tr>
            )
          })}
        </tbody>
      </table>

      {/* Gaussianity & assumptions */}
      <h3 style={{ color: 'var(--accent)', marginBottom: '0.75rem' }}>Statistical Assumptions & Validity</h3>
      <div style={{ display: 'flex', flexDirection: 'column', gap: '0.6rem' }}>
        {[
          { title: 'Gaussianity', status: 'partial', text: 'Z-score assumes approximately Gaussian sensor distributions within rolling windows. SWaT actuator sensors (on/off valves) are bimodal — violating this assumption. Robust Z-score with MAD (median absolute deviation) would improve performance.' },
          { title: 'Window Stationarity', status: 'partial', text: 'Both Z-score and drift assume local stationarity within their windows. Planned operational transitions (startup/shutdown, batch changes) break this assumption and produce false alarms. Production systems need transition-state suppression logic.' },
          { title: 'Test Set Independence', status: 'valid', text: 'Detection threshold τ was tuned exclusively on the validation set (steps 300–399). Final metrics are reported on the held-out test set (steps 400–499). No information leakage between splits.' },
          { title: 'Bootstrap CI Validity', status: 'valid', text: 'Bootstrap CI computed over 1,000 resamples with fixed seed (42) for reproducibility. With only 3 attack scenarios the CI is wide — production evaluation on the full 36-scenario SWaT dataset would narrow intervals substantially.' },
          { title: 'Adversarial Robustness', status: 'limitation', text: 'Slow-poison attacks evade Z-score by moving the rolling baseline gradually. Dual-window drift partially mitigates this, but a sufficiently patient adversary using the long-window period to baseline the drift could still evade all three detectors.' },
        ].map(({ title, status, text }) => (
          <div key={title} style={{ padding: '0.75rem 1rem', background: 'var(--surface)', borderRadius: 6, borderLeft: `3px solid ${{ valid: '#00e676', partial: '#e3b341', limitation: '#ff6b6b' }[status]}` }}>
            <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center', marginBottom: '0.3rem' }}>
              <strong style={{ fontSize: '0.85rem' }}>{title}</strong>
              <span style={{ fontSize: '0.68rem', padding: '1px 6px', borderRadius: 10, background: `${{ valid: '#00e676', partial: '#e3b341', limitation: '#ff6b6b' }[status]}22`, color: { valid: '#00e676', partial: '#e3b341', limitation: '#ff6b6b' }[status], fontWeight: 700 }}>
                {status.toUpperCase()}
              </span>
            </div>
            <div style={{ fontSize: '0.76rem', color: 'var(--text-muted)', lineHeight: 1.6 }}>{text}</div>
          </div>
        ))}
      </div>

      {/* Jaccard similarity note */}
      <div style={{ marginTop: '1.25rem', padding: '0.75rem 1rem', background: 'var(--surface)', borderRadius: 6, fontSize: '0.78rem', color: 'var(--text-muted)', lineHeight: 1.7 }}>
        <strong style={{ color: 'var(--accent)' }}>Threat Correlation (Jaccard):</strong> See the Threat Correlation tab for the full J(A,B) = |A∩B|/|A∪B| similarity matrix
        across all threat classes based on shared MITRE ATT&CK ICS techniques. Clusters in that matrix indicate where a single defensive control covers multiple threat classes.
      </div>
    </div>
  )
}
