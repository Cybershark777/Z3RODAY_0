import { useQuery } from '@tanstack/react-query'
import {
  Chart as ChartJS, CategoryScale, LinearScale, LineElement, PointElement,
  BarElement, ArcElement, Title, Tooltip, Legend, Filler,
} from 'chart.js'
import { Line, Bar, Scatter } from 'react-chartjs-2'
import { api } from '../services/api'
import LoadingSpinner from '../components/LoadingSpinner'

ChartJS.register(CategoryScale, LinearScale, LineElement, PointElement, BarElement, ArcElement, Title, Tooltip, Legend, Filler)

const SENSOR_COLORS = ['#388bfd', '#bc8cff', '#3fb950', '#e3b341', '#ff8c42', '#ff6b6b']
const DARK_OPTS = {
  scales: {
    x: { ticks: { color: '#8b949e' }, grid: { color: '#30363d' } },
    y: { ticks: { color: '#8b949e' }, grid: { color: '#30363d' } },
  },
  plugins: { legend: { labels: { color: '#8b949e' } } },
}

export default function MLSoar() {
  const { data, isLoading } = useQuery({
    queryKey: ['ml-detection'],
    queryFn: api.mlDetection,
    staleTime: 10 * 60 * 1000,
  })

  if (isLoading) return <LoadingSpinner message="Loading ML-SOAR analysis..." />
  if (!data) return null

  const steps = Array.from({ length: data.steps }, (_, i) => i)

  // Sensor time series (show first 3 sensors for clarity)
  const sensorChartData = {
    labels: steps.filter((_, i) => i % 5 === 0),
    datasets: data.sensors.slice(0, 3).map((sensor: any, i: number) => ({
      label: `${sensor.name} (${sensor.unit})`,
      data: data.series[sensor.name].filter((_: number, idx: number) => idx % 5 === 0),
      borderColor: SENSOR_COLORS[i],
      borderWidth: 1.5,
      pointRadius: 0,
      tension: 0.3,
    })),
  }

  // Anomaly score chart
  const anomalyData = {
    labels: steps.filter((_, i) => i % 5 === 0),
    datasets: [{
      label: 'Anomaly Score',
      data: data.anomaly_scores.filter((_: number, idx: number) => idx % 5 === 0),
      fill: true,
      backgroundColor: 'rgba(255,107,107,0.2)',
      borderColor: '#ff6b6b',
      borderWidth: 1.5,
      pointRadius: 0,
      tension: 0.3,
    }],
  }

  // MTTD comparison
  const mttdData = {
    labels: data.comparisons.map((c: any) => `Attack ${c.window}`),
    datasets: [
      {
        label: 'Baseline MTTD (min)',
        data: data.comparisons.map((c: any) => c.baseline_mttd),
        backgroundColor: 'rgba(227,179,65,0.7)',
      },
      {
        label: 'ML-SOAR MTTD (min)',
        data: data.comparisons.map((c: any) => c.ml_mttd),
        backgroundColor: 'rgba(56,139,253,0.7)',
      },
    ],
  }

  // ROC curve
  const rocData = {
    datasets: [{
      label: 'ROC Curve',
      data: data.roc_points.map((p: any) => ({ x: p.fpr, y: p.tpr })),
      borderColor: '#bc8cff',
      backgroundColor: 'rgba(188,140,255,0.3)',
      showLine: true,
      pointRadius: 4,
      fill: true,
    }],
  }

  return (
    <div className="tab-page">
      <div className="section-header">
        <h2>ML-SOAR: Anomaly Detection</h2>
        <p className="section-desc">
          Synthetic SWAT sensor data with multivariate Z-score anomaly detection.
          Three injected attack windows demonstrate ML-SOAR detection capability vs. baseline.
        </p>
      </div>

      {/* Accuracy cards */}
      <div className="metrics-bar" style={{ marginBottom: '1.5rem' }}>
        <div className="metric-card accent">
          <div className="metric-label">Detection Accuracy</div>
          <div className="metric-value">{(data.accuracy * 100).toFixed(1)}%</div>
          <div className="metric-sub">ML-SOAR</div>
        </div>
        <div className="metric-card">
          <div className="metric-label">False Positive Rate</div>
          <div className="metric-value">{(data.false_positive_rate * 100).toFixed(1)}%</div>
          <div className="metric-sub">ML-SOAR</div>
        </div>
        {data.comparisons.map((c: any) => (
          <div key={c.window} className="metric-card">
            <div className="metric-label">Attack {c.window} Improvement</div>
            <div className="metric-value" style={{ color: '#3fb950' }}>{c.improvement}%</div>
            <div className="metric-sub">MTTD reduction</div>
          </div>
        ))}
      </div>

      {/* Sensor chart */}
      <div className="ml-chart-section">
        <h3>Sensor Time Series (SWAT Dataset)</h3>
        <div style={{ height: 220 }}>
          <Line data={sensorChartData} options={{ ...DARK_OPTS as any, responsive: true, maintainAspectRatio: false }} />
        </div>
      </div>

      {/* Anomaly score */}
      <div className="ml-chart-section">
        <h3>Anomaly Score (Multivariate Z-Score)</h3>
        <div style={{ height: 180 }}>
          <Line
            data={anomalyData}
            options={{
              ...DARK_OPTS as any,
              responsive: true,
              maintainAspectRatio: false,
              scales: {
                ...DARK_OPTS.scales,
                y: { ...DARK_OPTS.scales.y, min: 0, max: 3, title: { display: true, text: 'Score', color: '#8b949e' } },
              },
            }}
          />
        </div>
        <div style={{ marginTop: '0.5rem', fontSize: '0.78rem', color: 'var(--text-muted)' }}>
          Attack windows: steps 120–160, 270–310, 400–450 (red shading = injected attack)
        </div>
      </div>

      {/* MTTD comparison + ROC */}
      <div className="charts-row">
        <div className="chart-card">
          <h2>MTTD: Baseline vs ML-SOAR (minutes)</h2>
          <div style={{ height: 220 }}>
            <Bar data={mttdData} options={{ ...DARK_OPTS as any, responsive: true, maintainAspectRatio: false }} />
          </div>
        </div>
        <div className="chart-card chart-card-sm">
          <h2>ROC Curve (AUC ≈ 0.96)</h2>
          <div style={{ height: 220 }}>
            <Scatter
              data={rocData}
              options={{
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                  x: { min: 0, max: 1, title: { display: true, text: 'FPR', color: '#8b949e' }, ticks: { color: '#8b949e' }, grid: { color: '#30363d' } },
                  y: { min: 0, max: 1, title: { display: true, text: 'TPR', color: '#8b949e' }, ticks: { color: '#8b949e' }, grid: { color: '#30363d' } },
                },
                plugins: { legend: { labels: { color: '#8b949e' } } },
              }}
            />
          </div>
        </div>
      </div>
    </div>
  )
}
