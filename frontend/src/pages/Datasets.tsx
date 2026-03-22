import { useQuery } from '@tanstack/react-query'
import { api } from '../services/api'
import LoadingSpinner from '../components/LoadingSpinner'

export default function Datasets() {
  const { data, isLoading } = useQuery({
    queryKey: ['datasets'],
    queryFn: api.datasets,
  })

  if (isLoading) return <LoadingSpinner message="Loading dataset information..." />

  const datasets = Array.isArray(data) ? data : data?.datasets ?? []

  return (
    <div className="tab-page">
      <div className="section-header">
        <h2>Research Datasets</h2>
        <p className="section-desc">
          Benchmark datasets used for ML-SOAR training, validation, and threat simulation.
          All datasets are publicly available and cited in the research.
        </p>
      </div>
      <div className="dataset-grid">
        {datasets.map((ds: any, i: number) => (
          <div key={i} className="dataset-card">
            <div className="dataset-name">{ds.name}</div>
            <div className="dataset-meta">
              {ds.records && <span className="intel-badge">{ds.records?.toLocaleString()} records</span>}
              {ds.format && <span className="intel-badge">{ds.format}</span>}
              {ds.year && <span className="intel-badge">{ds.year}</span>}
            </div>
            <div className="dataset-desc">{ds.description}</div>
            {ds.features && (
              <div style={{ marginTop: '0.5rem' }}>
                <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Features: </span>
                <span style={{ fontSize: '0.8rem' }}>{ds.features}</span>
              </div>
            )}
            {ds.url && (
              <a href={ds.url} target="_blank" rel="noopener noreferrer" className="dataset-link">
                → View Dataset
              </a>
            )}
          </div>
        ))}
      </div>
    </div>
  )
}
