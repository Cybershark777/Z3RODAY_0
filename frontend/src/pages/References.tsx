import { useQuery } from '@tanstack/react-query'
import { api } from '../services/api'
import LoadingSpinner from '../components/LoadingSpinner'

export default function References() {
  const { data, isLoading } = useQuery({
    queryKey: ['references'],
    queryFn: api.references,
  })

  if (isLoading) return <LoadingSpinner message="Loading references..." />

  const categories = data?.categories ?? []
  const refs = data?.references ?? []

  return (
    <div className="tab-page">
      <div className="section-header">
        <h2>References &amp; Citations</h2>
        <p className="section-desc">
          Academic papers, standards, and data sources cited in this research prototype.
          GWU SEAS 8499 — Doctoral Practicum.
        </p>
      </div>
      {categories.map((cat: any) => {
        const catRefs = refs.filter((r: any) => r.category_id === cat.id)
        return (
          <div key={cat.id} className="intel-section">
            <h3>{cat.name}</h3>
            <div className="reference-list">
              {catRefs.map((ref: any, i: number) => (
                <div key={i} className="reference-item">
                  <div className="ref-title">
                    {ref.url ? (
                      <a href={ref.url} target="_blank" rel="noopener noreferrer">{ref.title}</a>
                    ) : ref.title}
                  </div>
                  {ref.authors && <div className="ref-authors">{ref.authors}</div>}
                  {ref.year && <span className="intel-badge">{ref.year}</span>}
                  {ref.venue && <span className="ref-venue">{ref.venue}</span>}
                </div>
              ))}
            </div>
          </div>
        )
      })}
    </div>
  )
}
