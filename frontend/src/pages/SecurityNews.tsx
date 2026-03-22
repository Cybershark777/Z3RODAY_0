import { useQuery } from '@tanstack/react-query'
import { api } from '../services/api'
import LoadingSpinner from '../components/LoadingSpinner'

export default function SecurityNews() {
  const { data, isLoading } = useQuery({
    queryKey: ['news'],
    queryFn: api.news,
  })

  const articles: any[] = data?.articles ?? []

  return (
    <div className="tab-page">
      <div className="section-header">
        <h2>ICS/OT Security News</h2>
        <p className="section-desc">
          Aggregated cybersecurity news from CISA, ICS-CERT, and leading security research organizations.
        </p>
      </div>
      {isLoading && <LoadingSpinner message="Fetching latest security news..." />}
      {!isLoading && articles.length === 0 && (
        <div className="error-state">No articles available — external feeds may be unavailable.</div>
      )}
      <div className="news-grid">
        {articles.map((article: any, i: number) => (
          <a
            key={i}
            href={article.link}
            target="_blank"
            rel="noopener noreferrer"
            className="news-card"
          >
            <div className="news-card-title">{article.title}</div>
            <div className="news-card-date">{article.pub_date}</div>
            {article.summary && (
              <div className="news-card-summary">
                {article.summary.replace(/<[^>]+>/g, '').slice(0, 200)}...
              </div>
            )}
          </a>
        ))}
      </div>
    </div>
  )
}
