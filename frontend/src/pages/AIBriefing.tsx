import { useQuery } from '@tanstack/react-query'
import { api } from '../services/api'
import LoadingSpinner from '../components/LoadingSpinner'

function mdToHtml(text: string): string {
  const lines = text.split('\n')
  const out: string[] = []
  let inList = false
  let listTag = 'ul'

  const flush = () => {
    if (inList) { out.push(`</${listTag}>`); inList = false }
  }

  for (const raw of lines) {
    const line = raw.trim()
    if (!line) { flush(); out.push('<br/>'); continue }
    if (line.startsWith('### ')) { flush(); out.push(`<h3>${line.slice(4)}</h3>`); continue }
    if (line.startsWith('## ')) { flush(); out.push(`<h2>${line.slice(3)}</h2>`); continue }
    if (line.startsWith('# ')) { flush(); out.push(`<h1>${line.slice(2)}</h1>`); continue }
    if (line === '---') { flush(); out.push('<hr/>'); continue }
    if (line.startsWith('- ') || line.startsWith('* ')) {
      if (!inList || listTag !== 'ul') { flush(); out.push('<ul>'); inList = true; listTag = 'ul' }
      out.push(`<li>${line.slice(2)}</li>`)
      continue
    }
    const olMatch = line.match(/^\d+\.\s(.+)/)
    if (olMatch) {
      if (!inList || listTag !== 'ol') { flush(); out.push('<ol>'); inList = true; listTag = 'ol' }
      out.push(`<li>${olMatch[1]}</li>`)
      continue
    }
    flush()
    out.push(`<p>${line.replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>').replace(/\*(.+?)\*/g, '<em>$1</em>')}</p>`)
  }
  flush()
  return out.join('')
}

export default function AIBriefing() {
  const { data, isLoading, error, refetch } = useQuery({
    queryKey: ['briefing'],
    queryFn: api.briefing,
    staleTime: 30 * 60 * 1000,
  })

  return (
    <div className="tab-page">
      <div className="section-header">
        <h2>AI Threat Briefing</h2>
        <p className="section-desc">
          AI-generated tactical briefing synthesizing current ICS/OT threat landscape.
          Powered by Claude (Anthropic).
        </p>
        <button className="primary-btn" onClick={() => refetch()} disabled={isLoading}>
          {isLoading ? 'Generating...' : '↺ Regenerate'}
        </button>
      </div>

      {isLoading && <LoadingSpinner message="Generating AI threat briefing..." />}
      {error && (
        <div className="error-state">Failed to generate briefing — check ANTHROPIC_API_KEY</div>
      )}
      {data?.briefing && (
        <div className="briefing-container">
          {data.generated_at && (
            <div className="briefing-meta">Generated: {new Date(data.generated_at).toLocaleString()}</div>
          )}
          <div
            className="briefing-text"
            dangerouslySetInnerHTML={{ __html: mdToHtml(data.briefing) }}
          />
        </div>
      )}
    </div>
  )
}
