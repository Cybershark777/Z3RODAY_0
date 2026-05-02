import { useState, useRef } from 'react'
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
  const [streamText, setStreamText] = useState<string | null>(null)
  const [streaming, setStreaming] = useState(false)
  const [streamError, setStreamError] = useState<string | null>(null)
  const esRef = useRef<EventSource | null>(null)

  // Cached briefing fallback
  const { data, isLoading, error, refetch } = useQuery({
    queryKey: ['briefing'],
    queryFn: api.briefing,
    staleTime: 30 * 60 * 1000,
    enabled: streamText === null,
  })

  const startStream = () => {
    if (esRef.current) esRef.current.close()
    setStreamText('')
    setStreaming(true)
    setStreamError(null)

    const es = new EventSource('/api/live/briefing/stream')
    esRef.current = es

    es.addEventListener('delta', (e) => {
      setStreamText((prev) => (prev ?? '') + e.data)
    })

    es.addEventListener('done', () => {
      es.close()
      setStreaming(false)
    })

    es.onerror = () => {
      es.close()
      setStreaming(false)
      if (!streamText) setStreamError('Streaming failed — check ANTHROPIC_API_KEY')
    }
  }

  const displayText = streamText ?? data?.briefing ?? null
  const isGenerating = isLoading || streaming

  return (
    <div className="tab-page">
      <div className="section-header">
        <h2>AI Threat Briefing</h2>
        <p className="section-desc">
          AI-generated tactical briefing synthesizing current ICS/OT threat landscape.
          Powered by Claude (Anthropic).
        </p>
        <div style={{ display: 'flex', gap: '0.75rem', marginTop: '0.75rem' }}>
          <button className="primary-btn" onClick={startStream} disabled={streaming}>
            {streaming ? '⟳ Streaming...' : '▶ Stream Live'}
          </button>
          <button
            className="primary-btn"
            style={{ background: 'var(--surface2)', border: '1px solid var(--border)', color: 'var(--text-muted)' }}
            onClick={() => { setStreamText(null); refetch() }}
            disabled={isLoading}
          >
            {isLoading ? 'Loading...' : '↺ Load Cached'}
          </button>
        </div>
      </div>

      {isLoading && !streaming && <LoadingSpinner message="Generating AI threat briefing..." />}
      {(error || streamError) && (
        <div className="error-state">{streamError ?? 'Failed to generate briefing — check ANTHROPIC_API_KEY'}</div>
      )}

      {displayText && (
        <div className="briefing-container">
          {data?.generated_at && !streamText && (
            <div className="briefing-meta">Generated: {new Date(data.generated_at).toLocaleString()}</div>
          )}
          {streaming && (
            <div className="briefing-meta streaming-indicator">
              <span className="stream-dot" />
              Streaming response from Claude...
            </div>
          )}
          <div
            className="briefing-text"
            dangerouslySetInnerHTML={{ __html: mdToHtml(displayText) }}
          />
          {streaming && <span className="stream-cursor">▋</span>}
        </div>
      )}
    </div>
  )
}
