const BASE = '/api'

async function get<T>(path: string): Promise<T> {
  const res = await fetch(BASE + path)
  if (!res.ok) throw new Error(`API ${path}: ${res.status} ${res.statusText}`)
  return res.json()
}

export const api = {
  // Core
  threats: () => get<any[]>('/threats'),
  threat: (id: string) => get<any>(`/threats/${id}`),
  metrics: () => get<any>('/metrics'),
  datasets: () => get<any>('/datasets'),

  // MITRE
  mitreTactics: () => get<any[]>('/mitre/tactics'),
  mitreTechniques: () => get<any[]>('/mitre/techniques'),
  mitreHeatmap: () => get<any>('/mitre/heatmap'),
  mitreForThreat: (id: string) => get<any>(`/mitre/threat/${id}`),

  // Scenarios
  scenarios: () => get<any[]>('/scenarios'),
  scenario: (id: string) => get<any>(`/scenarios/${id}`),
  purdue: () => get<any>('/purdue'),

  // Correlation
  correlations: () => get<any>('/correlations'),

  // Actors
  threatActors: () => get<any>('/threat-actors'),
  threatActor: (id: string) => get<any>(`/threat-actors/${id}`),

  // Geo & Network
  geoRisk: () => get<any>('/geo-risk'),
  networkGraph: () => get<any>('/network-graph'),

  // Incidents
  incidents: () => get<any>('/incidents'),

  // Analytics
  mlDetection: () => get<any>('/ml-detection'),
  cveAssetMap: () => get<any>('/cve-asset-map'),
  killChain: () => get<any>('/kill-chain-techniques'),

  // Live Intel
  kev: () => get<any>('/live/kev'),
  cve: (keyword: string) => get<any>(`/live/cve?keyword=${encodeURIComponent(keyword)}`),
  otx: () => get<any>('/live/otx'),
  news: () => get<any>('/live/news'),
  briefing: () => get<any>('/live/briefing'),
  threatFeed: () => get<any>('/threat-feed'),

  // References
  references: () => get<any>('/references'),
}

// WebSocket helper
export function createThreatFeedSocket(
  onMessage: (event: any) => void,
  onClose?: () => void,
): WebSocket {
  const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
  const host = window.location.host
  const ws = new WebSocket(`${protocol}//${host}/ws/threatfeed`)
  ws.onmessage = (e) => {
    try {
      onMessage(JSON.parse(e.data))
    } catch {
      // ignore malformed
    }
  }
  if (onClose) ws.onclose = onClose
  return ws
}
