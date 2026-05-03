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
  mlCompare: () => get<any>('/ml-compare'),
  stixActor: (id: string) => get<any>(`/stix/actor/${id}`),
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

  // Threat Intelligence Platforms
  intelSummary: () => get<any>('/intel/summary'),
  threatFoxIOCs: () => get<any>('/intel/threatfox'),
  threatFoxSearch: (ioc: string) => get<any>(`/intel/threatfox/search?ioc=${encodeURIComponent(ioc)}`),
  feodoBlocklist: () => get<any>('/intel/feodo'),
  urlhausRecent: () => get<any>('/intel/urlhaus'),
  malwareBazaar: () => get<any>('/intel/malwarebazaar'),
  cisaAdvisories: () => get<any>('/intel/cisa-advisories'),
  greyNoiseICS: () => get<any>('/intel/greynoise'),
  greyNoiseIP: (ip: string) => get<any>(`/intel/greynoise/${ip}`),
  shodanICS: (protocol?: string) => get<any>(`/intel/shodan${protocol ? `?protocol=${protocol}` : ''}`),
  iocSearch: (q: string) => get<any>(`/intel/ioc-search?q=${encodeURIComponent(q)}`),
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

// Sensor stream WebSocket
export function createSensorStreamSocket(
  onMessage: (data: any) => void,
  onClose?: () => void,
): WebSocket {
  const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
  const host = window.location.host
  const ws = new WebSocket(`${protocol}//${host}/ws/sensor-stream`)
  ws.onmessage = (e) => {
    try { onMessage(JSON.parse(e.data)) } catch { /* ignore */ }
  }
  if (onClose) ws.onclose = onClose
  return ws
}
