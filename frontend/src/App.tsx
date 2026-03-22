import { useEffect } from 'react'
import { useDashboard } from './store/dashboard'
import { createThreatFeedSocket } from './services/api'
import Sidebar from './components/Sidebar'
import Header from './components/Header'
import { TabId } from './types'

// Pages (lazy loaded would be ideal but keeping simple for now)
import Overview from './pages/Overview'
import MitreATTCK from './pages/MitreATTCK'
import AttackScenarios from './pages/AttackScenarios'
import ThreatCorrelation from './pages/ThreatCorrelation'
import PhysicalThreats from './pages/PhysicalThreats'
import LiveIntel from './pages/LiveIntel'
import ThreatFeed from './pages/ThreatFeed'
import ThreatActors from './pages/ThreatActors'
import SecurityNews from './pages/SecurityNews'
import AIBriefing from './pages/AIBriefing'
import MLSoar from './pages/MLSoar'
import ATTCKHeatmap from './pages/ATTCKHeatmap'
import NetworkGraph from './pages/NetworkGraph'
import GeoRisk from './pages/GeoRisk'
import KillChainBuilder from './pages/KillChainBuilder'
import CVEAssetMap from './pages/CVEAssetMap'
import Datasets from './pages/Datasets'
import References from './pages/References'

const PAGE_MAP: Record<TabId, JSX.Element> = {
  overview: <Overview />,
  mitre: <MitreATTCK />,
  scenarios: <AttackScenarios />,
  correlation: <ThreatCorrelation />,
  physical: <PhysicalThreats />,
  liveintel: <LiveIntel />,
  threatfeed: <ThreatFeed />,
  actors: <ThreatActors />,
  news: <SecurityNews />,
  briefing: <AIBriefing />,
  soar: <MLSoar />,
  heatmap: <ATTCKHeatmap />,
  network: <NetworkGraph />,
  georisk: <GeoRisk />,
  killchain: <KillChainBuilder />,
  cvemap: <CVEAssetMap />,
  datasets: <Datasets />,
  references: <References />,
}

export default function App() {
  const { activeTab, theme, addLiveEvent, setWsConnected } = useDashboard()

  // Apply theme to document
  useEffect(() => {
    document.documentElement.setAttribute('data-theme', theme)
  }, [theme])

  // WebSocket live feed
  useEffect(() => {
    let ws: WebSocket | null = null
    let retryTimeout: ReturnType<typeof setTimeout>

    const connect = () => {
      ws = createThreatFeedSocket(
        (msg) => {
          const event = msg.event ?? msg
          addLiveEvent(event)
        },
        () => {
          setWsConnected(false)
          retryTimeout = setTimeout(connect, 5000)
        },
      )
      ws.onopen = () => setWsConnected(true)
    }

    connect()
    return () => {
      clearTimeout(retryTimeout)
      ws?.close()
    }
  }, [addLiveEvent, setWsConnected])

  return (
    <div className="app-root">
      <Header />
      <div className="app-layout">
        <Sidebar />
        <main className="app-main">
          {PAGE_MAP[activeTab] ?? <Overview />}
        </main>
      </div>
    </div>
  )
}
