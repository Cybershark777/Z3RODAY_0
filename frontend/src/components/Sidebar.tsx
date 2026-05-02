import { useDashboard } from '../store/dashboard'
import type { TabId } from '../types'

interface NavItem {
  id: TabId
  label: string
  icon: string
}

interface NavSection {
  label: string
  items: NavItem[]
}

const NAV: NavSection[] = [
  {
    label: 'Core',
    items: [
      { id: 'overview', label: 'Overview', icon: '▪' },
      { id: 'mitre', label: 'MITRE ATT&CK ICS', icon: '◆' },
      { id: 'scenarios', label: 'Attack Scenarios', icon: '▶' },
      { id: 'correlation', label: 'Threat Correlation', icon: '▪' },
      { id: 'physical', label: 'Physical Threats', icon: '◎' },
    ],
  },
  {
    label: 'Intelligence',
    items: [
      { id: 'liveintel', label: 'Live Intel', icon: '●' },
      { id: 'threatfeed', label: 'Threat Feed', icon: '⚡' },
      { id: 'threatintel', label: 'Threat Intel Feeds', icon: '⬡' },
      { id: 'actors', label: 'Threat Actors', icon: '◆' },
      { id: 'news', label: 'Security News', icon: '✎' },
      { id: 'briefing', label: 'AI Briefing', icon: '◆' },
    ],
  },
  {
    label: 'Analysis',
    items: [
      { id: 'soar', label: 'ML-SOAR', icon: '▲' },
      { id: 'heatmap', label: 'ATT&CK Map', icon: '▪' },
      { id: 'network', label: 'Network Graph', icon: '⬡' },
      { id: 'georisk', label: 'Geo Risk', icon: '◎' },
      { id: 'killchain', label: 'Kill Chain', icon: '⚔' },
      { id: 'cvemap', label: 'CVE Asset Map', icon: '⚠' },
      { id: 'datasets', label: 'Datasets', icon: '▪' },
    ],
  },
  {
    label: 'Other',
    items: [
      { id: 'references', label: 'References', icon: '▪' },
    ],
  },
]

export default function Sidebar() {
  const { activeTab, setActiveTab, sidebarCollapsed, toggleSidebar } = useDashboard()

  return (
    <aside className={`sidebar${sidebarCollapsed ? ' collapsed' : ''}`} id="sidebar">
      <button className="sidebar-toggle" onClick={toggleSidebar} title="Toggle sidebar">
        {sidebarCollapsed ? '▶' : '◀'}
      </button>

      {NAV.map((section) => (
        <div key={section.label}>
          <div className="sidebar-section-label">{section.label}</div>
          {section.items.map((item) => (
            <button
              key={item.id}
              className={`tab-btn${activeTab === item.id ? ' active' : ''}`}
              onClick={() => setActiveTab(item.id)}
              title={item.label}
            >
              <span className="tab-icon">{item.icon}</span>
              <span className="tab-label"> {item.label}</span>
            </button>
          ))}
        </div>
      ))}
    </aside>
  )
}
