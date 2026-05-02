import { useDashboard } from '../store/dashboard'
import ThreatTicker from './ThreatTicker'
import CyberSharkLogo from './CyberSharkLogo'

export default function Header() {
  const { theme, toggleTheme, wsConnected } = useDashboard()

  return (
    <header className="app-header">
      <div className="header-inner">
        <div className="header-title" style={{ display: 'flex', alignItems: 'center', gap: '1.25rem' }}>
          <CyberSharkLogo height={72} />
          <div>
            <span className="badge">GWU SEAS 8499</span>
            <h1>CyberShark Security&#8482;</h1>
            <p>IT/OT Threat Detection &bull; Cyber-Physical Systems &bull; Doctoral Practicum</p>
          </div>
        </div>
        <div className="header-status">
          <button className="theme-toggle-btn" onClick={toggleTheme} title="Toggle theme">
            {theme === 'dark' ? '☀' : '☾'}
          </button>
          <span className={`dot dot-ripple ${wsConnected ? 'dot-green' : 'dot-red'}`} />
          <span>{wsConnected ? 'Live' : 'Connecting...'}</span>
        </div>
      </div>
      <ThreatTicker />
    </header>
  )
}
