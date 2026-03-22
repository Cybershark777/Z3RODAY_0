import { useDashboard } from '../store/dashboard'

export default function Header() {
  const { theme, toggleTheme, wsConnected } = useDashboard()

  return (
    <header className="app-header">
      <div className="header-inner">
        <div className="header-title">
          <span className="badge">RESEARCH PROTOTYPE</span>
          <h1>CPS Threat Intelligence Dashboard</h1>
          <p>IT/OT Threat Detection &bull; Cyber-Physical Data Center Systems &bull; GWU SEAS 8499</p>
        </div>
        <div className="header-status">
          <button className="theme-toggle-btn" onClick={toggleTheme} title="Toggle theme">
            {theme === 'dark' ? '☀' : '☾'}
          </button>
          <span className={`dot ${wsConnected ? 'dot-green' : 'dot-red'}`} />
          <span>{wsConnected ? 'Live' : 'Connecting...'}</span>
        </div>
      </div>
    </header>
  )
}
