import { useState } from 'react'

const PLAYBOOKS = [
  {
    id: 'power-grid',
    name: 'Electric Grid / SCADA Attack',
    severity: 'critical',
    ref: 'NERC CIP-008, ICS-CERT AA22-110A',
    phases: [
      {
        phase: 'Detection', color: '#e3b341',
        steps: [
          'Verify anomalous SCADA historian gaps or HMI freeze events',
          'Cross-correlate with IT network authentication logs for lateral movement indicators',
          'Check ICS protocol traffic (IEC 104, Modbus, DNP3) for unexpected command sequences',
          'Alert SOC and OT security team; initiate P1 incident bridge',
        ],
      },
      {
        phase: 'Containment', color: '#ff8c42',
        steps: [
          'Isolate compromised engineering workstations from OT network — do NOT power off',
          'Engage manual/local control at substations if remote access is untrusted',
          'Block outbound connections from SCADA historian and HMI servers at DMZ firewall',
          'Preserve volatile memory (RAM dump) of affected systems before any shutdown',
          'Notify grid operations and activate manual contingency procedures',
        ],
      },
      {
        phase: 'Eradication', color: '#da3633',
        steps: [
          'Forensically image all affected ICS engineering workstations',
          'Scan OT environment for backdoors, scheduled tasks, and modified PLC logic',
          'Audit remote access credentials — rotate all VPN and jump server accounts',
          'Validate circuit breaker states and SIS configs against known-good baseline',
          'Remove malware artifacts; rebuild compromised hosts from trusted images',
        ],
      },
      {
        phase: 'Recovery', color: '#00e676',
        steps: [
          'Restore from verified clean backups; validate PLC/RTU logic checksums',
          'Re-enable SCADA remote access only after full network re-segmentation audit',
          'Monitor all ICS protocol traffic for 72h post-recovery at elevated alert threshold',
          'Issue NERC CIP-008 incident report within required timeframe',
          'Conduct post-incident review and update threat model',
        ],
      },
    ],
  },
  {
    id: 'ransomware-ot',
    name: 'Ransomware in OT Environment',
    severity: 'critical',
    ref: 'CISA AA21-131A, ICS-CERT Advisory',
    phases: [
      {
        phase: 'Detection', color: '#e3b341',
        steps: [
          'Identify ransom note artifacts and encrypted file extensions on OT DMZ servers',
          'Check for lateral movement from IT to OT via shared accounts or remote access tools',
          'Determine blast radius: which OT assets have network connectivity to affected IT systems?',
          'Assess whether PLC/RTU logic or historian data has been encrypted',
        ],
      },
      {
        phase: 'Containment', color: '#ff8c42',
        steps: [
          'Immediately segment OT network from enterprise IT — cut IT/OT firewall rules',
          'Activate manual/local process control if automated systems are untrusted',
          'Disable all remote access (VPN, RDP, jump servers) until scope confirmed',
          'Do NOT pay ransom — engage law enforcement (CISA, FBI) immediately',
          'Preserve all affected systems in current state for forensics',
        ],
      },
      {
        phase: 'Eradication', color: '#da3633',
        steps: [
          'Identify initial access vector — phishing, vulnerable internet-facing system, or supply chain',
          'Rebuild affected IT systems from clean images; validate OT system integrity',
          'Audit all privileged accounts for unauthorized changes or persistence mechanisms',
          'Verify ICS historian and SCADA database integrity against offline backups',
        ],
      },
      {
        phase: 'Recovery', color: '#00e676',
        steps: [
          'Restore OT systems using verified offline backups with integrity checksums',
          'Implement enhanced network monitoring at IT/OT boundary before reconnection',
          'Conduct full active directory audit and credential reset across enterprise',
          'Report to CISA via reporting portal; engage sector ISAC',
          'Update asset inventory and patch management to close exploited vulnerability',
        ],
      },
    ],
  },
  {
    id: 'sis-attack',
    name: 'Safety System (SIS) Compromise',
    severity: 'critical',
    ref: 'TRITON/TRISIS response; IEC 61511; CISA AA22-103A',
    phases: [
      {
        phase: 'Detection', color: '#e3b341',
        steps: [
          'Unexpected SIS safe-state trip with no corresponding process exceedance — treat as potential attack',
          'Check engineering workstation for unauthorized TriStation/SIS vendor software access',
          'Review SIS logic download history vs authorized change management records',
          'Look for TRITON/TRISIS indicators on engineering workstations',
        ],
      },
      {
        phase: 'Containment', color: '#ff8c42',
        steps: [
          'DO NOT restart process until SIS integrity is fully verified — safety first',
          'Physically isolate SIS network; remove all remote access to SIS controllers',
          'Engage SIS vendor (Schneider, Emerson, Yokogawa, ABB) for emergency support',
          'Notify safety authorities and operations leadership; activate emergency response plan',
          'Preserve SIS engineering workstation for forensics',
        ],
      },
      {
        phase: 'Eradication', color: '#da3633',
        steps: [
          'Forensically examine SIS controller firmware and logic for unauthorized modifications',
          'Compare SIS logic against last known-good version in change management system',
          'Audit all TriStation or SIS vendor software licenses and access logs',
          'Engage threat intelligence — check IOCs for XENOTIME/TEMP.Veles malware families',
          'Rebuild SIS engineering workstation from certified clean media',
        ],
      },
      {
        phase: 'Recovery', color: '#00e676',
        steps: [
          'Re-download certified SIS logic only from authorized engineering workstation',
          'Perform full SIS functional test before process restart',
          'Implement enhanced monitoring: alert on TriStation traffic from non-authorized hosts',
          'Mandatory regulatory notification — safety system attacks trigger reporting requirements',
          'Commission third-party ICS security assessment before resuming operations',
        ],
      },
    ],
  },
  {
    id: 'apt-recon',
    name: 'APT Long-Dwell OT Reconnaissance',
    severity: 'high',
    ref: 'Dragos VOLTZITE/Volt Typhoon; CISA AA24-038A',
    phases: [
      {
        phase: 'Detection', color: '#e3b341',
        steps: [
          'Unusual GIS shapefile or network diagram access from internal engineering systems',
          'Unexpected enumeration of OT asset inventory databases from IT-connected systems',
          'SOHO router or VPN appliance anomaly — check for web shell or LOLBin activity',
          'Passive network traffic analysis showing novel protocols from unexpected hosts',
        ],
      },
      {
        phase: 'Containment', color: '#ff8c42',
        steps: [
          'Identify full scope of compromised infrastructure before alerting adversary',
          'Coordinate with CISA/FBI before containment action — preserve intelligence value',
          'Quietly rotate credentials on affected systems before cutting adversary visibility',
          'Deploy enhanced network monitoring at IT/OT DMZ boundary',
          'Audit all internet-facing appliances for webshells or unauthorized access',
        ],
      },
      {
        phase: 'Eradication', color: '#da3633',
        steps: [
          'Replace or reimage all compromised SOHO routers, VPN appliances, and firewalls',
          'Remove all web shells and backdoors identified in forensic analysis',
          'Rotate all service accounts, VPN credentials, and privileged user passwords',
          'Audit OT asset inventory access logs — determine what topology data was exfiltrated',
          'Patch all identified initial access vulnerabilities (Fortinet, Ivanti, Citrix CVEs)',
        ],
      },
      {
        phase: 'Recovery', color: '#00e676',
        steps: [
          'Assume adversary has complete OT network topology — update network segmentation',
          'Deploy deception technology (honeypots) at OT network ingress points',
          'Implement zero-trust architecture for all remote OT access',
          'Share IOCs with CISA and sector ISAC for cross-sector defensive action',
          'Commission red team exercise against now-known threat actor TTPs',
        ],
      },
    ],
  },
]

export default function PhysicalThreats() {
  const [selectedId, setSelectedId] = useState<string | null>(null)
  const selected = PLAYBOOKS.find((p) => p.id === selectedId)

  return (
    <div className="tab-page">
      <div className="section-header">
        <h2>ICS/OT Incident Response Playbooks</h2>
        <p className="section-desc">
          Step-by-step response procedures for the highest-impact ICS/OT attack scenarios.
          Based on CISA advisories, NERC CIP, IEC 62443, and Dragos threat intelligence.
        </p>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(280px, 1fr))', gap: '1rem', marginBottom: '1.5rem' }}>
        {PLAYBOOKS.map((p) => (
          <div
            key={p.id}
            className={`actor-card${selectedId === p.id ? ' selected' : ''}`}
            style={{ cursor: 'pointer' }}
            onClick={() => setSelectedId(selectedId === p.id ? null : p.id)}
          >
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '0.5rem' }}>
              <div className="actor-name" style={{ fontSize: '0.92rem' }}>{p.name}</div>
              <span className={`severity-badge sev-${p.severity}`}>{p.severity.toUpperCase()}</span>
            </div>
            <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
              {p.phases.length} phases · Ref: {p.ref}
            </div>
          </div>
        ))}
      </div>

      {selected && (
        <div className="actor-detail-panel">
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1.25rem' }}>
            <div>
              <h3 style={{ marginBottom: '0.25rem' }}>{selected.name}</h3>
              <div style={{ fontSize: '0.76rem', color: 'var(--text-muted)' }}>Reference: {selected.ref}</div>
            </div>
            <button className="filter-btn" onClick={() => setSelectedId(null)}>✕ Close</button>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(300px, 1fr))', gap: '1rem' }}>
            {selected.phases.map((phase) => (
              <div key={phase.phase} style={{ padding: '1rem', background: 'var(--surface2)', borderRadius: 6, borderTop: `3px solid ${phase.color}` }}>
                <div style={{ fontWeight: 700, fontSize: '0.88rem', color: phase.color, marginBottom: '0.75rem', letterSpacing: '0.05em' }}>
                  {phase.phase.toUpperCase()}
                </div>
                <ol style={{ margin: 0, paddingLeft: '1.1rem' }}>
                  {phase.steps.map((step, i) => (
                    <li key={i} style={{ fontSize: '0.81rem', color: 'var(--text-muted)', lineHeight: 1.6, marginBottom: '0.4rem' }}>
                      {step}
                    </li>
                  ))}
                </ol>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}
