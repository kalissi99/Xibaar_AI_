import { useState, useEffect, useRef } from 'react';

const API = 'http://localhost:3001/api';
const RED = '#e8483a';

const SEV_STYLE = {
  critical: { background: '#ffeaea', color: '#e8483a', dot: '#e8483a' },
  high:     { background: '#fff4ea', color: '#f07030', dot: '#f07030' },
  medium:   { background: '#eaf4ff', color: '#3a7ae8', dot: '#3a7ae8' },
  low:      { background: '#eafff2', color: '#2ecc71', dot: '#2ecc71' },
};

const MITRE_COLOR = {
  'Credential Access': '#e8483a',
  'Persistence':       '#f07030', 
  'Exfiltration':      '#9b59b6',
  'Execution':         '#3a7ae8',
  'Defense Evasion':   '#e67e22',
  'Impact':            '#c0392b',
  'default':           'dodgerblue'
};

const NAV = [
  { label: 'Dashboard', icon: '▦' },
  { label: 'Alerts',    icon: '⚠' },
  { label: 'Live Logs', icon: '≡' },
  { label: 'Machines',  icon: '⊡' },
  { label: 'MITRE',     icon: '◈' },
  { label: 'Reports',   icon: '↗' },
  { label: 'AI Agent',  icon: '✦' },
];

function SevBadge({ sev }) {
  const s = SEV_STYLE[sev] || SEV_STYLE.low;
  return (
    <span style={{ display: 'inline-flex', alignItems: 'center', gap: 4, padding: '3px 8px', borderRadius: 20, fontSize: 10, fontWeight: 600, background: s.background, color: s.color }}>
      <span style={{ width: 4, height: 4, borderRadius: '50%', background: s.dot }}></span>
      {sev}
    </span>
  );
}

function Card({ children, style }) {
  return (
    <div style={{ background: '#fff', borderRadius: 12, padding: 16, boxShadow: '0 2px 8px rgba(0,0,0,0.04)', ...style }}>
      {children}
    </div>
  );
}

// ── Alerts Table ──────────────────────────────────────────────────────────────
function AlertsTable({ alerts, onAck, filter, setFilter, search }) {
  const filtered = alerts
    .filter(a => !a.acknowledged)
    .filter(a => filter === 'all' || a.severity === filter)
    .filter(a => !search ||
      a.machine?.toLowerCase().includes(search.toLowerCase()) ||
      a.alert_type?.toLowerCase().includes(search.toLowerCase()));

  return (
    <Card style={{ flex: 1 }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 12 }}>
        <div style={{ fontSize: 13, fontWeight: 700, color: '#1a1a2e' }}>
          Active Alerts <span style={{ fontSize: 11, color: '#b0b0b0', fontWeight: 400 }}>({filtered.length})</span>
        </div>
        <div style={{ display: 'flex', gap: 4 }}>
          {['all','critical','high','medium','low'].map(f => (
            <button key={f} onClick={() => setFilter(f)} style={{
              padding: '4px 10px', fontSize: 10, fontWeight: 600, borderRadius: 6,
              border: 'none', cursor: 'pointer',
              background: filter === f ? RED : '#f5f5f7',
              color: filter === f ? '#fff' : '#9a9a9a',
              fontFamily: 'inherit', textTransform: 'capitalize',
            }}>{f}</button>
          ))}
        </div>
      </div>
      <div style={{ overflowX: 'auto', overflowY: 'auto', maxHeight: 'calc(100vh - 280px)' }}>
        <table style={{ width: '100%', borderCollapse: 'collapse' }}>
          <thead style={{ position: 'sticky', top: 0, background: '#fff', zIndex: 1 }}>
            <tr style={{ background: '#fafafa' }}>
              {['Time','Type','Machine','Company','Severity','MITRE','Message','Action'].map(h => (
                <th key={h} style={{ padding: '8px 12px', fontSize: 10, color: '#b0b0b0', textAlign: 'left', fontWeight: 600, whiteSpace: 'nowrap' }}>{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {filtered.length === 0 && (
              <tr><td colSpan={8} style={{ padding: 40, textAlign: 'center', color: '#d0d0d0', fontSize: 12 }}>No active alerts</td></tr>
            )}
            {filtered.map(a => (
              <tr key={a.id} style={{ borderTop: '1px solid #f5f5f5' }}>
                <td style={{ padding: '10px 12px', fontSize: 10, color: '#b0b0b0', whiteSpace: 'nowrap' }}>{new Date(a.created_at).toLocaleString()}</td>
                <td style={{ padding: '10px 12px', fontSize: 11, fontWeight: 600, color: '#1a1a2e', whiteSpace: 'nowrap' }}>{a.alert_type?.replace(/_/g, ' ')}</td>
                <td style={{ padding: '10px 12px', fontSize: 11, color: '#1a1a2e' }}>{a.machine || '-'}</td>
                <td style={{ padding: '10px 12px', fontSize: 11, color: '#9a9a9a' }}>{a.company_id}</td>
                <td style={{ padding: '10px 12px' }}><SevBadge sev={a.severity} /></td>
                <td style={{ padding: '10px 12px' }}>
                  {a.mitre_id ? (
                    <span style={{ fontSize: 10, fontWeight: 600, color: MITRE_COLOR[a.mitre_tactic] || '#9a9a9a', background: '#f5f5f7', padding: '2px 6px', borderRadius: 4, whiteSpace: 'nowrap' }}>
                      {a.mitre_id}
                    </span>
                  ) : <span style={{ color: '#d0d0d0', fontSize: 10 }}>-</span>}
                </td>
                <td style={{ padding: '10px 12px', fontSize: 11, color: '#9a9a9a', maxWidth: 240, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{a.message || '-'}</td>
                <td style={{ padding: '10px 12px' }}>
                  <button onClick={() => onAck(a.id)} style={{ padding: '4px 12px', background: '#ffeaea', color: RED, border: 'none', borderRadius: 6, fontSize: 10, fontWeight: 600, cursor: 'pointer', fontFamily: 'inherit' }}>Ack</button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </Card>
  );
}

// ── Pie Chart Component (Camembert) ──────────────────────────────────────────
function SeverityPieChart({ alerts }) {
  const severityCounts = {
    critical: alerts.filter(a => a.severity === 'critical').length,
    high: alerts.filter(a => a.severity === 'high').length,
    medium: alerts.filter(a => a.severity === 'medium').length,
    low: alerts.filter(a => a.severity === 'low').length,
  };
  
  const total = alerts.length;
  if (total === 0) {
    return (
      <div style={{ textAlign: 'center', padding: 30, color: '#b0b0b0' }}>
        ⚠ No alerts yet
      </div>
    );
  }
  
  // Données pour le camembert
  const data = [
    { name: 'Critical', value: severityCounts.critical, color: '#e8483a' },
    { name: 'High', value: severityCounts.high, color: '#f07030' },
    { name: 'Medium', value: severityCounts.medium, color: '#3a7ae8' },
    { name: 'Low', value: severityCounts.low, color: '#2ecc71' },
  ].filter(d => d.value > 0);
  
  // Calculer les angles pour le camembert (SVG)
  let currentAngle = -90; // Commencer à midi
  const radius = 60;
  const center = 75;
  
  const segments = [];
  data.forEach(item => {
    const angle = (item.value / total) * 360;
    const startAngle = currentAngle;
    const endAngle = currentAngle + angle;
    
    // Calculer les coordonnées pour l'arc SVG
    const startRad = (startAngle * Math.PI) / 180;
    const endRad = (endAngle * Math.PI) / 180;
    
    const x1 = center + radius * Math.cos(startRad);
    const y1 = center + radius * Math.sin(startRad);
    const x2 = center + radius * Math.cos(endRad);
    const y2 = center + radius * Math.sin(endRad);
    
    const largeArc = angle > 180 ? 1 : 0;
    
    segments.push({
      ...item,
      startAngle,
      endAngle,
      path: `M ${center} ${center} L ${x1} ${y1} A ${radius} ${radius} 0 ${largeArc} 1 ${x2} ${y2} Z`,
    });
    
    currentAngle = endAngle;
  });
  
  return (
    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 20, flexWrap: 'wrap' }}>
      {/* Camembert SVG */}
      <div style={{ position: 'relative', width: 150, height: 150 }}>
        <svg width="150" height="150" viewBox="0 0 150 150">
          {segments.map((segment, i) => (
            <path key={i} d={segment.path} fill={segment.color} stroke="#fff" strokeWidth="2" />
          ))}
          {/* Cercle intérieur pour faire un donut (optionnel) */}
          <circle cx="75" cy="75" r="35" fill="#fff" />
          <text x="75" y="78" textAnchor="middle" fontSize="14" fontWeight="700" fill="#1a1a2e">
            {total}
          </text>
          <text x="75" y="92" textAnchor="middle" fontSize="8" fill="#b0b0b0">
            total
          </text>
        </svg>
      </div>
      
      {/* Légende */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
        {data.map(item => (
          <div key={item.name} style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <div style={{ width: 12, height: 12, borderRadius: '50%', background: item.color }}></div>
            <span style={{ fontSize: 11, color: '#1a1a2e', minWidth: 55 }}>{item.name}</span>
            <span style={{ fontSize: 13, fontWeight: 700, color: item.color }}>{item.value}</span>
            <span style={{ fontSize: 10, color: '#b0b0b0' }}>({Math.round((item.value / total) * 100)}%)</span>
          </div>
        ))}
      </div>
    </div>
  );
}
// ── Dashboard Page WITH MITRE CHART ──────────────────────────────────────────
function PageDashboard({ alerts, logs, stats, onAck, filter, setFilter, search }) {
  const unacked  = alerts.filter(a => !a.acknowledged);
  const critical = alerts.filter(a => a.severity === 'critical').length;
  const machines = [...new Set(alerts.map(a => a.machine).filter(Boolean))];

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 12, height: '100%' }}>
      {/* 4 CARDS EN HAUT */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 12 }}>
        {[
          { label: 'Total Alerts',   value: alerts.length,   color: 'dodgerblue' },
          { label: 'Unacknowledged', value: unacked.length,  color: unacked.length > 0 ? RED : 'dodgerblue' },
          { label: 'Critical',       value: critical,        color: critical > 0 ? RED : 'dodgerblue' },
          { label: 'Machines',       value: machines.length, color: 'dodgerblue' },
        ].map(c => (
          <Card key={c.label}>
            <div style={{ fontSize: 10, color: '#b0b0b0', marginBottom: 6, fontWeight: 500 }}>{c.label}</div>
            <div style={{ fontSize: 28, fontWeight: 700, color: c.color }}>{c.value}</div>
          </Card>
        ))}
      </div>

      {/* CAMEMBERT (DIAGRAMME CIRCULAIRE) - PLACÉ ICI */}
      <Card>
        <div style={{ fontSize: 13, fontWeight: 700, color: '#1a1a2e', marginBottom: 12 }}>
          📊 Distribution des alertes par sévérité
        </div>
        <SeverityPieChart alerts={alerts} />
      </Card>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 280px', gap: 12, flex: 1, minHeight: 0 }}>
        {/* GAUCHE - ACTIVE ALERTS TABLE */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: 12, minHeight: 0 }}>
          <AlertsTable alerts={alerts} onAck={onAck} filter={filter} setFilter={setFilter} search={search} />
        </div>

        {/* DROITE - STATS */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
          {/* Machines Card */}
          <Card style={{ flex: 1, overflowY: 'auto' }}>
            <div style={{ fontSize: 13, fontWeight: 700, color: '#1a1a2e', marginBottom: 12 }}>Machines</div>
            {machines.length === 0 && <div style={{ fontSize: 11, color: '#d0d0d0', textAlign: 'center', padding: 16 }}>No machines yet</div>}
            {machines.map(m => {
              const mAlerts = alerts.filter(a => a.machine === m && !a.acknowledged);
              const hasCrit = mAlerts.some(a => a.severity === 'critical' || a.severity === 'high');
              return (
                <div key={m} style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '8px 0', borderBottom: '1px solid #f5f5f5' }}>
                  <div style={{ width: 28, height: 28, background: hasCrit ? '#ffeaea' : '#f5f5f7', borderRadius: 7, display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: 12 }}>⊡</div>
                  <div style={{ flex: 1, minWidth: 0 }}>
                    <div style={{ fontSize: 11, fontWeight: 600, color: '#1a1a2e', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{m}</div>
                    <div style={{ fontSize: 9, color: '#b0b0b0' }}>{mAlerts.length} active alerts</div>
                  </div>
                  <div style={{ width: 7, height: 7, borderRadius: '50%', background: hasCrit ? RED : '#2ecc71' }}></div>
                </div>
              );
            })}
          </Card>

          {/* Last 24h Card */}
          <Card>
            <div style={{ fontSize: 13, fontWeight: 700, color: '#1a1a2e', marginBottom: 10 }}>Last 24h</div>
            {stats.length === 0 && <div style={{ fontSize: 11, color: '#d0d0d0', textAlign: 'center' }}>No data</div>}
            {stats.map(s => (
              <div key={s.severity} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '5px 0', borderBottom: '1px solid #f5f5f5' }}>
                <span style={{ fontSize: 11, color: '#9a9a9a', textTransform: 'capitalize' }}>{s.severity}</span>
                <span style={{ fontSize: 12, fontWeight: 700, color: SEV_STYLE[s.severity]?.color || '#1a1a2e' }}>{s.count}</span>
              </div>
            ))}
          </Card>
        </div>
      </div>
    </div>
  );
}

// ── Alerts Page ───────────────────────────────────────────────────────────────
function PageAlerts({ alerts, onAck, filter, setFilter, search }) {
  const all = alerts.filter(a =>
    (filter === 'all' || a.severity === filter) &&
    (!search || a.machine?.toLowerCase().includes(search.toLowerCase()) || a.alert_type?.toLowerCase().includes(search.toLowerCase()))
  );

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 12, height: '100%' }}>
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(5, 1fr)', gap: 12 }}>
        {['all','critical','high','medium','low'].map(sev => {
          const count = sev === 'all' ? alerts.length : alerts.filter(a => a.severity === sev).length;
          const s = SEV_STYLE[sev] || { color: '#1a1a2e', background: '#f5f5f7' };
          return (
            <Card key={sev} style={{ cursor: 'pointer', border: filter === sev ? `2px solid ${RED}` : '2px solid transparent' }} onClick={() => setFilter(sev)}>
              <div style={{ fontSize: 10, color: '#b0b0b0', marginBottom: 4, textTransform: 'capitalize' }}>{sev === 'all' ? 'Total' : sev}</div>
              <div style={{ fontSize: 24, fontWeight: 700, color: sev === 'all' ? '#1a1a2e' : s.color }}>{count}</div>
            </Card>
          );
        })}
      </div>

      <Card style={{ flex: 1, overflow: 'hidden', display: 'flex', flexDirection: 'column' }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 12 }}>
          <div style={{ fontSize: 13, fontWeight: 700, color: '#1a1a2e' }}>All Alerts - {all.length} records</div>
          <div style={{ display: 'flex', gap: 4 }}>
            {['all','critical','high','medium','low'].map(f => (
              <button key={f} onClick={() => setFilter(f)} style={{ padding: '4px 10px', fontSize: 10, fontWeight: 600, borderRadius: 6, border: 'none', cursor: 'pointer', background: filter === f ? RED : '#f5f5f7', color: filter === f ? '#fff' : '#9a9a9a', fontFamily: 'inherit', textTransform: 'capitalize' }}>{f}</button>
            ))}
          </div>
        </div>
        <div style={{ overflowY: 'auto', flex: 1 }}>
          <table style={{ width: '100%', borderCollapse: 'collapse' }}>
            <thead style={{ position: 'sticky', top: 0, background: '#fff', zIndex: 1 }}>
              <tr style={{ background: '#fafafa' }}>
                {['#','Time','Type','Machine','Company','Severity','MITRE','Message','Status','Action'].map(h => (
                  <th key={h} style={{ padding: '8px 12px', fontSize: 10, color: '#b0b0b0', textAlign: 'left', fontWeight: 600, whiteSpace: 'nowrap' }}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {all.length === 0 && (
                <tr><td colSpan={10} style={{ padding: 40, textAlign: 'center', color: '#d0d0d0', fontSize: 12 }}>No alerts</td></tr>
              )}
              {all.map((a, i) => (
                <tr key={a.id} style={{ borderTop: '1px solid #f5f5f5', background: a.acknowledged ? '#fafafa' : '#fff' }}>
                  <td style={{ padding: '10px 12px', fontSize: 10, color: '#d0d0d0' }}>{i + 1}</td>
                  <td style={{ padding: '10px 12px', fontSize: 10, color: '#b0b0b0', whiteSpace: 'nowrap' }}>{new Date(a.created_at).toLocaleString()}</td>
                  <td style={{ padding: '10px 12px', fontSize: 11, fontWeight: 600, color: '#1a1a2e', whiteSpace: 'nowrap' }}>{a.alert_type?.replace(/_/g, ' ')}</td>
                  <td style={{ padding: '10px 12px', fontSize: 11, color: '#1a1a2e' }}>{a.machine || '-'}</td>
                  <td style={{ padding: '10px 12px', fontSize: 11, color: '#9a9a9a' }}>{a.company_id}</td>
                  <td style={{ padding: '10px 12px' }}><SevBadge sev={a.severity} /></td>
                  <td style={{ padding: '10px 12px' }}>
                    {a.mitre_id ? (
                      <div>
                        <div style={{ fontSize: 10, fontWeight: 700, color: MITRE_COLOR[a.mitre_tactic] || '#9a9a9a' }}>{a.mitre_id}</div>
                        <div style={{ fontSize: 9, color: '#b0b0b0' }}>{a.mitre_tactic}</div>
                      </div>
                    ) : <span style={{ color: '#d0d0d0', fontSize: 10 }}>-</span>}
                  </td>
                  <td style={{ padding: '10px 12px', fontSize: 11, color: '#9a9a9a', maxWidth: 260, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{a.message || '-'}</td>
                  <td style={{ padding: '10px 12px' }}>
                    <span style={{ fontSize: 10, fontWeight: 600, color: a.acknowledged ? '#2ecc71' : RED }}>
                      {a.acknowledged ? '✓ Acked' : '● Open'}
                    </span>
                  </td>
                  <td style={{ padding: '10px 12px' }}>
                    {!a.acknowledged && (
                      <button onClick={() => onAck(a.id)} style={{ padding: '4px 12px', background: '#ffeaea', color: RED, border: 'none', borderRadius: 6, fontSize: 10, fontWeight: 600, cursor: 'pointer', fontFamily: 'inherit' }}>Ack</button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Card>
    </div>
  );
}



// ── MITRE Donut Chart Component ──────────────────────────────────────────────
function MitreDonut({ alerts }) {
  const mitreAlerts = alerts.filter(a => a.mitre_id && a.mitre_tactic);
  const tacticCounts = {};
  
  mitreAlerts.forEach(a => {
    const tactic = a.mitre_tactic;
    if (tactic) {
      tacticCounts[tactic] = (tacticCounts[tactic] || 0) + 1;
    }
  });
  
  const total = Object.values(tacticCounts).reduce((a, b) => a + b, 0);
  
  if (total === 0) {
    return (
      <div>
        <div style={{ fontSize: 13, fontWeight: 700, color: '#1a1a2e', marginBottom: 12 }}>MITRE ATT&CK Distribution</div>
        <div style={{ textAlign: 'center', padding: 20, color: '#b0b0b0', fontSize: 12 }}>
          ⚠ No MITRE data yet<br/>
          <span style={{ fontSize: 10 }}>Run SQL UPDATE to add MITRE mapping</span>
        </div>
      </div>
    );
  }
  
  const colors = {
    'Credential Access': '#e8483a',
    'Persistence': '#f07030',
    'Exfiltration': '#9b59b6', 
    'Execution': '#3a7ae8',
    'Defense Evasion': '#e67e22',
    'Impact': '#c0392b',
    'Lateral Movement': '#1abc9c',
    'Discovery': '#3498db'
  };
  
  return (
    <div>
      <div style={{ fontSize: 13, fontWeight: 700, color: '#1a1a2e', marginBottom: 12 }}>MITRE ATT&CK Distribution</div>
      {Object.entries(tacticCounts).map(([tactic, count]) => {
        const pct = Math.round((count / total) * 100);
        return (
          <div key={tactic} style={{ marginBottom: 10 }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 4 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                <div style={{ width: 8, height: 8, borderRadius: '50%', background: colors[tactic] || '#b0b0b0' }}></div>
                <span style={{ fontSize: 11, fontWeight: 500, color: '#1a1a2e' }}>{tactic}</span>
              </div>
              <span style={{ fontSize: 11, fontWeight: 700, color: colors[tactic] || '#b0b0b0' }}>{count} ({pct}%)</span>
            </div>
            <div style={{ height: 4, background: '#f5f5f7', borderRadius: 2 }}>
              <div style={{ height: '100%', width: `${pct}%`, background: colors[tactic] || '#b0b0b0', borderRadius: 2 }}></div>
            </div>
          </div>
        );
      })}
    </div>
  );
}
// ── Live Logs Page ────────────────────────────────────────────────────────────
function PageLiveLogs({ logs }) {
  const [typeFilter, setTypeFilter] = useState('all');
  const types = ['all', ...new Set(logs.map(l => l.alert_type || l['event']?.code).filter(Boolean))];
  const filtered = logs.filter(l => typeFilter === 'all' || (l.alert_type || l['event']?.code) === typeFilter);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 12, height: '100%' }}>
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 12 }}>
        <Card>
          <div style={{ fontSize: 10, color: '#b0b0b0', marginBottom: 4 }}>Total Events</div>
          <div style={{ fontSize: 24, fontWeight: 700, color: '#1a1a2e' }}>{logs.length}</div>
        </Card>
        <Card>
          <div style={{ fontSize: 10, color: '#b0b0b0', marginBottom: 4 }}>Alert Events</div>
          <div style={{ fontSize: 24, fontWeight: 700, color: RED }}>{logs.filter(l => l.alert_type).length}</div>
        </Card>
        <Card>
          <div style={{ fontSize: 10, color: '#b0b0b0', marginBottom: 4 }}>Machines Seen</div>
          <div style={{ fontSize: 24, fontWeight: 700, color: '#1a1a2e' }}>{[...new Set(logs.map(l => l.host?.name).filter(Boolean))].length}</div>
        </Card>
      </div>

      <Card style={{ flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 12, flexWrap: 'wrap' }}>
          <div style={{ fontSize: 13, fontWeight: 700, color: '#1a1a2e', marginRight: 8 }}>Event Stream</div>
          {types.slice(0, 8).map(t => (
            <button key={t} onClick={() => setTypeFilter(t)} style={{ padding: '3px 8px', fontSize: 10, borderRadius: 6, border: 'none', cursor: 'pointer', background: typeFilter === t ? RED : '#f5f5f7', color: typeFilter === t ? '#fff' : '#9a9a9a', fontFamily: 'inherit' }}>{t}</button>
          ))}
          <div style={{ marginLeft: 'auto', fontSize: 10, color: '#2ecc71', fontWeight: 600 }}>● Live - {filtered.length} events</div>
        </div>
        <div style={{ overflowY: 'auto', flex: 1, fontFamily: 'monospace', fontSize: 11 }}>
          {filtered.length === 0 && <div style={{ color: '#d0d0d0', padding: 40, textAlign: 'center' }}>No events</div>}
          {filtered.map((l, i) => {
            const isAlert = l.severity === 'critical' || l.severity === 'high' || l.alert_type;
            return (
              <div key={i} style={{ display: 'grid', gridTemplateColumns: '80px 16px 120px 160px 1fr', gap: 10, padding: '6px 8px', borderBottom: '1px solid #fafafa', alignItems: 'center', background: isAlert ? '#fffafa' : '#fff' }}>
                <span style={{ color: '#d0d0d0', fontSize: 10 }}>{l['@timestamp']?.slice(11, 19)}</span>
                <span style={{ width: 5, height: 5, borderRadius: '50%', background: isAlert ? RED : '#d0d0d0', display: 'inline-block' }}></span>
                <span style={{ color: isAlert ? RED : '#9a9a9a', fontWeight: isAlert ? 600 : 400, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{l.alert_type || l['event']?.code || 'event'}</span>
                <span style={{ color: '#1a1a2e', fontWeight: 500 }}>{l.host?.name || '-'}</span>
                <span style={{ color: '#b0b0b0', fontSize: 10, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{l['event']?.action || l.message?.slice(0, 80) || ''}</span>
              </div>
            );
          })}
        </div>
      </Card>
    </div>
  );
}

// ── Machines Page ─────────────────────────────────────────────────────────────
function PageMachines({ logs, alerts }) {
  const machines  = [...new Set([
    ...logs.map(l => l.host?.name),
    ...alerts.map(a => a.machine)
  ].filter(Boolean))];
  const companies = [...new Set(alerts.map(a => a.company_id).filter(Boolean))];

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 12, height: '100%' }}>
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 12 }}>
        <Card>
          <div style={{ fontSize: 10, color: '#b0b0b0', marginBottom: 4 }}>Total Machines</div>
          <div style={{ fontSize: 24, fontWeight: 700, color: '#1a1a2e' }}>{machines.length}</div>
        </Card>
        <Card>
          <div style={{ fontSize: 10, color: '#b0b0b0', marginBottom: 4 }}>Companies</div>
          <div style={{ fontSize: 24, fontWeight: 700, color: '#1a1a2e' }}>{companies.length}</div>
        </Card>
        <Card>
          <div style={{ fontSize: 10, color: '#b0b0b0', marginBottom: 4 }}>Machines with Alerts</div>
          <div style={{ fontSize: 24, fontWeight: 700, color: RED }}>
            {machines.filter(m => alerts.filter(a => a.machine === m && !a.acknowledged).length > 0).length}
          </div>
        </Card>
      </div>

      <Card style={{ flex: 1, overflow: 'hidden', display: 'flex', flexDirection: 'column' }}>
        <div style={{ fontSize: 13, fontWeight: 700, color: '#1a1a2e', marginBottom: 12 }}>All Endpoints</div>
        <div style={{ overflowY: 'auto', flex: 1 }}>
          <table style={{ width: '100%', borderCollapse: 'collapse' }}>
            <thead style={{ position: 'sticky', top: 0, background: '#fff', zIndex: 1 }}>
              <tr style={{ background: '#fafafa' }}>
                {['Machine','Company','Total Alerts','Open Alerts','Critical','Status'].map(h => (
                  <th key={h} style={{ padding: '8px 16px', fontSize: 10, color: '#b0b0b0', textAlign: 'left', fontWeight: 600 }}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {machines.length === 0 && (
                <tr><td colSpan={6} style={{ padding: 40, textAlign: 'center', color: '#d0d0d0', fontSize: 12 }}>No machines detected yet. Install Winlogbeat on client machines.</td></tr>
              )}
              {machines.map(m => {
                const mAll  = alerts.filter(a => a.machine === m);
                const mOpen = mAll.filter(a => !a.acknowledged);
                const mCrit = mAll.filter(a => a.severity === 'critical');
                const company = mAll[0]?.company_id || '-';
                const status  = mOpen.length === 0 ? 'clean' : mCrit.length > 0 ? 'critical' : 'warning';
                return (
                  <tr key={m} style={{ borderTop: '1px solid #f5f5f5' }}>
                    <td style={{ padding: '14px 16px' }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                        <div style={{ width: 32, height: 32, background: status === 'critical' ? '#ffeaea' : status === 'warning' ? '#fff4ea' : '#eafff2', borderRadius: 8, display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: 14 }}>⊡</div>
                        <div>
                          <div style={{ fontSize: 12, fontWeight: 600, color: '#1a1a2e' }}>{m}</div>
                          <div style={{ fontSize: 10, color: '#b0b0b0' }}>Windows endpoint</div>
                        </div>
                      </div>
                    </td>
                    <td style={{ padding: '14px 16px', fontSize: 12, color: '#9a9a9a' }}>{company}</td>
                    <td style={{ padding: '14px 16px', fontSize: 12, fontWeight: 600, color: '#1a1a2e' }}>{mAll.length}</td>
                    <td style={{ padding: '14px 16px', fontSize: 12, fontWeight: 600, color: mOpen.length > 0 ? RED : '#2ecc71' }}>{mOpen.length}</td>
                    <td style={{ padding: '14px 16px', fontSize: 12, fontWeight: 600, color: mCrit.length > 0 ? RED : '#b0b0b0' }}>{mCrit.length}</td>
                    <td style={{ padding: '14px 16px' }}>
                      <span style={{ padding: '4px 10px', borderRadius: 20, fontSize: 10, fontWeight: 600, background: status === 'clean' ? '#eafff2' : status === 'critical' ? '#ffeaea' : '#fff4ea', color: status === 'clean' ? '#2ecc71' : status === 'critical' ? RED : '#f07030' }}>
                        {status === 'clean' ? '✓ Clean' : status === 'critical' ? '● Critical' : '⚠ Warning'}
                      </span>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </Card>
    </div>
  );
}

// ── MITRE ATT&CK Page ─────────────────────────────────────────────────────────
function PageMITRE({ alerts }) {
  const mitreAlerts = alerts.filter(a => a.mitre_id);

  const byTechnique = {};
  mitreAlerts.forEach(a => {
    const key = a.mitre_id;
    if (!byTechnique[key]) {
      byTechnique[key] = { id: a.mitre_id, name: a.mitre_name, tactic: a.mitre_tactic, count: 0, machines: new Set(), alerts: [] };
    }
    byTechnique[key].count++;
    if (a.machine) byTechnique[key].machines.add(a.machine);
    byTechnique[key].alerts.push(a);
  });

  const techniques = Object.values(byTechnique).sort((a, b) => b.count - a.count);

  const byTactic = {};
  techniques.forEach(t => {
    if (!byTactic[t.tactic]) byTactic[t.tactic] = [];
    byTactic[t.tactic].push(t);
  });

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 12 }}>
        {[
          { label: 'Techniques Detected', value: techniques.length },
          { label: 'Tactics Covered',     value: Object.keys(byTactic).length },
          { label: 'Total MITRE Events',  value: mitreAlerts.length },
          { label: 'Machines Affected',   value: new Set(mitreAlerts.map(a => a.machine).filter(Boolean)).size },
        ].map(c => (
          <Card key={c.label}>
            <div style={{ fontSize: 10, color: '#b0b0b0', marginBottom: 4 }}>{c.label}</div>
            <div style={{ fontSize: 24, fontWeight: 700, color: '#1a1a2e' }}>{c.value}</div>
          </Card>
        ))}
      </div>

      {techniques.length === 0 && (
        <Card>
          <div style={{ textAlign: 'center', padding: 40, color: '#d0d0d0', fontSize: 12 }}>
            No MITRE ATT&CK data yet - alerts with known technique mappings will appear here.
          </div>
        </Card>
      )}

      {Object.entries(byTactic).map(([tactic, techs]) => (
        <Card key={tactic}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 12 }}>
            <div style={{ width: 10, height: 10, borderRadius: '50%', background: MITRE_COLOR[tactic] || '#9a9a9a' }}></div>
            <div style={{ fontSize: 13, fontWeight: 700, color: '#1a1a2e' }}>{tactic}</div>
            <span style={{ fontSize: 10, color: '#b0b0b0' }}>{techs.length} technique{techs.length > 1 ? 's' : ''}</span>
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(260px, 1fr))', gap: 10 }}>
            {techs.map(t => (
              <div key={t.id} style={{ border: `1.5px solid ${MITRE_COLOR[t.tactic] || '#f0f0f0'}22`, borderRadius: 10, padding: 12, background: `${MITRE_COLOR[t.tactic] || '#f5f5f7'}08` }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 6 }}>
                  <div>
                    <div style={{ fontSize: 11, fontWeight: 700, color: MITRE_COLOR[t.tactic] || '#1a1a2e' }}>{t.id}</div>
                    <div style={{ fontSize: 12, fontWeight: 600, color: '#1a1a2e', marginTop: 2 }}>{t.name}</div>
                  </div>
                  <div style={{ fontSize: 18, fontWeight: 700, color: MITRE_COLOR[t.tactic] || '#1a1a2e' }}>{t.count}</div>
                </div>
                <div style={{ fontSize: 10, color: '#b0b0b0' }}>
                  {t.machines.size} machine{t.machines.size !== 1 ? 's' : ''} · {t.count} event{t.count !== 1 ? 's' : ''}
                </div>
                {t.machines.size > 0 && (
                  <div style={{ marginTop: 6, display: 'flex', flexWrap: 'wrap', gap: 4 }}>
                    {[...t.machines].slice(0, 3).map(m => (
                      <span key={m} style={{ fontSize: 9, background: '#f5f5f7', color: '#9a9a9a', padding: '2px 6px', borderRadius: 4 }}>{m}</span>
                    ))}
                    {t.machines.size > 3 && <span style={{ fontSize: 9, color: '#b0b0b0' }}>+{t.machines.size - 3} more</span>}
                  </div>
                )}
              </div>
            ))}
          </div>
        </Card>
      ))}
    </div>
  );
}

// ── Reports Page ──────────────────────────────────────────────────────────────
function PageReports({ alerts, stats }) {
  const companies = [...new Set(alerts.map(a => a.company_id).filter(Boolean))];
  const acked     = alerts.filter(a => a.acknowledged).length;
  const rate      = alerts.length > 0 ? Math.round((acked / alerts.length) * 100) : 0;

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 12 }}>
        {[
          { label: 'Total Alerts',     value: alerts.length },
          { label: 'Acknowledged',     value: acked },
          { label: 'Ack Rate',         value: `${rate}%` },
          { label: 'Active Companies', value: companies.length },
        ].map(c => (
          <Card key={c.label}>
            <div style={{ fontSize: 10, color: '#b0b0b0', marginBottom: 4 }}>{c.label}</div>
            <div style={{ fontSize: 24, fontWeight: 700, color: '#1a1a2e' }}>{c.value}</div>
          </Card>
        ))}
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
        <Card>
          <div style={{ fontSize: 13, fontWeight: 700, color: '#1a1a2e', marginBottom: 12 }}>By Company</div>
          {companies.length === 0 && <div style={{ color: '#d0d0d0', fontSize: 12, textAlign: 'center', padding: 20 }}>No data</div>}
          {companies.map(c => {
            const count = alerts.filter(a => a.company_id === c).length;
            const open  = alerts.filter(a => a.company_id === c && !a.acknowledged).length;
            return (
              <div key={c} style={{ display: 'flex', alignItems: 'center', gap: 12, padding: '10px 0', borderBottom: '1px solid #f5f5f5' }}>
                <div style={{ width: 32, height: 32, background: '#ffeaea', borderRadius: 8, display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: 12, color: RED, fontWeight: 700 }}>{c[0]?.toUpperCase()}</div>
                <div style={{ flex: 1 }}>
                  <div style={{ fontSize: 12, fontWeight: 600, color: '#1a1a2e' }}>{c}</div>
                  <div style={{ fontSize: 10, color: '#b0b0b0' }}>{count} total · {open} open</div>
                </div>
                <div style={{ fontSize: 12, fontWeight: 700, color: open > 0 ? RED : '#2ecc71' }}>{open > 0 ? `${open} open` : '✓ Clear'}</div>
              </div>
            );
          })}
        </Card>

        <Card>
          <div style={{ fontSize: 13, fontWeight: 700, color: '#1a1a2e', marginBottom: 12 }}>By Alert Type</div>
          {(() => {
            const types = {};
            alerts.forEach(a => { types[a.alert_type] = (types[a.alert_type] || 0) + 1; });
            return Object.entries(types).sort((a, b) => b[1] - a[1]).map(([type, count]) => (
              <div key={type} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '8px 0', borderBottom: '1px solid #f5f5f5' }}>
                <span style={{ fontSize: 12, color: '#1a1a2e', textTransform: 'capitalize' }}>{type?.replace(/_/g, ' ')}</span>
                <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                  <div style={{ width: 80, height: 4, background: '#f5f5f7', borderRadius: 2 }}>
                    <div style={{ height: '100%', width: `${Math.round((count / alerts.length) * 100)}%`, background: RED, borderRadius: 2 }}></div>
                  </div>
                  <span style={{ fontSize: 12, fontWeight: 700, color: '#1a1a2e', minWidth: 20 }}>{count}</span>
                </div>
              </div>
            ));
          })()}
        </Card>
      </div>

      <Card>
        <div style={{ fontSize: 13, fontWeight: 700, color: '#1a1a2e', marginBottom: 4 }}>How to add more machines</div>
        <div style={{ fontSize: 12, color: '#9a9a9a', lineHeight: 1.8 }}>
          On each Windows machine, install Winlogbeat and set <code style={{ background: '#f5f5f7', padding: '1px 6px', borderRadius: 4 }}>company_id</code> to the client name.
          Each client gets their own index in Elasticsearch and their own login.
          Logstash address: <code style={{ background: '#f5f5f7', padding: '1px 6px', borderRadius: 4 }}>YOUR_VPS_IP:5044</code>
        </div>
      </Card>
    </div>
  );
}

// ── AI Agent Page ─────────────────────────────────────────────────────────────
// ── AI Agent Page - VERSION CORRIGEE ─────────────────────────────────────────
function PageAI({ token }) {
  const [analysis, setAnalysis]       = useState(null);
  const [loadingAI, setLoadingAI]     = useState(false);
  const [nmapTarget, setNmapTarget]   = useState('');
  const [nmapResult, setNmapResult]   = useState(null);
  const [loadingNmap, setLoadingNmap] = useState(false);
  const [chatInput, setChatInput]     = useState('');
  const [chatHistory, setChatHistory] = useState([]);
  const [loadingChat, setLoadingChat] = useState(false);
  const chatEndRef = useRef(null);

  const headers = { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' };

  useEffect(() => {
    chatEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [chatHistory]);

  const runAnalysis = async () => {
    setLoadingAI(true);
    setAnalysis(null);
    try {
      const res  = await fetch(`${API}/ai/analyze`, { method: 'POST', headers });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Server error');
      setAnalysis(data);
    } catch (e) {
      alert(`Analysis failed: ${e.message}`);
    } finally {
      setLoadingAI(false);
    }
  };

  const runNmap = async () => {
    if (!nmapTarget.trim()) {
      alert('Please enter an IP address');
      return;
    }
    setLoadingNmap(true);
    setNmapResult(null);
    try {
      console.log('Sending scan request for:', nmapTarget);
      const res  = await fetch(`${API}/ai/nmap`, { 
        method: 'POST', 
        headers, 
        body: JSON.stringify({ ip: nmapTarget.trim() }) 
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Scan failed');
      console.log('Scan result:', data);
      setNmapResult(data);
    } catch (e) {
      console.error('Nmap error:', e);
      alert(`Nmap failed: ${e.message}`);
    } finally {
      setLoadingNmap(false);
    }
  };

  const sendChat = async () => {
    const msg = chatInput.trim();
    if (!msg || loadingChat) return;

    const newHistory = [...chatHistory, { role: 'analyst', content: msg }];
    setChatHistory(newHistory);
    setChatInput('');
    setLoadingChat(true);

    try {
      const res  = await fetch(`${API}/ai/chat`, {
        method: 'POST',
        headers,
        body: JSON.stringify({ message: msg, history: newHistory }),
      });
      const data = await res.json();

      if (!res.ok) {
        setChatHistory(prev => [...prev, { role: 'AI', content: `⚠ Error: ${data.error || 'Server error'}` }]);
      } else if (!data.response || data.response.trim() === '') {
        setChatHistory(prev => [...prev, { role: 'AI', content: '⚠ Empty response - check if API key is configured.' }]);
      } else {
        setChatHistory(prev => [...prev, { role: 'AI', content: data.response }]);
      }
    } catch (e) {
      setChatHistory(prev => [...prev, { role: 'AI', content: `⚠ Network error: ${e.message}` }]);
    } finally {
      setLoadingChat(false);
    }
  };

  const riskColor = { critical: '#e8483a', high: '#f07030', medium: '#3a7ae8', low: '#2ecc71', unknown: '#b0b0b0' };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>

      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
        <div>
          <div style={{ fontSize: 16, fontWeight: 700, color: '#1a1a2e' }}>Agent IA de Sécurité</div>
          <div style={{ fontSize: 11, color: '#b0b0b0' }}>Analyse des incidents et recommandations</div>
        </div>
        <button onClick={runAnalysis} disabled={loadingAI} style={{ padding: '10px 20px', background: loadingAI ? '#f5f5f7' : 'dodgerblue', color: loadingAI ? '#b0b0b0' : '#fff', border: 'none', borderRadius: 8, fontSize: 12, fontWeight: 600, cursor: loadingAI ? 'not-allowed' : 'pointer', fontFamily: 'inherit' }}>
          {loadingAI ? '⏳ Analyse en cours...' : '🔍 Analyser les incidents'}
        </button>
      </div>

      {/* Analysis Result */}
      {analysis && (
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
          <Card>
            <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 12 }}>
              <div style={{ fontSize: 13, fontWeight: 700, color: '#1a1a2e' }}>Évaluation des risques</div>
              <span style={{ padding: '3px 10px', borderRadius: 20, fontSize: 11, fontWeight: 700, background: (riskColor[analysis.risk_level] || '#b0b0b0') + '22', color: riskColor[analysis.risk_level] || '#b0b0b0' }}>
                {analysis.risk_level?.toUpperCase() || 'INCONNU'}
              </span>
            </div>
            <div style={{ fontSize: 12, color: '#9a9a9a', lineHeight: 1.7, marginBottom: 12 }}>{analysis.summary || 'Aucune information'}</div>
            {analysis.threats?.length > 0 && (
              <>
                <div style={{ fontSize: 11, fontWeight: 600, color: '#1a1a2e', marginBottom: 8 }}>Menaces détectées</div>
                {analysis.threats.map((t, i) => (
                  <div key={i} style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '5px 0', borderBottom: '1px solid #f5f5f5' }}>
                    <span style={{ width: 5, height: 5, borderRadius: '50%', background: '#e8483a', flexShrink: 0 }}></span>
                    <span style={{ fontSize: 12, color: '#1a1a2e' }}>{t}</span>
                  </div>
                ))}
              </>
            )}
          </Card>

          <Card>
            <div style={{ fontSize: 13, fontWeight: 700, color: '#1a1a2e', marginBottom: 12 }}>Actions immédiates</div>
            {analysis.immediate_actions?.map((a, i) => (
              <div key={i} style={{ display: 'flex', gap: 10, padding: '6px 0', borderBottom: '1px solid #f5f5f5' }}>
                <span style={{ width: 20, height: 20, background: 'dodgerblue', color: '#fff', borderRadius: '50%', display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: 10, fontWeight: 700, flexShrink: 0 }}>{i + 1}</span>
                <span style={{ fontSize: 12, color: '#1a1a2e', lineHeight: 1.5 }}>{a}</span>
              </div>
            ))}
          </Card>

          <Card>
            <div style={{ fontSize: 13, fontWeight: 700, color: '#1a1a2e', marginBottom: 12 }}>Recommandations</div>
            {analysis.recommendations?.map((r, i) => (
              <div key={i} style={{ display: 'flex', gap: 10, padding: '6px 0', borderBottom: '1px solid #f5f5f5', alignItems: 'flex-start' }}>
                <span style={{ fontSize: 14, flexShrink: 0, color: '#2ecc71' }}>✓</span>
                <span style={{ fontSize: 12, color: '#1a1a2e', lineHeight: 1.5 }}>{r}</span>
              </div>
            ))}
          </Card>

          <Card>
            <div style={{ fontSize: 13, fontWeight: 700, color: '#1a1a2e', marginBottom: 12 }}>Explication</div>
            <div style={{ fontSize: 12, color: '#9a9a9a', lineHeight: 1.8 }}>{analysis.explanation || analysis.summary}</div>
          </Card>
        </div>
      )}

      {/* Nmap Scanner - CORRIGE */}
      <Card>
        <div style={{ fontSize: 13, fontWeight: 700, color: '#1a1a2e', marginBottom: 4 }}>Scanner Réseau (Nmap + IA)</div>
        <div style={{ fontSize: 11, color: '#b0b0b0', marginBottom: 12 }}>Scannez une IP pour détecter les ports ouverts et obtenir une analyse des vulnérabilités</div>
        <div style={{ display: 'flex', gap: 8, marginBottom: 12 }}>
          <input
            value={nmapTarget}
            onChange={e => setNmapTarget(e.target.value)}
            onKeyDown={e => e.key === 'Enter' && runNmap()}
            placeholder="Entrez une adresse IP ex: 192.168.1.50"
            style={{ flex: 1, padding: '9px 14px', border: '1.5px solid #f0f0f0', borderRadius: 8, fontSize: 12, outline: 'none', background: '#fafafa', color: '#1a1a2e', fontFamily: 'inherit' }}
          />
          <button onClick={runNmap} disabled={loadingNmap || !nmapTarget.trim()} style={{ padding: '9px 20px', background: loadingNmap ? '#f5f5f7' : '#1a1a2e', color: loadingNmap ? '#b0b0b0' : '#fff', border: 'none', borderRadius: 8, fontSize: 12, fontWeight: 600, cursor: loadingNmap ? 'not-allowed' : 'pointer', fontFamily: 'inherit', whiteSpace: 'nowrap' }}>
            {loadingNmap ? '⏳ Scan en cours...' : '▶ Lancer le scan'}
          </button>
        </div>

        {nmapResult && (
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
            <div>
              <div style={{ fontSize: 11, fontWeight: 600, color: '#1a1a2e', marginBottom: 8 }}>
                Ports ouverts sur {nmapResult.target}
                {nmapResult.risk_level && (
                  <span style={{ marginLeft: 8, padding: '2px 8px', borderRadius: 20, fontSize: 10, background: (riskColor[nmapResult.risk_level] || '#b0b0b0') + '22', color: riskColor[nmapResult.risk_level] || '#b0b0b0' }}>
                    RISQUE {nmapResult.risk_level.toUpperCase()}
                  </span>
                )}
              </div>
              {!nmapResult.open_ports?.length && <div style={{ fontSize: 12, color: '#d0d0d0' }}>Aucun port ouvert trouvé</div>}
              {nmapResult.open_ports?.map((p, i) => (
                <div key={i} style={{ display: 'flex', justifyContent: 'space-between', padding: '5px 0', borderBottom: '1px solid #f5f5f5', fontSize: 12 }}>
                  <span style={{ fontWeight: 600, color: '#1a1a2e' }}>:{p.port}</span>
                  <span style={{ color: '#9a9a9a' }}>{p.service || p.protocol}</span>
                </div>
              ))}
              {nmapResult.vulnerabilities?.length > 0 && (
                <>
                  <div style={{ fontSize: 11, fontWeight: 600, color: '#1a1a2e', margin: '12px 0 8px' }}>Vulnérabilités identifiées</div>
                  {nmapResult.vulnerabilities.map((v, i) => (
                    <div key={i} style={{ display: 'flex', gap: 8, padding: '4px 0', fontSize: 12, color: '#e8483a' }}>
                      <span>⚠</span><span>{v}</span>
                    </div>
                  ))}
                </>
              )}
            </div>
            <div>
              <div style={{ fontSize: 11, fontWeight: 600, color: '#1a1a2e', marginBottom: 8 }}>Recommandations</div>
              {nmapResult.recommendations?.map((r, i) => (
                <div key={i} style={{ display: 'flex', gap: 8, padding: '5px 0', borderBottom: '1px solid #f5f5f5', fontSize: 12 }}>
                  <span style={{ color: '#2ecc71', flexShrink: 0 }}>✓</span>
                  <span style={{ color: '#1a1a2e' }}>{r}</span>
                </div>
              ))}
            </div>
          </div>
        )}
        
        {nmapResult?.raw_output && (
          <details style={{ marginTop: 12 }}>
            <summary style={{ fontSize: 11, color: '#b0b0b0', cursor: 'pointer' }}>Résultat brut Nmap</summary>
            <pre style={{ fontSize: 10, color: '#9a9a9a', background: '#fafafa', padding: 12, borderRadius: 8, marginTop: 8, overflow: 'auto', maxHeight: 200 }}>{nmapResult.raw_output}</pre>
          </details>
        )}
        
        {nmapResult?.error && (
          <div style={{ marginTop: 12, padding: 12, background: '#ffeaea', borderRadius: 8, color: '#e8483a', fontSize: 12 }}>
            ⚠ {nmapResult.error}
          </div>
        )}
      </Card>

      {/* AI Chat - garder identique mais traduire prompts */}
      <Card>
        <div style={{ fontSize: 13, fontWeight: 700, color: '#1a1a2e', marginBottom: 4 }}>Assistant IA de Sécurité</div>
        <div style={{ fontSize: 11, color: '#b0b0b0', marginBottom: 12 }}>Posez des questions sur vos alertes, techniques MITRE ou comment protéger vos machines</div>

        <div style={{ minHeight: 200, maxHeight: 340, overflowY: 'auto', marginBottom: 12, padding: 12, background: '#fafafa', borderRadius: 8 }}>
          {chatHistory.length === 0 && (
            <div style={{ color: '#d0d0d0', fontSize: 12, textAlign: 'center', paddingTop: 70 }}>
              Bonjour ! Je suis votre assistant sécurité. Posez-moi une question...
            </div>
          )}
          {chatHistory.map((m, i) => (
            <div key={i} style={{ marginBottom: 12, display: 'flex', gap: 8, flexDirection: m.role === 'analyst' ? 'row-reverse' : 'row' }}>
              <div style={{ width: 26, height: 26, borderRadius: '50%', background: m.role === 'analyst' ? '#ffeaea' : 'dodgerblue', display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: 10, color: m.role === 'analyst' ? '#e8483a' : '#fff', fontWeight: 700, flexShrink: 0 }}>
                {m.role === 'analyst' ? 'A' : 'AI'}
              </div>
              <div style={{ maxWidth: '80%', padding: '8px 12px', borderRadius: 10, background: m.role === 'analyst' ? '#ffeaea' : '#fff', fontSize: 12, color: '#1a1a2e', lineHeight: 1.6, boxShadow: '0 1px 4px rgba(0,0,0,0.06)', whiteSpace: 'pre-wrap' }}>
                {m.content}
              </div>
            </div>
          ))}
          {loadingChat && (
            <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
              <div style={{ width: 26, height: 26, borderRadius: '50%', background: 'dodgerblue', display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: 10, color: '#fff', fontWeight: 700 }}>AI</div>
              <div style={{ fontSize: 12, color: '#b0b0b0' }}>L'IA réfléchit...</div>
            </div>
          )}
          <div ref={chatEndRef} />
        </div>

        <div style={{ display: 'flex', gap: 8 }}>
          <input
            value={chatInput}
            onChange={e => setChatInput(e.target.value)}
            onKeyDown={e => e.key === 'Enter' && !e.shiftKey && sendChat()}
            placeholder="Bonjour! / Qu'est-ce qu'une attaque par brute force? / Comment sécuriser un serveur?"
            style={{ flex: 1, padding: '9px 14px', border: '1.5px solid #f0f0f0', borderRadius: 8, fontSize: 12, outline: 'none', background: '#fafafa', color: '#1a1a2e', fontFamily: 'inherit' }}
          />
          <button onClick={sendChat} disabled={loadingChat || !chatInput.trim()} style={{ padding: '9px 20px', background: loadingChat || !chatInput.trim() ? '#f5f5f7' : 'dodgerblue', color: loadingChat || !chatInput.trim() ? '#b0b0b0' : '#fff', border: 'none', borderRadius: 8, fontSize: 12, fontWeight: 600, cursor: loadingChat || !chatInput.trim() ? 'not-allowed' : 'pointer', fontFamily: 'inherit' }}>
            Envoyer
          </button>
        </div>
      </Card>
    </div>
  );
}

// ── Main Dashboard Shell ──────────────────────────────────────────────────────
export default function Dashboard({ token, onLogout }) {
  const [alerts, setAlerts] = useState([]);
  const [logs,   setLogs]   = useState([]);
  const [stats,  setStats]  = useState([]);
  const [page,   setPage]   = useState('Dashboard');
  const [filter, setFilter] = useState('all');
  const [search, setSearch] = useState('');
  const [time,   setTime]   = useState(new Date());

  const headers = { Authorization: `Bearer ${token}` };

  useEffect(() => {
    const load = async () => {
      try {
        const [a, l, s] = await Promise.all([
          fetch(`${API}/alerts`, { headers }).then(r => r.json()),
          fetch(`${API}/logs`,   { headers }).then(r => r.json()),
          fetch(`${API}/stats`,  { headers }).then(r => r.json()),
        ]);
        setAlerts(Array.isArray(a) ? a : []);
        setLogs(Array.isArray(l)   ? l : []);
        setStats(Array.isArray(s)  ? s : []);
      } catch (e) { console.error(e); }
    };
    load();
    const iv = setInterval(load, 15000);
    const tc = setInterval(() => setTime(new Date()), 1000);
    return () => { clearInterval(iv); clearInterval(tc); };
  }, []);

  const ack = async (id) => {
    await fetch(`${API}/alerts/${id}/ack`, { method: 'PATCH', headers });
    setAlerts(a => a.map(x => x.id === id ? { ...x, acknowledged: true } : x));
  };

  const unacked  = alerts.filter(a => !a.acknowledged);
  const critical = alerts.filter(a => a.severity === 'critical').length;

  const renderPage = () => {
    switch (page) {
      case 'Alerts':    return <PageAlerts    alerts={alerts} onAck={ack} filter={filter} setFilter={setFilter} search={search} />;
      case 'Live Logs': return <PageLiveLogs  logs={logs} />;
      case 'Machines':  return <PageMachines  alerts={alerts} logs={logs} />;
      case 'MITRE':     return <PageMITRE     alerts={alerts} />;
      case 'Reports':   return <PageReports   alerts={alerts} stats={stats} />;
      case 'AI Agent':  return <PageAI        token={token} />;
      default:          return <PageDashboard alerts={alerts} logs={logs} stats={stats} onAck={ack} filter={filter} setFilter={setFilter} search={search} />;
    }
  };

  return (
    <div style={{ display: 'flex', width: '100vw', height: '100vh', background: '#f5f5f7', fontFamily: 'Inter, -apple-system, sans-serif', overflow: 'hidden', fontSize: 13 }}>
      {/* SIDEBAR */}
      <div style={{ width: 200, minWidth: 200, background: '#fff', display: 'flex', flexDirection: 'column', boxShadow: '2px 0 8px rgba(0,0,0,0.04)', zIndex: 10 }}>
          <div style={{ padding: '18px 16px 14px', borderBottom: '1px solid #f0f0f0' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <div style={{ width: 28, height: 28, background: 'dodgerblue', borderRadius: 8, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                <div style={{ width: 10, height: 10, background: '#fff', borderRadius: 2 }}></div>
              </div>
              <div>
                <div style={{ fontSize: 12, fontWeight: 700, color: '#1a1a2e' }}>Xibaar AI</div>
                <div style={{ fontSize: 9, color: '#b0b0b0' }}>Security Intelligence</div>
              </div>
            </div>
          </div>
        <div style={{ padding: '10px 16px', borderBottom: '1px solid #f0f0f0' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <div style={{ width: 28, height: 28, background: '#ffeaea', borderRadius: '50%', display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: 11, color: RED, fontWeight: 700 }}>A</div>
            <div>
              <div style={{ fontSize: 11, fontWeight: 600, color: '#1a1a2e' }}>Admin</div>
              <div style={{ fontSize: 9, color: '#b0b0b0' }}>Analyst</div>
            </div>
          </div>
        </div>

        <nav style={{ flex: 1, padding: '8px 8px' }}>
          {NAV.map(item => (
            <div key={item.label} onClick={() => setPage(item.label)} style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '9px 10px', borderRadius: 8, marginBottom: 2, cursor: 'pointer', fontSize: 12, fontWeight: 500, background: page === item.label ? '#ffeaea' : 'transparent', color: page === item.label ? RED : '#9a9a9a', transition: 'all 0.15s' }}>
              <span style={{ fontSize: 13 }}>{item.icon}</span>
              {item.label}
              {item.label === 'Alerts' && unacked.length > 0 && (
                <span style={{ marginLeft: 'auto', background: RED, color: '#fff', fontSize: 9, fontWeight: 700, padding: '2px 6px', borderRadius: 20 }}>{unacked.length}</span>
              )}
            </div>
          ))}
        </nav>

        <div style={{ padding: '10px 8px', borderTop: '1px solid #f0f0f0' }}>
          <button onClick={onLogout} style={{ width: '100%', padding: '8px', background: '#f5f5f7', color: '#9a9a9a', border: 'none', borderRadius: 8, fontSize: 11, fontWeight: 600, cursor: 'pointer', fontFamily: 'inherit' }}>Sign out</button>
        </div>
      </div>

      {/* MAIN */}
      <div style={{ flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden', minWidth: 0 }}>

        {/* TOPBAR */}
        <div style={{ height: 52, background: '#fff', borderBottom: '1px solid #f0f0f0', display: 'flex', alignItems: 'center', padding: '0 20px', gap: 12, flexShrink: 0 }}>
          <div style={{ flex: 1 }}>
            <div style={{ fontSize: 14, fontWeight: 700, color: '#1a1a2e' }}>{page}</div>
            <div style={{ fontSize: 9, color: '#b0b0b0' }}>{time.toLocaleString()}</div>
          </div>
          <input value={search} onChange={e => setSearch(e.target.value)} placeholder="Search alerts, machines..." style={{ width: 220, padding: '7px 14px', border: '1.5px solid #f0f0f0', borderRadius: 8, fontSize: 12, outline: 'none', background: '#fafafa', color: '#1a1a2e', fontFamily: 'inherit' }} />
          {critical > 0 && <div style={{ background: '#ffeaea', color: RED, fontSize: 10, fontWeight: 600, padding: '5px 10px', borderRadius: 20 }}>● {critical} Critical</div>}
          <div style={{ background: '#eafff2', color: '#2ecc71', fontSize: 10, fontWeight: 600, padding: '5px 10px', borderRadius: 20 }}>● Live</div>
        </div>

        {/* PAGE CONTENT */}
        <div style={{ flex: 1, overflow: 'auto', padding: 16 }}>
          {renderPage()}
        </div>
      </div>
    </div>
  );
}