import { useEffect, useState } from 'react'
import type { ChangeEvent } from 'react'
import { Activity, AlertTriangle, ArrowUpRight, Bell, BrainCircuit, Check, ChevronRight, Database, GitBranch, Laptop, Layers3, LockKeyhole, Menu, Network, Play, ScanLine, Search, Server, ShieldCheck, Sparkles, Upload, UserRound, X } from 'lucide-react'
import { Area, AreaChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'
import './App.css'

type Stage = { label: string; color: string }
type ChartPoint = { time: string; traffic: number; threat: number }
type DatasetSummary = { row_count: number; source_count: number; failed_logins: number; traffic: number; threat_score: number; confidence: number; current_stage: string; predicted_next_stage: string; risk: string }
type Alert = { severity: string; stage: string; time: string; source: string; action: string; color: string }

const stages: Stage[] = [
  { label: 'Normal Traffic', color: '#5d6a7e' }, { label: 'Port Scanning', color: '#25d9e8' },
  { label: 'Suspicious Login', color: '#a884ff' }, { label: 'Privilege Escalation', color: '#ffb25b' },
  { label: 'Data Exfiltration', color: '#ff647c' },
]
const defaultChart: ChartPoint[] = [
  { time: '09:14', traffic: 35, threat: 18 }, { time: '09:18', traffic: 42, threat: 22 },
  { time: '09:22', traffic: 38, threat: 28 }, { time: '09:26', traffic: 64, threat: 36 },
  { time: '09:30', traffic: 58, threat: 46 }, { time: '09:34', traffic: 74, threat: 58 },
  { time: '09:38', traffic: 82, threat: 66 }, { time: '09:42', traffic: 76, threat: 72 },
]
const defaultAlerts: Alert[] = [
  { severity: 'HIGH', stage: 'Privilege Escalation', time: '09:42:18', source: '10.24.8.17', action: 'Isolate endpoint', color: 'red' },
  { severity: 'MEDIUM', stage: 'Suspicious Login', time: '09:41:56', source: '185.203.118.4', action: 'Review session', color: 'orange' },
  { severity: 'LOW', stage: 'Port Scanning', time: '09:39:22', source: '172.16.4.9', action: 'Watch activity', color: 'cyan' },
]
const navItems = ['Overview', 'Attack Forecast', 'Network Graph', 'Explainability', 'Alerts', 'MITRE ATT&CK']

function App() {
  const [activeNav, setActiveNav] = useState('Overview')
  const [stageIndex, setStageIndex] = useState(2)
  const [isSimulating, setIsSimulating] = useState(false)
  const [mobileMenu, setMobileMenu] = useState(false)
  const [alerts, setAlerts] = useState<Alert[]>(defaultAlerts)
  const [datasetName, setDatasetName] = useState('No dataset uploaded')
  const [uploadMessage, setUploadMessage] = useState('')
  const [summary, setSummary] = useState<DatasetSummary | null>(null)
  const [chartData, setChartData] = useState(defaultChart)

  useEffect(() => {
    if (!isSimulating) return
    const timer = window.setInterval(() => setStageIndex((current) => {
      if (current >= stages.length - 1) { setIsSimulating(false); return current }
      return current + 1
    }), 1500)
    return () => window.clearInterval(timer)
  }, [isSimulating])

  const currentStage = stages[stageIndex]
  const predictedStage = stages[Math.min(stageIndex + 1, stages.length - 1)]
  const confidence = summary?.confidence ?? Math.min(98, 78 + stageIndex * 5)
  const risk = summary?.risk ?? (stageIndex >= 3 ? 'CRITICAL' : stageIndex === 2 ? 'HIGH' : 'ELEVATED')
  const eventCount = summary?.row_count ?? 28491
  const traffic = summary?.traffic ?? 8.42
  const threatScore = summary?.threat_score ?? 42 + stageIndex * 14

  function startSimulation() { setSummary(null); setStageIndex(0); setAlerts(defaultAlerts); setIsSimulating(true) }
  async function uploadDataset(event: ChangeEvent<HTMLInputElement>) {
    const file = event.target.files?.[0]
    if (!file) return
    const formData = new FormData()
    formData.append('file', file)
    setUploadMessage('Uploading...')
    try {
      const response = await fetch('http://127.0.0.1:8000/api/dataset', { method: 'POST', body: formData })
      const result = await response.json()
      if (!response.ok) throw new Error(result.detail || 'Upload failed')
      const uploadedSummary = result.summary as DatasetSummary
      const uploadedIndex = stages.findIndex((stage) => stage.label === uploadedSummary.current_stage)
      setDatasetName(result.filename)
      setSummary(uploadedSummary)
      setStageIndex(uploadedIndex >= 0 ? uploadedIndex : 0)
      setChartData(defaultChart.map((point, index) => ({
        ...point,
        traffic: Math.max(8, Math.round(uploadedSummary.traffic / 8 + index * uploadedSummary.threat_score / 20)),
        threat: Math.max(5, Math.round(uploadedSummary.threat_score * (index + 3) / 10)),
      })))
      setAlerts([{ severity: uploadedSummary.risk, stage: uploadedSummary.predicted_next_stage, time: new Date().toLocaleTimeString(), source: `${uploadedSummary.source_count} sources`, action: 'Review dataset', color: uploadedSummary.risk === 'CRITICAL' ? 'red' : 'orange' }])
      setUploadMessage(`${uploadedSummary.row_count.toLocaleString()} rows analyzed`)
    } catch (error) {
      setUploadMessage(error instanceof Error ? error.message : 'Upload failed')
    }
  }

  return <div className="app-shell">
    <aside className={`sidebar ${mobileMenu ? 'sidebar-open' : ''}`}>
      <div className="brand"><div className="brand-mark"><ScanLine size={21} /></div><div><strong>CYBER<span>PREDICT</span></strong><small>AI SECURITY COMMAND</small></div><button className="icon-button close-mobile" onClick={() => setMobileMenu(false)} aria-label="Close menu"><X size={18} /></button></div>
      <div className="workspace-switch"><span className="status-dot" /> SOC / PRIMARY <ChevronRight size={14} /></div>
      <nav><p className="nav-label">OPERATIONS</p>{navItems.map((item, index) => <button key={item} className={`nav-item ${activeNav === item ? 'active' : ''}`} onClick={() => { setActiveNav(item); setMobileMenu(false) }}><Activity size={17} /><span>{item}</span>{index === 4 && <em>{alerts.length}</em>}</button>)}<p className="nav-label second">SYSTEM</p><button className="nav-item"><Layers3 size={17} /><span>Settings</span></button></nav>
      <div className="sidebar-bottom"><div className="model-status"><div className="pulse-ring"><BrainCircuit size={18} /></div><div><strong>AI CORE ONLINE</strong><span>v2.4.8 / DEMO MODE</span></div><span className="live-dot" /></div><div className="side-footer">SYSTEM UPTIME <span>14d 07h 22m</span></div></div>
    </aside>
    <main className="main-content">
      <header className="topbar"><button className="icon-button menu-trigger" onClick={() => setMobileMenu(true)} aria-label="Open menu"><Menu size={21} /></button><div className="breadcrumb"><span>COMMAND CENTER</span><ChevronRight size={13} /><b>{activeNav.toUpperCase()}</b></div><div className="top-actions"><div className="search"><Search size={16} /><span>Search events, IPs, techniques...</span></div><button className="icon-button notification" aria-label="Notifications"><Bell size={17} /></button><div className="user-avatar">JS</div></div></header>
      <div className="dashboard-content">
        <section className="welcome-row"><div><p className="eyebrow"><span className="live-dot" /> LIVE INTELLIGENCE FEED / DATA-AWARE</p><h1>Good morning, Jordan <span>〽</span></h1><p className="subcopy">{summary ? `Analyzing ${datasetName} from the uploaded dataset.` : 'Your network is being monitored. AI has identified a developing attack pattern.'}</p></div><div className="welcome-actions"><label className="upload-button"><Upload size={16} /> IMPORT DATASET<input type="file" accept=".csv,.json,.jsonl" onChange={uploadDataset} /></label><button className={`simulate-button ${isSimulating ? 'running' : ''}`} onClick={startSimulation}><Play size={16} fill="currentColor" /> {isSimulating ? 'SIMULATION RUNNING' : 'SIMULATE ATTACK'}</button><small className="upload-status">{datasetName}{uploadMessage && ` / ${uploadMessage}`}</small></div></section>
        <section className="status-grid"><div className="status-card protected"><div className="card-kicker"><span>SECURITY STATUS</span><ShieldCheck size={17} /></div><div className="status-value"><span className="status-check"><Check size={20} /></span><strong>PROTECTED</strong></div><div className="status-meta"><span><i className="live-dot" /> All systems operational</span><span>DATA-AWARE</span></div></div><Metric label="EVENTS PROCESSED" value={eventCount.toLocaleString()} icon={<Activity size={16} />} /><Metric label="THREAT LEVEL" value={risk} icon={<AlertTriangle size={16} />} tone="threat" /><Metric label="AI CONFIDENCE" value={`${confidence}%`} icon={<BrainCircuit size={16} />} tone="confidence" /></section>
        <div className="section-heading"><div><p className="eyebrow">01 / PREDICTIVE ANALYSIS</p><h2>Attack Forecast <span className="demo-pill">DATASET ANALYSIS</span></h2></div></div>
        <section className="forecast-grid"><div className="forecast-panel"><div className="forecast-top"><span className="live-tag"><i className="live-dot" /> FORECAST ACTIVE</span><span className="timestamp">derived from {eventCount.toLocaleString()} rows</span></div><div className="stage-comparison"><div><span className="field-label">CURRENT ATTACK STAGE</span><strong>{currentStage.label}</strong><span className="stage-caption">observed in uploaded data</span></div><div className="forecast-arrow"><ArrowUpRight size={24} /></div><div className="predicted"><span className="field-label">PREDICTED NEXT STAGE</span><strong>{summary?.predicted_next_stage ?? predictedStage.label}</strong><span className="stage-caption"><Sparkles size={13} /> {confidence}% confidence</span></div></div><div className="confidence-line"><div><span>PROBABILITY OF ESCALATION</span><b>{confidence}%</b></div><div className="progress-track"><i style={{ width: `${confidence}%` }} /></div></div></div><div className="risk-panel"><span className="field-label">COMPOSITE RISK SCORE</span><div className="risk-score"><strong>{(threatScore / 10).toFixed(1)}</strong><span>/ 10</span></div><div className="risk-label"><i /> {risk} RISK</div><p>{summary ? `${summary.failed_logins.toLocaleString()} failed login signals found.` : 'Demo mode uses simulated signals.'}</p></div></section>
        <section className="timeline-panel"><div className="timeline-title"><div><p className="eyebrow">ATTACK CHAIN RECONSTRUCTION</p><h3>Live Attack Timeline</h3></div><span className="timeline-state"><i className="live-dot" /> {isSimulating ? 'SIMULATING' : 'MONITORING'}</span></div><div className="timeline">{stages.map((stage, index) => <div className={`timeline-node ${index === stageIndex ? 'current' : ''} ${index === stageIndex + 1 ? 'predicted' : ''} ${index < stageIndex ? 'complete' : ''}`} key={stage.label}><div className="node-point" style={{ '--node-color': stage.color } as React.CSSProperties}>{index < stageIndex ? <Check size={13} /> : index === stageIndex ? <span /> : null}</div><span className="node-label">{stage.label}</span><small>{index < stageIndex ? 'complete' : index === stageIndex ? 'current stage' : index === stageIndex + 1 ? 'AI predicted' : 'pending'}</small>{index < stages.length - 1 && <div className="node-line"><i style={{ width: index < stageIndex ? '100%' : '0%' }} /></div>}</div>)}</div></section>
        <div className="two-col"><section className="panel network-panel"><div className="panel-header"><div><p className="eyebrow">TOPOLOGY / REAL-TIME</p><h3>Network Graph</h3></div><Network size={17} /></div><div className="network-visual"><div className="grid-lines" /><div className="network-link link-one" /><div className="network-link link-two alert-link" /><div className="network-node user-node"><UserRound size={17} /><span>USER</span><small>uploaded source</small></div><div className="network-node laptop-node"><Laptop size={18} /><span>LAPTOP</span><small>{summary?.source_count ?? 4} sources</small></div><div className="network-node server-node"><Server size={18} /><span>SERVER</span><small>analysis-api</small></div><div className="network-node database-node"><Database size={18} /><span>DATASET</span><small>{datasetName === 'No dataset uploaded' ? 'demo-data' : datasetName}</small></div></div></section><section className="panel explain-panel"><div className="panel-header"><div><p className="eyebrow">MODEL TRANSPARENCY / XAI</p><h3>Why this prediction?</h3></div><BrainCircuit size={17} /></div><p className="explain-intro">Feature importance from the uploaded dataset.</p><Feature label="Failed login attempts" value={summary ? Math.min(99, summary.failed_logins) : 92} tone="critical" /><Feature label="Traffic pattern" value={summary ? Math.min(99, Math.round(summary.threat_score * .9)) : 78} tone="high" /><Feature label="Source diversity" value={summary ? Math.min(99, summary.source_count * 10) : 64} tone="medium" /><div className="model-note"><BrainCircuit size={15} /><span>Dataset summary / <b>{summary ? 'analyzed' : 'demo fallback'}</b></span></div></section></div>
        <div className="section-heading lower"><div><p className="eyebrow">02 / BEHAVIORAL TELEMETRY</p><h2>Live Monitoring</h2></div></div><section className="panel chart-panel"><div className="chart-summary"><div><span className="field-label">NETWORK TRAFFIC</span><strong>{traffic.toLocaleString()} <small>units</small></strong></div><div><span className="field-label">ROWS ANALYZED</span><strong>{eventCount.toLocaleString()}</strong></div><div><span className="field-label">ATTACK PROBABILITY</span><strong>{confidence}<small>%</small></strong></div></div><div className="chart-wrap"><ResponsiveContainer width="100%" height={220}><AreaChart data={chartData}><defs><linearGradient id="trafficFill" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stopColor="#26d9e8" stopOpacity={.3} /><stop offset="100%" stopColor="#26d9e8" stopOpacity={0} /></linearGradient><linearGradient id="threatFill" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stopColor="#a884ff" stopOpacity={.25} /><stop offset="100%" stopColor="#a884ff" stopOpacity={0} /></linearGradient></defs><CartesianGrid stroke="#1d2a3b" vertical={false} /><XAxis dataKey="time" axisLine={false} tickLine={false} tick={{ fill: '#64758c', fontSize: 10 }} /><YAxis axisLine={false} tickLine={false} tick={{ fill: '#64758c', fontSize: 10 }} /><Tooltip contentStyle={{ background: '#101827', border: '1px solid #28435a', color: '#edf8ff' }} /><Area type="monotone" dataKey="traffic" stroke="#26d9e8" strokeWidth={2} fill="url(#trafficFill)" /><Area type="monotone" dataKey="threat" stroke="#a884ff" strokeWidth={2} fill="url(#threatFill)" /></AreaChart></ResponsiveContainer></div></section>
        <div className="lower-grid"><section className="panel alerts-panel"><div className="panel-header"><div><p className="eyebrow">REAL-TIME EVENT STREAM</p><h3>Security Alerts <span className="count-pill">{alerts.length}</span></h3></div></div>{alerts.map((alert, index) => <div className="alert-row" key={`${alert.time}-${index}`}><div className={`alert-icon ${alert.color}`}><AlertTriangle size={15} /></div><div className="alert-main"><div><b>{alert.stage}</b><span className={`severity ${alert.color}`}>{alert.severity}</span></div><span>{alert.source} <i /> {alert.time}</span></div><button className="ack-button" onClick={() => setAlerts((items) => items.filter((_, itemIndex) => itemIndex !== index))} aria-label="Acknowledge alert"><Check size={14} /></button></div>)}</section><section className="panel mitre-panel"><div className="panel-header"><div><p className="eyebrow">TACTICAL MAPPING</p><h3>MITRE ATT&CK</h3></div><GitBranch size={17} /></div><div className="technique-card"><div className="technique-id">T1068</div><div><b>Privilege Escalation</b><span>Derived from forecast stage</span></div></div><div className="technique-card"><div className="technique-id">T1078</div><div><b>Valid Accounts</b><span>Behavioral correlation</span></div></div></section></div>
        <footer><span><LockKeyhole size={13} /> END-TO-END ENCRYPTED TELEMETRY</span><span>{summary ? 'UPLOADED DATASET / ANALYZED' : 'DEMO DATASET / PREDICTIONS ARE SIMULATED'}</span><b>PREDICT. EXPLAIN. PREVENT.</b></footer>
      </div>
    </main>
  </div>
}

function Metric({ label, value, icon, tone = '' }: { label: string; value: string; icon: React.ReactNode; tone?: string }) {
  return <div className={`metric-card ${tone}`}><div className="card-kicker"><span>{label}</span>{icon}</div><strong className="metric-value">{value}</strong><span className="metric-change up">Dataset-derived</span></div>
}
function Feature({ label, value, tone }: { label: string; value: number; tone: string }) {
  return <div className="feature"><div><span>{label}</span><b>{value}%</b></div><div className="feature-track"><i className={tone} style={{ width: `${value}%` }} /></div></div>
}
export default App
