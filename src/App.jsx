import React, { useState, useEffect, useRef } from 'react';
import {
  Chart as ChartJS,
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  BarElement,
  ArcElement,
  RadialLinearScale,
  Title,
  Tooltip,
  Legend,
  Filler
} from 'chart.js';
import { Line, Doughnut, Bar, PolarArea } from 'react-chartjs-2';
import * as nids from './services/nidsService';

// Register Chart.js components
ChartJS.register(
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  BarElement,
  ArcElement,
  RadialLinearScale,
  Title,
  Tooltip,
  Legend,
  Filler
);

function App() {
  const [activeUser, setActiveUser] = useState(null);
  const [activeTab, setActiveTab] = useState('dashboard');
  const [monitoringActive, setMonitoringActive] = useState(false);
  const [simulationMode, setSimulationMode] = useState(true);
  const [packets, setPackets] = useState([]);
  const [alerts, setAlerts] = useState([]);
  const [thresholds, setThresholds] = useState({});
  const [toast, setToast] = useState(null);
  const [clockStr, setClockStr] = useState('');

  const captureTimerRef = useRef(null);
  const toastTimeoutRef = useRef(null);

  // Initialize DB and state
  useEffect(() => {
    nids.initDatabase();
    setActiveUser(nids.getActiveUser());
    setPackets(nids.getPackets());
    setAlerts(nids.getAlerts());
    setThresholds(nids.getSettings());

    // UTC System Clock
    const timer = setInterval(() => {
      const now = new Date();
      setClockStr(now.toISOString().replace('T', ' ').substring(0, 19) + ' UTC');
    }, 1000);

    return () => clearInterval(timer);
  }, []);

  // Show toast notification
  const showNotification = (message, type = 'info') => {
    if (toastTimeoutRef.current) clearTimeout(toastTimeoutRef.current);
    setToast({ message, type });
    toastTimeoutRef.current = setTimeout(() => setToast(null), 6000);
  };

  const activeRef = useRef(monitoringActive);
  useEffect(() => {
    activeRef.current = monitoringActive;
  }, [monitoringActive]);

  // Sniffing background simulation loop (Standard, leak-proof interval hook)
  useEffect(() => {
    if (!monitoringActive) return;

    // Loop that simulates packet arrivals every 1200ms
    const intervalId = setInterval(() => {
      if (!activeRef.current) {
        clearInterval(intervalId);
        return;
      }
      const isAttack = Math.random() > 0.82; // 18% chance of attack burst on each tick
      let newPackets = [];

      if (isAttack) {
        const patterns = [
          'Port Scanning', 'SYN Flood', 'Ping Flood', 'Brute Force', 
          'SQL Injection', 'Cross-Site Scripting', 'ARP Poisoning', 
          'DNS Spoofing', 'MITM Redirect', 'Botnet C2 Callout', 
          'Smurf Attack', 'Buffer Overflow', 'DoS'
        ];
        const pattern = patterns[Math.floor(Math.random() * patterns.length)];
        const attackerIp = ['185.220.101.5', '45.133.1.20', '198.51.100.42'][Math.floor(Math.random() * 3)];
        
        // Generate a burst of 18-25 packets spanning a short duration
        const burstSize = 18 + Math.floor(Math.random() * 8);
        const now = new Date();
        for (let i = 0; i < burstSize; i++) {
          const p = nids.generateSimulatedPacket(pattern);
          p.src_ip = attackerIp;
          p.timestamp = new Date(now.getTime() - i * 35).toISOString(); // Offset slightly
          newPackets.push(p);
        }
      } else {
        newPackets.push(nids.generateSimulatedPacket('Normal'));
      }

      // Load latest state histories
      const currentPackets = JSON.parse(localStorage.getItem('nids_packets') || '[]');
      const updatedPackets = [...newPackets, ...currentPackets].slice(0, 200);
      localStorage.setItem('nids_packets', JSON.stringify(updatedPackets));
      setPackets(updatedPackets);

      // Evaluate heuristic rules for the first packet in the list (the trigger)
      const triggerPacket = newPackets[0];
      const ruleResult = nids.processDetectionRules(triggerPacket, updatedPackets);
      
      if (ruleResult.triggered) {
        const currentAlerts = JSON.parse(localStorage.getItem('nids_alerts') || '[]');
        
        // Check if this type of alert from this IP was already triggered in the last 6 seconds
        const sixSecAgo = new Date(new Date().getTime() - 6000);
        const duplicate = currentAlerts.find(a => 
          a.src_ip === triggerPacket.src_ip && 
          a.attack_type === ruleResult.attack_type && 
          new Date(a.timestamp) >= sixSecAgo
        );

        if (!duplicate) {
          const nextId = currentAlerts.length > 0 ? Math.max(...currentAlerts.map(a => a.id)) + 1 : 1;
          const newAlert = {
            id: nextId,
            timestamp: new Date().toISOString(),
            src_ip: triggerPacket.src_ip,
            dst_ip: triggerPacket.dst_ip,
            attack_type: ruleResult.attack_type,
            severity: ruleResult.severity,
            confidence: ruleResult.confidence,
            status: 'Active'
          };

          const updatedAlerts = [newAlert, ...currentAlerts];
          localStorage.setItem('nids_alerts', JSON.stringify(updatedAlerts));
          setAlerts(updatedAlerts.filter(a => a.status !== 'Deleted'));
          
          showNotification(`[ALERT] ${ruleResult.attack_type} detected from ${triggerPacket.src_ip}!`, 'danger');
        }
      }
    }, 1200);

    return () => {
      clearInterval(intervalId);
    };
  }, [monitoringActive]);

  // Auth Handlers
  const handleLogin = (username, password) => {
    const users = nids.getUsers();
    const match = users.find(u => u.username === username && u.password === password);
    if (match) {
      nids.setActiveUser(match);
      setActiveUser(match);
      setActiveTab('dashboard');
      showNotification(`Welcome back, ${match.username}!`, 'success');
      return true;
    } else {
      showNotification("Invalid username or password credentials.", "danger");
      return false;
    }
  };

  const handleLogout = () => {
    nids.setActiveUser(null);
    setActiveUser(null);
    setMonitoringActive(false);
    showNotification("Logged out successfully.", "info");
  };

  const handleClearLogs = () => {
    if (window.confirm("Are you sure you want to permanently delete all network alerts, packet logs, and threat actor profiles? This resets all dashboard metrics to zero.")) {
      nids.clearAllLogs();
      setPackets([]);
      setAlerts([]);
      showNotification("All database logs and alerts cleared successfully.", "warning");
    }
  };

  if (!activeUser) {
    return <LoginView onLogin={handleLogin} toast={toast} onCloseToast={() => setToast(null)} />;
  }

  return (
    <div>
      {/* Top Navbar Header */}
      <nav className="navbar navbar-expand-lg navbar-light bg-white border-bottom shadow-sm py-2">
        <div className="container-fluid px-4">
          <button className="navbar-brand fw-extrabold text-dark border-0 bg-transparent d-flex align-items-center me-4" onClick={() => setActiveTab('dashboard')}>
            <i className="fa-solid fa-shield-halved text-primary me-2"></i>AI-NIDS
          </button>
          
          <button className="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarContent">
            <span className="navbar-toggler-icon"></span>
          </button>
          
          <div className="collapse navbar-collapse" id="navbarContent">
            <ul className="navbar-nav me-auto mb-2 mb-lg-0 gap-1">
              <li className="nav-item">
                <button className={`nav-link border-0 bg-transparent d-flex align-items-center ${activeTab === 'dashboard' ? 'active' : ''}`} onClick={() => setActiveTab('dashboard')}>
                  <i className="fa-solid fa-chart-line me-2"></i>Dashboard
                </button>
              </li>
              <li className="nav-item">
                <button className={`nav-link border-0 bg-transparent d-flex align-items-center ${activeTab === 'monitor' ? 'active' : ''}`} onClick={() => setActiveTab('monitor')}>
                  <i className="fa-solid fa-ethernet me-2"></i>Monitor
                </button>
              </li>
              <li className="nav-item">
                <button className={`nav-link border-0 bg-transparent d-flex align-items-center ${activeTab === 'threats' ? 'active' : ''}`} onClick={() => setActiveTab('threats')}>
                  <i className="fa-solid fa-brain me-2"></i>AI Engine
                </button>
              </li>
              <li className="nav-item">
                <button className={`nav-link border-0 bg-transparent d-flex align-items-center ${activeTab === 'alerts' ? 'active' : ''}`} onClick={() => setActiveTab('alerts')}>
                  <i className="fa-solid fa-triangle-exclamation me-2"></i>Alerts
                </button>
              </li>
              <li className="nav-item">
                <button className={`nav-link border-0 bg-transparent d-flex align-items-center ${activeTab === 'settings' ? 'active' : ''}`} onClick={() => setActiveTab('settings')}>
                  <i className="fa-solid fa-sliders me-2"></i>Thresholds
                </button>
              </li>
              <li className="nav-item">
                <button className={`nav-link border-0 bg-transparent d-flex align-items-center ${activeTab === 'profile' ? 'active' : ''}`} onClick={() => setActiveTab('profile')}>
                  <i className="fa-solid fa-user-shield me-2"></i>Profile
                </button>
              </li>
              <li className="nav-item">
                <button className={`nav-link border-0 bg-transparent d-flex align-items-center ${activeTab === 'knowledge' ? 'active' : ''}`} onClick={() => setActiveTab('knowledge')}>
                  <i className="fa-solid fa-book-open me-2"></i>Attack Knowledge
                </button>
              </li>
              {activeUser.role === 'Admin' && (
                <li className="nav-item">
                  <button className={`nav-link border-0 bg-transparent d-flex align-items-center ${activeTab === 'admin' ? 'active' : ''}`} onClick={() => setActiveTab('admin')}>
                    <i className="fa-solid fa-user-gear me-2"></i>Admin
                  </button>
                </li>
              )}
            </ul>
            
            {/* Toggle controls and profile pic */}
            <div className="d-flex align-items-center gap-3 pe-3">
              <button 
                id="toggle-sniff-btn" 
                className={`btn btn-sm d-flex align-items-center fw-bold py-1 px-3 ${monitoringActive ? 'btn-outline-danger' : 'btn-outline-primary'}`}
                onClick={() => {
                  setMonitoringActive(!monitoringActive);
                  showNotification(monitoringActive ? "Capture daemon suspended." : "Capture daemon launched.", monitoringActive ? "warning" : "success");
                }}
              >
                <i className={`fa-solid me-1 ${monitoringActive ? 'fa-stop' : 'fa-play'}`}></i>
                {monitoringActive ? 'Stop Sniffing' : 'Start Sniffing'}
              </button>
              
              <div className="d-flex align-items-center me-2">
                <div className="text-end me-2" style={{ lineHeight: '1.2' }}>
                  <div className="fw-bold text-dark" style={{ fontSize: '13px' }}>{activeUser.username}</div>
                  <small className="text-muted" style={{ fontSize: '10px' }}>{activeUser.role}</small>
                </div>
                <img 
                  src={`https://api.dicebear.com/7.x/bottts/svg?seed=${activeUser.username}`} 
                  alt="Profile" width="36" height="36" className="rounded-circle border border-primary" 
                />
              </div>
              
              <button onClick={handleLogout} className="btn btn-sm btn-outline-danger d-flex align-items-center gap-2 py-1 px-3 fw-bold" title="Sign Out">
                <i className="fa-solid fa-right-from-bracket"></i>
                <span className="d-none d-md-inline" style={{ fontSize: '12px' }}>Sign Out</span>
              </button>
            </div>
          </div>
        </div>
      </nav>

      {/* Main Content Area */}
      <div className="main-content">
        <div className="container-fluid mb-4 d-flex justify-content-between align-items-center px-0 flex-wrap gap-2">
          <div>
            <h2 className="fw-bold text-dark mb-0">
              {activeTab === 'dashboard' && 'Security Operations Center Dashboard'}
              {activeTab === 'monitor' && 'Raw Network Packet Monitor'}
              {activeTab === 'threats' && 'AI Intrusion Detection Classification'}
              {activeTab === 'alerts' && 'Threat Registry & Mitigation Panel'}
              {activeTab === 'settings' && 'Rule Threshold Matrix Configurator'}
              {activeTab === 'profile' && 'Operator Security Clearance Credentials'}
              {activeTab === 'knowledge' && 'Network Intrusion Attack Knowledge Base'}
              {activeTab === 'admin' && 'SOC Console Account Management'}
            </h2>
            <small className="text-muted">{clockStr}</small>
          </div>
          
          {/* Status Metrics widget */}
          <div className="d-flex align-items-center bg-white border rounded px-3 py-2 shadow-sm" style={{ fontSize: '13px', gap: '15px' }}>
            <div className="d-flex align-items-center">
              <span className={`status-indicator me-2 ${monitoringActive ? 'status-active' : 'status-inactive'}`}></span>
              <span className="text-muted fw-semibold">Engine: {monitoringActive ? 'Active' : 'Off'}</span>
            </div>
            <div className="vr" style={{ height: '15px', color: 'var(--border-color)' }}></div>
            <div className="d-flex align-items-center text-muted fw-semibold">
              <i className="fa-solid fa-microchip me-2 text-primary"></i>
              <span>Mode: {simulationMode ? 'Simulated' : 'Raw Capture'}</span>
            </div>
          </div>
        </div>

        {/* Dynamic Views */}
        {activeTab === 'dashboard' && <DashboardView packets={packets} alerts={alerts} onClearLogs={handleClearLogs} onNavigate={setActiveTab} />}
        {activeTab === 'monitor' && <MonitorView packets={packets} />}
        {activeTab === 'threats' && <AIEngineView />}
        {activeTab === 'alerts' && <AlertsView alerts={alerts} setAlerts={setAlerts} onClearLogs={handleClearLogs} showNotification={showNotification} />}
        {activeTab === 'settings' && <SettingsView thresholds={thresholds} setThresholds={setThresholds} showNotification={showNotification} />}
        {activeTab === 'profile' && <ProfileView activeUser={activeUser} setActiveUser={setActiveUser} showNotification={showNotification} />}
        {activeTab === 'knowledge' && <AttackKnowledgeView />}
        {activeTab === 'admin' && <AdminView showNotification={showNotification} />}
      </div>

      {/* Floating Notifications Toast */}
      {toast && (
        <div className="toast-container position-fixed bottom-0 end-0 p-3" style={{ zIndex: 1055 }}>
          <div 
            className="toast align-items-center border-0 shadow-lg show" 
            style={{ 
              display: 'block', 
              backgroundColor: '#ffffff', 
              color: 'var(--text-main)', 
              borderLeft: `5px solid ${toast.type === 'danger' ? 'var(--sev-critical)' : toast.type === 'success' ? 'var(--sev-low)' : 'var(--primary)'}` 
            }}
          >
            <div className="d-flex">
              <div className="toast-body">
                <i className={`fa-solid me-2 ${toast.type === 'danger' ? 'fa-radiation text-danger' : toast.type === 'success' ? 'fa-circle-check text-success' : 'fa-bell text-primary'}`}></i>
                <span>{toast.message}</span>
              </div>
              <button type="button" className="btn-close me-2 m-auto" onClick={() => setToast(null)}></button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

// ----------------------------------------------------
// 1. LOGIN VIEW
// ----------------------------------------------------
function LoginView({ onLogin, toast, onCloseToast }) {
  const [username, setUsername] = useState('admin');
  const [password, setPassword] = useState('password123');

  const handleSubmit = (e) => {
    e.preventDefault();
    onLogin(username, password);
  };

  return (
    <div className="login-body">
      <div className="login-box">
        <div className="text-center mb-4">
          <i className="fa-solid fa-shield-halved text-primary fa-3x mb-3"></i>
          <h3 className="fw-bold text-dark mb-1">AI-NIDS Log In</h3>
          <p className="text-muted small">Access the Enterprise Threat Protection Suite</p>
        </div>
        <form onSubmit={handleSubmit}>
          <div className="mb-3">
            <label className="form-label text-muted small fw-semibold">Clearance Username</label>
            <div className="input-group">
              <span className="input-group-text bg-light border-end-0 text-muted"><i className="fa-solid fa-user"></i></span>
              <input 
                type="text" 
                className="form-control form-cyber border-start-0" 
                value={username} 
                onChange={(e) => setUsername(e.target.value)} 
                required 
              />
            </div>
          </div>
          <div className="mb-4">
            <label className="form-label text-muted small fw-semibold">Clearance Passcode</label>
            <div className="input-group">
              <span className="input-group-text bg-light border-end-0 text-muted"><i className="fa-solid fa-lock"></i></span>
              <input 
                type="password" 
                className="form-control form-cyber border-start-0" 
                value={password} 
                onChange={(e) => setPassword(e.target.value)} 
                required 
              />
            </div>
          </div>
          <button type="submit" className="btn btn-cyber w-100 py-2 fw-bold">
            <i className="fa-solid fa-right-to-bracket me-2"></i>Authenticate Security Clearance
          </button>
        </form>
        <div className="mt-4 p-3 bg-light rounded text-muted" style={{ fontSize: '11px' }}>
          <div>Default Admin: <code>admin</code> / <code>password123</code></div>
          <div className="mt-1">Default Analyst: <code>analyst</code> / <code>password123</code></div>
        </div>
      </div>
      
      {toast && (
        <div className="toast-container position-fixed bottom-0 end-0 p-3">
          <div className="toast align-items-center border-0 shadow-lg show" style={{ display: 'block', backgroundColor: '#ffffff', borderLeft: '5px solid var(--sev-critical)' }}>
            <div className="d-flex">
              <div className="toast-body">
                <i className="fa-solid fa-radiation text-danger me-2"></i>
                <span>{toast.message}</span>
              </div>
              <button type="button" className="btn-close me-2 m-auto" onClick={onCloseToast}></button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

// ----------------------------------------------------
// 2. DASHBOARD VIEW
// ----------------------------------------------------
function DashboardView({ packets, alerts, onClearLogs, onNavigate }) {
  const totalPackets = packets.length;
  const maliciousPackets = packets.filter(p => {
    const pred = nids.predictPacket(p);
    return pred.is_malicious;
  }).length;
  const normalPackets = totalPackets - maliciousPackets;

  const todayStart = new Date().setHours(0, 0, 0, 0);
  const todayAlerts = alerts.filter(a => new Date(a.timestamp) >= todayStart).length;
  const activeThreats = alerts.filter(a => a.status === 'Active').length;
  const accuracy = "99.85%";

  // Protocol Distribution counts
  const protoCounts = packets.reduce((acc, p) => {
    acc[p.protocol] = (acc[p.protocol] || 0) + 1;
    return acc;
  }, { TCP: 0, UDP: 0, ICMP: 0 });

  // Attack Vectors counts
  const vectorCounts = alerts.reduce((acc, a) => {
    acc[a.attack_type] = (acc[a.attack_type] || 0) + 1;
    return acc;
  }, {});

  // Top Source IPs counts
  const ipCounts = alerts.reduce((acc, a) => {
    acc[a.src_ip] = (acc[a.src_ip] || 0) + 1;
    return acc;
  }, {});
  const sortedIps = Object.entries(ipCounts).sort((a, b) => b[1] - a[1]).slice(0, 5);

  // Group alerts by minute for the timeline chart (last 6 minutes)
  const timelineLabels = [];
  const timelineCounts = [];
  for (let i = 5; i >= 0; i--) {
    const d = new Date();
    d.setMinutes(d.getMinutes() - i);
    const label = d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    timelineLabels.push(label);
    
    // Count alerts that occurred in this minute
    const count = alerts.filter(a => {
      const alertTime = new Date(a.timestamp);
      return alertTime.getHours() === d.getHours() && alertTime.getMinutes() === d.getMinutes();
    }).length;
    timelineCounts.push(count);
  }

  // Charts Configs
  const timelineData = {
    labels: timelineLabels,
    datasets: [{
      label: 'Triggered Threats',
      data: timelineCounts,
      borderColor: '#0284c7',
      backgroundColor: 'rgba(2, 132, 199, 0.1)',
      borderWidth: 2,
      fill: true,
      tension: 0.3
    }]
  };

  const attackDistData = {
    labels: Object.keys(vectorCounts).length > 0 ? Object.keys(vectorCounts) : ['No Threat'],
    datasets: [{
      data: Object.values(vectorCounts).length > 0 ? Object.values(vectorCounts) : [1],
      backgroundColor: ['#dc2626', '#ea580c', '#d97706', '#4f46e5', '#a855f7', '#0284c7', '#cbd5e1'],
      borderWidth: 1
    }]
  };

  const protoData = {
    labels: Object.keys(protoCounts),
    datasets: [{
      data: Object.values(protoCounts),
      backgroundColor: ['rgba(2, 132, 199, 0.6)', 'rgba(79, 70, 229, 0.6)', 'rgba(16, 185, 129, 0.6)'],
      borderWidth: 1
    }]
  };

  const topIpsData = {
    labels: sortedIps.length > 0 ? sortedIps.map(x => x[0]) : ['No Threat'],
    datasets: [{
      label: 'Alerts count',
      data: sortedIps.length > 0 ? sortedIps.map(x => x[1]) : [0],
      backgroundColor: 'rgba(234, 88, 12, 0.7)',
      borderColor: '#ea580c',
      borderWidth: 1
    }]
  };

  return (
    <div>
      {/* Metrics Cards Grid */}
      <div className="row g-3 mb-4">
        <div className="col-md-6 col-lg-2">
          <div className="metric-card">
            <div className="d-flex justify-content-between align-items-center mb-2">
              <span className="text-muted small fw-bold text-uppercase">Total Packets</span>
              <div className="icon-wrapper"><i className="fa-solid fa-network-wired"></i></div>
            </div>
            <h3 className="fw-extrabold mb-0">{totalPackets.toLocaleString()}</h3>
          </div>
        </div>
        <div className="col-md-6 col-lg-2">
          <div className="metric-card success">
            <div className="d-flex justify-content-between align-items-center mb-2">
              <span className="text-muted small fw-bold text-uppercase">Normal Ingress</span>
              <div className="icon-wrapper"><i className="fa-solid fa-shield-halved"></i></div>
            </div>
            <h3 className="fw-extrabold mb-0">{normalPackets.toLocaleString()}</h3>
          </div>
        </div>
        <div className="col-md-6 col-lg-2">
          <div className="metric-card critical">
            <div className="d-flex justify-content-between align-items-center mb-2">
              <span className="text-muted small fw-bold text-uppercase">Malicious Injected</span>
              <div className="icon-wrapper"><i className="fa-solid fa-circle-exclamation"></i></div>
            </div>
            <h3 className="fw-extrabold mb-0 text-danger">{maliciousPackets.toLocaleString()}</h3>
          </div>
        </div>
        <div className="col-md-6 col-lg-2">
          <div className="metric-card critical">
            <div className="d-flex justify-content-between align-items-center mb-2">
              <span className="text-muted small fw-bold text-uppercase">Active Threats</span>
              <div className="icon-wrapper"><i className="fa-solid fa-triangle-exclamation"></i></div>
            </div>
            <h3 className="fw-extrabold mb-0 text-danger">{activeThreats}</h3>
          </div>
        </div>
        <div className="col-md-6 col-lg-2">
          <div className="metric-card warning">
            <div className="d-flex justify-content-between align-items-center mb-2">
              <span className="text-muted small fw-bold text-uppercase">Alerts Today</span>
              <div className="icon-wrapper"><i className="fa-solid fa-clock"></i></div>
            </div>
            <h3 className="fw-extrabold mb-0 text-warning">{todayAlerts}</h3>
          </div>
        </div>
        <div className="col-md-6 col-lg-2">
          <div className="metric-card">
            <div className="d-flex justify-content-between align-items-center mb-2">
              <span className="text-muted small fw-bold text-uppercase">AI Precision</span>
              <div className="icon-wrapper"><i className="fa-solid fa-brain"></i></div>
            </div>
            <h3 className="fw-extrabold mb-0">{accuracy}</h3>
          </div>
        </div>
      </div>

      {/* Charts Grid */}
      <div className="row g-4 mb-4">
        <div className="col-md-12 col-lg-8">
          <div className="card-cyber p-4">
            <h6 className="border-bottom pb-2 mb-3 fw-bold text-muted">
              <i className="fa-solid fa-chart-area me-2 text-primary"></i>Ingress Intrusion Attack Vectors Timeline
            </h6>
            <div style={{ height: '220px' }}><Line data={timelineData} options={{ responsive: true, maintainAspectRatio: false }} /></div>
          </div>
        </div>
        <div className="col-md-12 col-lg-4">
          <div className="card-cyber p-4">
            <h6 className="border-bottom pb-2 mb-3 fw-bold text-muted">
              <i className="fa-solid fa-chart-pie me-2 text-primary"></i>Attack Vector Classification
            </h6>
            <div style={{ height: '220px' }}><Doughnut data={attackDistData} options={{ responsive: true, maintainAspectRatio: false }} /></div>
          </div>
        </div>
      </div>

      <div className="row g-4 mb-4">
        <div className="col-md-6 col-lg-4">
          <div className="card-cyber p-4">
            <h6 className="border-bottom pb-2 mb-3 fw-bold text-muted">
              <i className="fa-solid fa-list-check me-2 text-primary"></i>Top Attack Source IPs
            </h6>
            <div style={{ height: '200px' }}><Bar data={topIpsData} options={{ indexAxis: 'y', responsive: true, maintainAspectRatio: false, plugins: { legend: { display: false } } }} /></div>
          </div>
        </div>
        <div className="col-md-6 col-lg-4">
          <div className="card-cyber p-4">
            <h6 className="border-bottom pb-2 mb-3 fw-bold text-muted">
              <i className="fa-solid fa-circle-nodes me-2 text-primary"></i>Protocol Distribution
            </h6>
            <div style={{ height: '200px' }}><PolarArea data={protoData} options={{ responsive: true, maintainAspectRatio: false }} /></div>
          </div>
        </div>
        <div className="col-md-12 col-lg-4">
          <div className="card-cyber p-4 h-100">
            <h6 className="border-bottom pb-2 mb-3 fw-bold text-muted"><i className="fa-solid fa-shield-halved me-2 text-primary"></i>System Engine Diagnostics</h6>
            <div className="small text-muted py-2">
              <div className="d-flex justify-content-between mb-2"><span>Heuristic Processing:</span><span className="text-success fw-bold">Active</span></div>
              <div className="d-flex justify-content-between mb-2"><span>Random Forest Core:</span><span className="text-success fw-bold">Online</span></div>
              <div className="d-flex justify-content-between mb-2"><span>SQLite Database Thread:</span><span className="text-success fw-bold">localStorage Emulator</span></div>
              <div className="d-flex justify-content-between mb-2"><span>Capture Provider:</span><span className="text-muted">Javascript Timer Interval</span></div>
              <div className="d-flex justify-content-between"><span>Pipeline Accuracy:</span><span className="text-primary fw-bold">99.85%</span></div>
            </div>
          </div>
        </div>
      </div>

      {/* Recent Activity Table */}
      <div className="row mb-4">
        <div className="col-12">
          <div className="card-cyber p-4">
            <div className="d-flex justify-content-between align-items-center mb-3 flex-wrap gap-2">
              <h5 className="mb-0 text-dark fw-bold"><i className="fa-solid fa-shield-cat me-2 text-primary"></i>Recent Security Activity log</h5>
              <div className="d-flex gap-2">
                <button id="clear-all-alerts-btn" onClick={onClearLogs} className="btn btn-sm btn-outline-danger"><i className="fa-solid fa-trash-can me-1"></i>Clear All Logs</button>
                <button className="btn btn-sm btn-cyber" onClick={() => onNavigate('alerts')}><i className="fa-solid fa-magnifying-glass-chart me-1"></i>Open Alert Center</button>
              </div>
            </div>
            <div className="table-responsive">
              <table className="table table-hover align-middle mb-0" style={{ fontSize: '13px' }}>
                <thead>
                  <tr className="border-bottom text-muted">
                    <th>Alert ID</th>
                    <th>Timestamp (UTC)</th>
                    <th>Source IP</th>
                    <th>Destination IP</th>
                    <th>Attack Vectors</th>
                    <th>Severity</th>
                    <th>Confidence</th>
                    <th className="text-end">Status</th>
                  </tr>
                </thead>
                <tbody>
                  {alerts.length === 0 ? (
                    <tr>
                      <td colSpan="8" className="text-center py-4 text-muted">No active threats logged recently.</td>
                    </tr>
                  ) : (
                    alerts.slice(0, 5).map(a => (
                      <tr key={a.id}>
                        <td className="fw-semibold text-primary">#{a.id}</td>
                        <td className="text-muted">{new Date(a.timestamp).toISOString().replace('T', ' ').substring(0, 19)}</td>
                        <td className="font-monospace">{a.src_ip}</td>
                        <td className="font-monospace">{a.dst_ip}</td>
                        <td>
                          <i className="fa-solid fa-triangle-exclamation text-warning me-1"></i>
                          <span className="fw-bold">{a.attack_type}</span>
                        </td>
                        <td>
                          <span className={`badge-sev ${a.severity === 'Critical' ? 'badge-critical' : a.severity === 'High' ? 'badge-high' : a.severity === 'Medium' ? 'badge-medium' : 'badge-low'}`}>
                            {a.severity}
                          </span>
                        </td>
                        <td>{(a.confidence * 100).toFixed(0)}%</td>
                        <td className="text-end">
                          <span className={`badge ${a.status === 'Resolved' ? 'bg-success-subtle text-success border border-success' : 'bg-danger-subtle text-danger border border-danger'}`}>
                            {a.status}
                          </span>
                        </td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

// ----------------------------------------------------
// 3. PACKET MONITOR VIEW
// ----------------------------------------------------
function MonitorView({ packets }) {
  return (
    <div className="card-cyber p-4">
      <div className="d-flex justify-content-between align-items-center mb-3">
        <h6 className="mb-0 text-primary fw-bold"><i className="fa-solid fa-list me-2"></i>Live Ingested Packets Feed</h6>
        <span className="text-muted small">Showing last 50 packets</span>
      </div>
      <div className="table-responsive" style={{ maxHeight: '550px', overflowY: 'auto' }}>
        <table className="table table-hover align-middle mb-0" style={{ fontSize: '13px' }}>
          <thead>
            <tr className="text-muted border-bottom">
              <th>Timestamp</th>
              <th>Protocol</th>
              <th>Source IP</th>
              <th>Src Port</th>
              <th>Destination IP</th>
              <th>Dst Port</th>
              <th>Size (B)</th>
              <th>Flags</th>
              <th className="text-end">Classification</th>
            </tr>
          </thead>
          <tbody>
            {packets.length === 0 ? (
              <tr>
                <td colSpan="9" className="text-center py-4 text-muted">No packets capture data available. Click "Start Sniffing" to begin.</td>
              </tr>
            ) : (
              packets.slice(0, 50).map((p, idx) => {
                const pred = nids.predictPacket(p);
                return (
                  <tr key={idx} className={pred.is_malicious ? 'packet-row malicious' : 'packet-row'}>
                    <td className="text-muted">{new Date(p.timestamp).toLocaleTimeString()}</td>
                    <td className="fw-bold">{p.protocol}</td>
                    <td className="font-monospace">{p.src_ip}</td>
                    <td>{p.src_port}</td>
                    <td className="font-monospace">{p.dst_ip}</td>
                    <td className="fw-semibold">{p.dst_port}</td>
                    <td>{p.size}</td>
                    <td className="font-monospace text-muted">{p.flags || '-'}</td>
                    <td className="text-end">
                      <span className={`badge ${pred.is_malicious ? 'bg-danger-subtle text-danger border border-danger' : 'bg-success-subtle text-success border border-success'}`}>
                        {pred.is_malicious ? `${pred.attack_type} (${(pred.confidence * 100).toFixed(0)}%)` : 'Normal'}
                      </span>
                    </td>
                  </tr>
                );
              })
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}

// ----------------------------------------------------
// 4. AI ENGINE VIEW
// ----------------------------------------------------
function AIEngineView() {
  const [inputs, setInputs] = useState({
    Source_Port: 49152,
    Destination_Port: 80,
    Protocol: 'TCP',
    Flow_Duration: 1000,
    Total_Fwd_Packets: 10,
    Total_Backward_Packets: 8,
    Total_Length_of_Fwd_Packets: 1500,
    Fwd_Packet_Length_Max: 120,
    Bwd_Packet_Length_Max: 1500,
    Flow_Bytes_s: 2500,
    Flow_Packets_s: 18
  });
  const [result, setResult] = useState(null);

  const handlePredict = (e) => {
    e.preventDefault();
    const pred = nids.predictPacket(inputs);
    setResult(pred);
  };

  return (
    <div className="row g-4">
      <div className="col-md-6 col-lg-7">
        <div className="card-cyber p-4">
          <h6 className="border-bottom pb-2 mb-3 fw-bold text-muted">
            <i className="fa-solid fa-sliders me-2 text-primary"></i>Manually Inject Packet Features
          </h6>
          <form onSubmit={handlePredict}>
            <div className="row g-3">
              <div className="col-md-4">
                <label className="form-label text-muted small">Source Port</label>
                <input type="number" className="form-control form-cyber py-1 px-2" value={inputs.Source_Port} onChange={e => setInputs({ ...inputs, Source_Port: parseInt(e.target.value) || 0 })} required />
              </div>
              <div className="col-md-4">
                <label className="form-label text-muted small">Destination Port</label>
                <input type="number" className="form-control form-cyber py-1 px-2" value={inputs.Destination_Port} onChange={e => setInputs({ ...inputs, Destination_Port: parseInt(e.target.value) || 0 })} required />
              </div>
              <div className="col-md-4">
                <label className="form-label text-muted small">Protocol</label>
                <select className="form-select form-cyber py-1 px-2" value={inputs.Protocol} onChange={e => setInputs({ ...inputs, Protocol: e.target.value })} required>
                  <option value="TCP">TCP</option>
                  <option value="UDP">UDP</option>
                  <option value="ICMP">ICMP</option>
                </select>
              </div>
              <div className="col-md-4">
                <label className="form-label text-muted small">Flow Duration (μs)</label>
                <input type="number" className="form-control form-cyber py-1 px-2" value={inputs.Flow_Duration} onChange={e => setInputs({ ...inputs, Flow_Duration: parseInt(e.target.value) || 0 })} required />
              </div>
              <div className="col-md-4">
                <label className="form-label text-muted small">Total Forward Packets</label>
                <input type="number" className="form-control form-cyber py-1 px-2" value={inputs.Total_Fwd_Packets} onChange={e => setInputs({ ...inputs, Total_Fwd_Packets: parseInt(e.target.value) || 0 })} required />
              </div>
              <div className="col-md-4">
                <label className="form-label text-muted small">Total Backward Packets</label>
                <input type="number" className="form-control form-cyber py-1 px-2" value={inputs.Total_Backward_Packets} onChange={e => setInputs({ ...inputs, Total_Backward_Packets: parseInt(e.target.value) || 0 })} required />
              </div>
              <div className="col-md-4">
                <label className="form-label text-muted small">Total Fwd Packets Length</label>
                <input type="number" className="form-control form-cyber py-1 px-2" value={inputs.Total_Length_of_Fwd_Packets} onChange={e => setInputs({ ...inputs, Total_Length_of_Fwd_Packets: parseInt(e.target.value) || 0 })} required />
              </div>
              <div className="col-md-4">
                <label className="form-label text-muted small">Fwd Packet Length Max</label>
                <input type="number" className="form-control form-cyber py-1 px-2" value={inputs.Fwd_Packet_Length_Max} onChange={e => setInputs({ ...inputs, Fwd_Packet_Length_Max: parseInt(e.target.value) || 0 })} required />
              </div>
              <div className="col-md-4">
                <label className="form-label text-muted small">Bwd Packet Length Max</label>
                <input type="number" className="form-control form-cyber py-1 px-2" value={inputs.Bwd_Packet_Length_Max} onChange={e => setInputs({ ...inputs, Bwd_Packet_Length_Max: parseInt(e.target.value) || 0 })} required />
              </div>
              <div className="col-md-6">
                <label className="form-label text-muted small">Flow Bytes per Sec</label>
                <input type="number" step="any" className="form-control form-cyber py-1 px-2" value={inputs.Flow_Bytes_s} onChange={e => setInputs({ ...inputs, Flow_Bytes_s: parseFloat(e.target.value) || 0 })} required />
              </div>
              <div className="col-md-6">
                <label className="form-label text-muted small">Flow Packets per Sec</label>
                <input type="number" step="any" className="form-control form-cyber py-1 px-2" value={inputs.Flow_Packets_s} onChange={e => setInputs({ ...inputs, Flow_Packets_s: parseFloat(e.target.value) || 0 })} required />
              </div>
            </div>
            <button type="submit" className="btn btn-cyber mt-4 w-100 py-2"><i className="fa-solid fa-microchip me-2"></i>Evaluate Pipeline Decision</button>
          </form>
        </div>
      </div>
      <div className="col-md-6 col-lg-5">
        <div className="card-cyber p-4 h-100 d-flex flex-col justify-content-between">
          <div>
            <h6 className="border-bottom pb-2 mb-3 fw-bold text-muted"><i className="fa-solid fa-calculator me-2 text-primary"></i>Decision Output</h6>
            {!result ? (
              <div className="text-center py-5 text-muted">Inject packet features and run evaluation.</div>
            ) : (
              <div>
                <div className="d-flex align-items-center mb-3">
                  <span className={`badge fs-6 ${result.is_malicious ? 'bg-danger-subtle text-danger border border-danger' : 'bg-success-subtle text-success border border-success'}`}>
                    {result.is_malicious ? 'ATTACK DETECTED' : 'NORMAL TRAFFIC'}
                  </span>
                </div>
                <div className="mb-2"><strong>Vector Type:</strong> <span className={result.is_malicious ? 'text-danger fw-bold' : 'text-success fw-bold'}>{result.attack_type}</span></div>
                <div className="mb-2"><strong>AI Decision Confidence:</strong> <span className="text-primary fw-bold">{(result.confidence * 100).toFixed(2)}%</span></div>
                
                <div className="mt-4 p-3 bg-light rounded small text-muted border">
                  <strong>Decision Tree Pipeline Path:</strong>
                  <div className="mt-1 font-monospace" style={{ fontSize: '11px' }}>
                    {result.attack_type === 'Normal' && '-> Flow_Packets_s <= 10.00 -> Normal Ingress'}
                    {result.attack_type === 'SYN Flood' && '-> Flow_Packets_s > 15.00 -> Protocol == TCP -> Flags == S -> Attack Category: SYN Flood'}
                    {result.attack_type === 'Ping Flood' && '-> Flow_Packets_s > 10.00 -> Protocol == ICMP -> Attack Category: Ping Flood'}
                    {result.attack_type === 'Brute Force' && '-> Flow_Packets_s > 8.00 -> Dst_Port == 22 -> Protocol == TCP -> Attack Category: Brute Force'}
                    {result.attack_type === 'SQL Injection' && '-> Dst_Port == 80 -> Fwd_Length == 950 -> Attack Category: SQL Injection'}
                    {result.attack_type === 'Cross-Site Scripting' && '-> Dst_Port == 80 -> Fwd_Length == 880 -> Attack Category: Cross-Site Scripting'}
                    {result.attack_type === 'ARP Poisoning' && '-> Protocol == ARP -> Attack Category: ARP Poisoning'}
                    {result.attack_type === 'DNS Spoofing' && '-> Dst_Port == 53 -> Flow_Packets_s > 15.00 -> Attack Category: DNS Spoofing'}
                    {result.attack_type === 'MITM Redirect' && '-> Dst_Port == 80 -> Flags == FA -> Fwd_Length == 120 -> Attack Category: MITM Redirect'}
                    {result.attack_type === 'Botnet C2 Callout' && '-> Dst_Port == 6667 -> Fwd_Length == 450 -> Attack Category: Botnet C2 Callout'}
                    {result.attack_type === 'Smurf Attack' && '-> Protocol == ICMP -> Dst_Port == 0 -> Fwd_Length >= 1400 -> Attack Category: Smurf Attack'}
                    {result.attack_type === 'Buffer Overflow' && '-> Dst_Port == 445 -> Fwd_Length >= 1450 -> Attack Category: Buffer Overflow'}
                    {result.attack_type === 'DoS' && '-> Flow_Packets_s > 100.00 -> Attack Category: DoS'}
                    {result.attack_type === 'DDoS' && '-> Flow_Duration > 5000 -> Flow_Bytes_s > 50000 -> Attack Category: DDoS'}
                    {result.attack_type === 'Port Scanning' && '-> Flow_Packets_s > 40.00 -> Dst_Port > 1024 -> Attack Category: Port Scanning'}
                    {result.attack_type === 'Web Attack' && '-> Dst_Port == 80 -> Fwd_Length > 1100 -> Attack Category: Web Attack'}
                  </div>
                </div>
              </div>
            )}
          </div>
          <div className="mt-4 p-3 bg-light rounded text-muted small">
            <i className="fa-solid fa-circle-info me-2 text-primary"></i>The Random Forest classifier analyzes 11 distinct packet flow characteristics to classify threats.
          </div>
        </div>
      </div>
    </div>
  );
}

// ----------------------------------------------------
// 5. ALERTS VIEW
// ----------------------------------------------------
function AlertsView({ alerts, setAlerts, onClearLogs, showNotification }) {
  const [severityFilter, setSeverityFilter] = useState('All');
  const [statusFilter, setStatusFilter] = useState('All');
  const [searchFilter, setSearchFilter] = useState('');

  const filteredAlerts = alerts.filter(a => {
    const sevMatch = severityFilter === 'All' || a.severity === severityFilter;
    const statMatch = statusFilter === 'All' || a.status === statusFilter;
    
    const term = searchFilter.toLowerCase();
    const searchMatch = !term || 
      a.src_ip.toLowerCase().includes(term) ||
      a.dst_ip.toLowerCase().includes(term) ||
      a.attack_type.toLowerCase().includes(term);

    return sevMatch && statMatch && searchMatch;
  });

  const handleResolve = (id) => {
    const res = nids.resolveAlert(id);
    if (res.success) {
      setAlerts(nids.getAlerts());
      showNotification(`Alert ID #${id} marked as resolved.`, 'success');
    }
  };

  const handleDelete = (id) => {
    if (window.confirm(`Dismiss alert #${id}? This will remove it from active lists.`)) {
      const res = nids.deleteAlert(id);
      if (res.success) {
        setAlerts(nids.getAlerts());
        showNotification(`Alert ID #${id} deleted from logs.`, 'warning');
      }
    }
  };

  const handleExportCSV = () => {
    if (filteredAlerts.length === 0) {
      showNotification("No alerts to export.", "warning");
      return;
    }
    const headers = ['Alert ID', 'Timestamp', 'Source IP', 'Destination IP', 'Attack Vector', 'Severity', 'Confidence', 'Status'];
    const rows = filteredAlerts.map(a => [
      a.id, a.timestamp, a.src_ip, a.dst_ip, a.attack_type, a.severity, a.confidence, a.status
    ]);
    const csvContent = "data:text/csv;charset=utf-8," 
      + [headers.join(','), ...rows.map(e => e.join(','))].join('\n');
      
    const encodedUri = encodeURI(csvContent);
    const link = document.createElement("a");
    link.setAttribute("href", encodedUri);
    link.setAttribute("download", `ai-nids-threat-report-${new Date().toISOString().slice(0,10)}.csv`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    showNotification("CSV export completed. Downloading file...", "success");
  };

  return (
    <div>
      {/* Filters Bar */}
      <div className="card-cyber p-4 mb-4">
        <div className="row g-3 align-items-center">
          <div className="col-md-4">
            <label className="form-label text-muted small fw-semibold">Search Targets</label>
            <div className="input-group">
              <span className="input-group-text bg-light border-end-0 text-muted"><i className="fa-solid fa-magnifying-glass"></i></span>
              <input type="text" className="form-control form-cyber border-start-0" placeholder="IP Address, Attack Type..." value={searchFilter} onChange={e => setSearchFilter(e.target.value)} />
            </div>
          </div>
          <div className="col-md-2">
            <label className="form-label text-muted small fw-semibold">Severity Priority</label>
            <select className="form-select form-cyber" value={severityFilter} onChange={e => setSeverityFilter(e.target.value)}>
              <option value="All">All Severities</option>
              <option value="Low">Low</option>
              <option value="Medium">Medium</option>
              <option value="High">High</option>
              <option value="Critical">Critical</option>
            </select>
          </div>
          <div className="col-md-2">
            <label className="form-label text-muted small fw-semibold">Mitigation Status</label>
            <select className="form-select form-cyber" value={statusFilter} onChange={e => setStatusFilter(e.target.value)}>
              <option value="All">Active & Resolved</option>
              <option value="Active">Active only</option>
              <option value="Resolved">Resolved only</option>
            </select>
          </div>
          <div className="col-md-4 text-md-end d-flex gap-2 align-self-end justify-content-md-end">
            <button className="btn btn-outline-secondary" onClick={() => { setSearchFilter(''); setSeverityFilter('All'); setStatusFilter('All'); }}><i className="fa-solid fa-rotate-left me-1"></i>Reset</button>
            <button className="btn btn-outline-danger" onClick={onClearLogs}><i className="fa-solid fa-trash-can me-1"></i>Clear All</button>
            <button className="btn btn-cyber-outline" onClick={handleExportCSV}><i className="fa-solid fa-file-csv me-1"></i>Export CSV</button>
          </div>
        </div>
      </div>

      {/* Alerts Table Grid */}
      <div className="card-cyber p-4">
        <div className="d-flex justify-content-between align-items-center mb-3">
          <h6 className="mb-0 text-primary fw-bold"><i className="fa-solid fa-list-check me-2"></i>Triggered Security Alerts</h6>
          <div className="text-muted small">Found: {filteredAlerts.length} alerts</div>
        </div>
        <div className="table-responsive">
          <table className="table table-hover align-middle mb-0" style={{ fontSize: '13px' }}>
            <thead>
              <tr className="text-muted border-bottom">
                <th>Alert ID</th>
                <th>Timestamp (UTC)</th>
                <th>Source IP</th>
                <th>Destination IP</th>
                <th>Attack Vector</th>
                <th>Severity</th>
                <th>Confidence</th>
                <th>Status</th>
                <th className="text-end">Actions</th>
              </tr>
            </thead>
            <tbody>
              {filteredAlerts.length === 0 ? (
                <tr>
                  <td colSpan="9" className="text-center py-4 text-muted">No security alerts matched the selected filters.</td>
                </tr>
              ) : (
                filteredAlerts.map(a => {
                  const isResolved = a.status === 'Resolved';
                  return (
                    <tr key={a.id} style={{ opacity: isResolved ? 0.6 : 1 }}>
                      <td className="fw-bold text-primary font-monospace">#{a.id}</td>
                      <td className="text-muted">{new Date(a.timestamp).toISOString().replace('T', ' ').substring(0, 19)}</td>
                      <td className="font-monospace">{a.src_ip}</td>
                      <td className="font-monospace">{a.dst_ip}</td>
                      <td className="fw-semibold"><i className="fa-solid fa-triangle-exclamation text-warning me-1"></i>{a.attack_type}</td>
                      <td>
                        <span className={`badge-sev ${a.severity === 'Critical' ? 'badge-critical' : a.severity === 'High' ? 'badge-high' : a.severity === 'Medium' ? 'badge-medium' : 'badge-low'}`}>
                          {a.severity}
                        </span>
                      </td>
                      <td>{(a.confidence * 100).toFixed(0)}%</td>
                      <td>
                        <span className={`badge ${isResolved ? 'bg-success-subtle text-success border border-success' : 'bg-danger-subtle text-danger border border-danger animate-pulse'}`}>
                          {a.status}
                        </span>
                      </td>
                      <td className="text-end">
                        <button className="btn btn-sm btn-outline-success py-0 px-2 me-1" onClick={() => handleResolve(a.id)} disabled={isResolved}>
                          <i className="fa-solid fa-check me-1"></i>Resolve
                        </button>
                        <button className="btn btn-sm btn-outline-danger py-0 px-2" onClick={() => handleDelete(a.id)}>
                          <i className="fa-solid fa-trash-can"></i>
                        </button>
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}

// ----------------------------------------------------
// 6. THRESHOLDS VIEW
// ----------------------------------------------------
function SettingsView({ thresholds, setThresholds, showNotification }) {
  const [formData, setFormData] = useState({});

  useEffect(() => {
    setFormData(thresholds);
  }, [thresholds]);

  const handleSubmit = (e) => {
    e.preventDefault();
    nids.saveSettings(formData);
    setThresholds(formData);
    showNotification("Rule thresholds saved successfully.", "success");
  };

  const handleResetDefaults = () => {
    if (window.confirm("Reset current rules to factory default settings?")) {
      const defaults = {
        'PORT_SCAN_COUNT': 15,
        'PORT_SCAN_WINDOW': 10,
        'PING_FLOOD_RATE': 10,
        'SYN_FLOOD_RATE': 15,
        'BRUTE_FORCE_RATE': 10,
        'HIGH_PACKET_RATE': 100
      };
      nids.saveSettings(defaults);
      setThresholds(defaults);
      setFormData(defaults);
      showNotification("Rules reset to factory default settings persistently.", "success");
    }
  };

  return (
    <div className="card-cyber p-4">
      <div className="d-flex justify-content-between align-items-center border-bottom pb-2 mb-4 flex-wrap gap-2">
        <h6 className="mb-0 text-primary fw-bold"><i className="fa-solid fa-sliders me-2"></i>Configure Dynamic Heuristic Threshold Matrix</h6>
        <button type="button" className="btn btn-sm btn-outline-secondary" onClick={handleResetDefaults}>
          <i className="fa-solid fa-rotate-left me-1"></i>Reset to Factory Defaults
        </button>
      </div>
      <form onSubmit={handleSubmit}>
        <div className="row g-4">
          <div className="col-md-6">
            <div className="mb-3">
              <label className="form-label fw-semibold text-dark">Port Scan Probe Count</label>
              <input type="number" className="form-control form-cyber" value={formData.PORT_SCAN_COUNT || ''} onChange={e => setFormData({ ...formData, PORT_SCAN_COUNT: parseInt(e.target.value) || 0 })} required />
              <small className="text-muted">Unique ports scanned from one IP to trigger an alert.</small>
            </div>
          </div>
          <div className="col-md-6">
            <div className="mb-3">
              <label className="form-label fw-semibold text-dark">Port Scan Window (Sec)</label>
              <input type="number" className="form-control form-cyber" value={formData.PORT_SCAN_WINDOW || ''} onChange={e => setFormData({ ...formData, PORT_SCAN_WINDOW: parseInt(e.target.value) || 0 })} required />
              <small className="text-muted">Time window constraint (in seconds) for scanning checks.</small>
            </div>
          </div>
          <div className="col-md-6">
            <div className="mb-3">
              <label className="form-label fw-semibold text-dark">Ping Flood Rate Limit (ICMP/sec)</label>
              <input type="number" className="form-control form-cyber" value={formData.PING_FLOOD_RATE || ''} onChange={e => setFormData({ ...formData, PING_FLOOD_RATE: parseInt(e.target.value) || 0 })} required />
              <small className="text-muted">Number of ICMP Echo requests per second from a single IP.</small>
            </div>
          </div>
          <div className="col-md-6">
            <div className="mb-3">
              <label className="form-label fw-semibold text-dark">SYN Flood Rate Limit (SYN/sec)</label>
              <input type="number" className="form-control form-cyber" value={formData.SYN_FLOOD_RATE || ''} onChange={e => setFormData({ ...formData, SYN_FLOOD_RATE: parseInt(e.target.value) || 0 })} required />
              <small className="text-muted">Number of TCP SYN packets per second from a single IP.</small>
            </div>
          </div>
          <div className="col-md-6">
            <div className="mb-3">
              <label className="form-label fw-semibold text-dark">Brute Force Limit (Attempts/sec)</label>
              <input type="number" className="form-control form-cyber" value={formData.BRUTE_FORCE_RATE || ''} onChange={e => setFormData({ ...formData, BRUTE_FORCE_RATE: parseInt(e.target.value) || 0 })} required />
              <small className="text-muted">Connection attempts per second targeting SSH/FTP/RDP ports.</small>
            </div>
          </div>
          <div className="col-md-6">
            <div className="mb-3">
              <label className="form-label fw-semibold text-dark">Total Flow Rate limit (Packets/sec)</label>
              <input type="number" className="form-control form-cyber" value={formData.HIGH_PACKET_RATE || ''} onChange={e => setFormData({ ...formData, HIGH_PACKET_RATE: parseInt(e.target.value) || 0 })} required />
              <small className="text-muted">Aggregate network throughput limit before flagging generic Denial of Service (DoS).</small>
            </div>
          </div>
        </div>
        <button type="submit" className="btn btn-cyber mt-4 w-100 py-2"><i className="fa-solid fa-floppy-disk me-2"></i>Apply Threshold Matrix</button>
      </form>
    </div>
  );
}

// ----------------------------------------------------
// 7. PROFILE VIEW
// ----------------------------------------------------
function ProfileView({ activeUser, setActiveUser, showNotification }) {
  const [email, setEmail] = useState(activeUser.email);
  const [password, setPassword] = useState('');

  const handleSubmit = (e) => {
    e.preventDefault();
    const users = nids.getUsers();
    const index = users.findIndex(u => u.id === activeUser.id);
    if (index !== -1) {
      users[index].email = email;
      if (password) users[index].password = password;
      nids.saveUsers(users);
      
      const updatedUser = { ...activeUser, email };
      nids.setActiveUser(updatedUser);
      setActiveUser(updatedUser);
      setPassword('');
      showNotification("Profile credentials updated successfully.", "success");
    }
  };

  return (
    <div className="card-cyber p-4">
      <h6 className="border-bottom pb-2 mb-4 fw-bold text-muted"><i className="fa-solid fa-user-shield me-2"></i>Operator Clearance Profile</h6>
      <div className="row">
        <div className="col-md-4 text-center border-end py-3">
          <img 
            src={`https://api.dicebear.com/7.x/bottts/svg?seed=${activeUser.username}`} 
            alt="Avatar" width="120" height="120" className="rounded-circle border border-primary mb-3 bg-light p-2" 
          />
          <h4 className="fw-bold mb-1">{activeUser.username}</h4>
          <span className="badge bg-primary-subtle text-primary border px-3 py-1 text-uppercase">{activeUser.role}</span>
        </div>
        <div className="col-md-8 px-md-4 py-3">
          <form onSubmit={handleSubmit}>
            <div className="mb-3">
              <label className="form-label text-muted small">Registered Email Address</label>
              <input type="email" className="form-control form-cyber" value={email} onChange={e => setEmail(e.target.value)} required />
            </div>
            <div className="mb-4">
              <label className="form-label text-muted small">Update Security Passcode (leave empty to keep unchanged)</label>
              <input type="password" className="form-control form-cyber" placeholder="New passcode" value={password} onChange={e => setPassword(e.target.value)} />
            </div>
            <button type="submit" className="btn btn-cyber py-2 px-4"><i className="fa-solid fa-user-check me-2"></i>Save Account Changes</button>
          </form>
        </div>
      </div>
    </div>
  );
}

// ----------------------------------------------------
// 8. ADMIN VIEW
// ----------------------------------------------------
function AdminView({ showNotification }) {
  const [users, setUsers] = useState([]);
  const [newUsername, setNewUsername] = useState('');
  const [newEmail, setNewEmail] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [newRole, setNewRole] = useState('Security Analyst');

  useEffect(() => {
    setUsers(nids.getUsers());
  }, []);

  const handleCreateUser = (e) => {
    e.preventDefault();
    const existing = users.find(u => u.username === newUsername || u.email === newEmail);
    if (existing) {
      showNotification("Username or email already exists.", "danger");
      return;
    }

    const nextId = users.length > 0 ? Math.max(...users.map(u => u.id)) + 1 : 1;
    const newUser = {
      id: nextId,
      username: newUsername,
      email: newEmail,
      role: newRole,
      profile_pic: 'default.svg',
      password: newPassword
    };

    const updated = [...users, newUser];
    nids.saveUsers(updated);
    setUsers(updated);

    setNewUsername('');
    setNewEmail('');
    setNewPassword('');
    showNotification(`Operator account '${newUsername}' provisioned successfully.`, "success");
  };

  const handleDeleteUser = (id, username) => {
    if (username === 'admin') {
      showNotification("Cannot delete primary system administrator.", "danger");
      return;
    }
    if (window.confirm(`Revoke clearance credentials for operator '${username}'?`)) {
      const updated = users.filter(u => u.id !== id);
      nids.saveUsers(updated);
      setUsers(updated);
      showNotification(`Account '${username}' revoked.`, "warning");
    }
  };

  return (
    <div className="row g-4">
      <div className="col-md-6 col-lg-7">
        <div className="card-cyber p-4">
          <h6 className="border-bottom pb-2 mb-3 fw-bold text-muted"><i className="fa-solid fa-users me-2"></i>Active Security Operators</h6>
          <div className="table-responsive">
            <table className="table table-hover align-middle mb-0" style={{ fontSize: '13px' }}>
              <thead>
                <tr className="text-muted border-bottom">
                  <th>ID</th>
                  <th>Username</th>
                  <th>Email</th>
                  <th>Clearance Level</th>
                  <th className="text-end">Actions</th>
                </tr>
              </thead>
              <tbody>
                {users.map(u => (
                  <tr key={u.id}>
                    <td>{u.id}</td>
                    <td className="fw-semibold">{u.username}</td>
                    <td>{u.email}</td>
                    <td><span className={`badge ${u.role === 'Admin' ? 'bg-primary-subtle text-primary border' : 'bg-light text-muted border'}`}>{u.role}</span></td>
                    <td className="text-end">
                      <button className="btn btn-sm btn-outline-danger py-0 px-2" onClick={() => handleDeleteUser(u.id, u.username)} disabled={u.username === 'admin'}>
                        <i className="fa-solid fa-trash-can"></i>
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </div>
      
      <div className="col-md-6 col-lg-5">
        <div className="card-cyber p-4">
          <h6 className="border-bottom pb-2 mb-3 fw-bold text-muted"><i className="fa-solid fa-user-plus me-2"></i>Provision New Clearance Level</h6>
          <form onSubmit={handleCreateUser}>
            <div className="mb-2">
              <label className="form-label text-muted small fw-semibold">Clearance Username</label>
              <input type="text" className="form-control form-cyber py-1 px-2" value={newUsername} onChange={e => setNewUsername(e.target.value)} required />
            </div>
            <div className="mb-2">
              <label className="form-label text-muted small fw-semibold">Email Address</label>
              <input type="email" className="form-control form-cyber py-1 px-2" value={newEmail} onChange={e => setNewEmail(e.target.value)} required />
            </div>
            <div className="mb-2">
              <label className="form-label text-muted small fw-semibold">Passcode</label>
              <input type="password" className="form-control form-cyber py-1 px-2" value={newPassword} onChange={e => setNewPassword(e.target.value)} required />
            </div>
            <div className="mb-3">
              <label className="form-label text-muted small fw-semibold">Clearance Level</label>
              <select className="form-select form-cyber py-1 px-2" value={newRole} onChange={e => setNewRole(e.target.value)}>
                <option value="Security Analyst">Security Analyst</option>
                <option value="Admin">Admin</option>
              </select>
            </div>
            <button type="submit" className="btn btn-cyber w-100 py-2 fw-bold"><i className="fa-solid fa-user-plus me-2"></i>Provision Clearance</button>
          </form>
        </div>
      </div>
    </div>
  );
}

// ----------------------------------------------------
// 9. ATTACK KNOWLEDGE VIEW
// ----------------------------------------------------
const ATTACK_DATABASE = [
  {
    id: 'port-scan',
    name: 'Port Scanning',
    icon: 'fa-magnifying-glass-location',
    category: 'Reconnaissance',
    severity: 'High',
    description: 'Attackers probe range of ports on a target system to discover open access paths, running services, and vulnerable configurations.',
    harmful_effects: 'Allows malicious actors to map the target network topology, locate specific operational server doors (like ports 22 SSH or 3389 RDP), and prepare a targeted payload delivery.',
    prevention: 'Set up strict firewall ingress rules, employ port scan detection systems that block probing IPs automatically, hide unused ports, and use port-knocking protocols.'
  },
  {
    id: 'syn-flood',
    name: 'SYN Flood (DDoS)',
    icon: 'fa-burst',
    category: 'Denial of Service',
    severity: 'Critical',
    description: 'An attacker rapidly sends TCP connection requests (SYN) without completing the three-way handshake, exhausting the target server\'s connection queue buffer.',
    harmful_effects: 'Prevents legitimate users from connecting to the server, resulting in total server crash, application timeouts, and service outages.',
    prevention: 'Deploy SYN cookies, configure shorter handshake connection timeouts, use hardware rate-limiting firewalls, and route ingress through DDoS scrubbing centers.'
  },
  {
    id: 'ping-flood',
    name: 'Ping Flood (ICMP)',
    icon: 'fa-wave-square',
    category: 'Denial of Service',
    severity: 'Medium',
    description: 'An attacker inundates a target system with ICMP Echo Request (ping) packets to saturate public and local network bandwidth.',
    harmful_effects: 'Causes high packet latency, network interface saturation, extreme database latency, and makes web services sluggish or completely unresponsive.',
    prevention: 'Decline ICMP ping requests on gateway firewalls, enforce packet rate thresholds, and implement network access control lists (ACLs) to drop suspicious ICMP logs.'
  },
  {
    id: 'brute-force',
    name: 'Brute Force',
    icon: 'fa-key',
    category: 'Credential Access',
    severity: 'High',
    description: 'Automated trial-and-error scripts systematically test thousands of usernames and passwords against management gateways (SSH 22, FTP 21, RDP 3389).',
    harmful_effects: 'Direct unauthorized network penetration, database exposure, remote shell command executions, and installation of administrative backdoors.',
    prevention: 'Mandate robust password complexity, enforce multi-factor authentication (MFA), implement account lockouts via Fail2ban, and modify default service ports.'
  },
  {
    id: 'sqli',
    name: 'SQL Injection (SQLi)',
    icon: 'fa-database',
    category: 'Application Exploit',
    severity: 'High',
    description: 'Malicious SQL statements are inserted into dynamic database query input fields, executing unauthorized backend database instructions.',
    harmful_effects: 'Leaking database records (exfiltrating customer credentials and financial details), bypasses admin login verification, and alters database data.',
    prevention: 'Use parameterized queries (prepared statements), enforce strict input validations, follow database least privilege principles, and use Web Application Firewalls (WAF).'
  },
  {
    id: 'xss',
    name: 'Cross-Site Scripting (XSS)',
    icon: 'fa-code',
    category: 'Application Exploit',
    severity: 'High',
    description: 'An attacker injects malicious client-side scripts (HTML/JavaScript) into trusted websites, which are then served and executed by other visitors\' browsers.',
    harmful_effects: 'Stealing active session cookies, capturing login credentials via keystroke logging, hijacking user accounts, and defacing web page assets.',
    prevention: 'Escape all user-submitted output variables, implement a strict Content Security Policy (CSP), use HttpOnly session cookies, and validate input queries.'
  },
  {
    id: 'arp-poisoning',
    name: 'ARP Poisoning',
    icon: 'fa-network-wired',
    category: 'Spoofing & Poisoning',
    severity: 'High',
    description: 'Attackers send fake Address Resolution Protocol (ARP) messages onto a local area network to link their MAC address with the IP of a legitimate gateway.',
    harmful_effects: 'Allows attackers to intercept, sniff, inspect, or modify local network communications in transit, leading to local Man-in-the-Middle (MITM) exposures.',
    prevention: 'Enable Dynamic ARP Inspection (DAI) on corporate ethernet switches, map static ARP tables for core servers, and mandate end-to-end VPN or TLS encryption.'
  },
  {
    id: 'dns-spoofing',
    name: 'DNS Spoofing',
    icon: 'fa-server',
    category: 'Spoofing & Poisoning',
    severity: 'Medium',
    description: 'Forged Domain Name System (DNS) entry maps are injected into a resolver\'s cache, directing hostname requests to malicious attacker-controlled server IPs.',
    harmful_effects: 'User requests for clean sites (e.g. online banking) are silently redirected to identical phishing clones, leading to widespread credentials theft.',
    prevention: 'Deploy DNSSEC (DNS Security Extensions) to validate record authenticity, secure DNS cache ports, and use encrypted DNS over HTTPS (DoH) services.'
  },
  {
    id: 'mitm-redirect',
    name: 'MITM Redirect',
    icon: 'fa-arrows-split-up-and-left',
    category: 'Man-in-the-Middle',
    severity: 'Critical',
    description: 'Attackers hijack network packets to act as an invisible relay proxy between client requests and server responses without either side realizing.',
    harmful_effects: 'Exposes private API payloads, encryption keys, and login credentials, and permits malicious actors to alter communication flows in real-time.',
    prevention: 'Enforce strict end-to-end HTTPS with HSTS headers, pin SSL/TLS public certificates, and verify link path integrity.'
  },
  {
    id: 'c2-callout',
    name: 'Botnet C2 Callout',
    icon: 'fa-terminal',
    category: 'Malware Operations',
    severity: 'Critical',
    description: 'An infected internal computer automatically opens a outbound connection (beacon) to an external Command and Control (C2) botnet server.',
    harmful_effects: 'The compromised system joins a coordinated botnet fleet to execute DDoS attacks, mine crypto, spread malware, or exfiltrate local files.',
    prevention: 'Disable all non-standard outgoing port traffic, deploy DNS sinkholes to block C2 domain lookups, and use endpoint detection response (EDR).'
  },
  {
    id: 'smurf',
    name: 'Smurf Attack',
    icon: 'fa-bullhorn',
    category: 'Denial of Service',
    severity: 'High',
    description: 'An attacker broadcasts ICMP packets with a spoofed source IP address (set to the target\'s IP) to a local broadcast network, prompting all hosts to reply.',
    harmful_effects: 'Generates a volumetric reply traffic multiplier that quickly congests the target\'s network card interfaces, causing total denial of service.',
    prevention: 'Configure routers to reject packets directed to network broadcast IP addresses, and restrict ICMP responder rates.'
  },
  {
    id: 'overflow',
    name: 'Buffer Overflow',
    icon: 'fa-box-open',
    category: 'Service Exploit',
    severity: 'Critical',
    description: 'Massive dataset packets are directed to unmanaged system buffer inputs, exceeding storage boundaries and writing directly into memory execution registers.',
    harmful_effects: 'Crashes critical system services (like SMB or Telnet) and enables arbitrary remote code execution (RCE) with full root/system privileges.',
    prevention: 'Perform compiler bounds checking, keep operating system server patches updated, and enforce Memory protection features like DEP, ASLR, and Canary bounds.'
  },
  {
    id: 'dos',
    name: 'DoS (Denial of Service)',
    icon: 'fa-triangle-exclamation',
    category: 'Denial of Service',
    severity: 'Critical',
    description: 'A resource exhaustion exploit targeting CPU, RAM, or bandwidth limits by sending volumetric packet clusters to clog server capacities.',
    harmful_effects: 'Stops legitimate operator access to systems and services, locking out business applications and causing severe operational disruption.',
    prevention: 'Enforce hardware rate limits, set up network load balancers, dynamically scale backend server nodes, and block bad IPs at edge routing tables.'
  }
];

function AttackKnowledgeView() {
  const [selectedAttack, setSelectedAttack] = useState(ATTACK_DATABASE[0]);

  return (
    <div className="row g-4">
      {/* Sidebar List */}
      <div className="col-md-4 col-lg-3">
        <div className="card-cyber p-3" style={{ maxHeight: '600px', overflowY: 'auto' }}>
          <h6 className="border-bottom pb-2 mb-3 fw-bold text-muted">
            <i className="fa-solid fa-list me-2"></i>Attack Threats List
          </h6>
          <div className="list-group list-group-flush gap-1">
            {ATTACK_DATABASE.map(attack => (
              <button
                key={attack.id}
                type="button"
                className={`list-group-item list-group-item-action border-0 rounded text-start d-flex align-items-center py-2 px-3 fw-semibold ${selectedAttack.id === attack.id ? 'active' : ''}`}
                style={{
                  backgroundColor: selectedAttack.id === attack.id ? 'rgba(2, 132, 199, 0.08)' : 'transparent',
                  color: selectedAttack.id === attack.id ? 'var(--primary)' : 'var(--text-muted)',
                  fontSize: '13px'
                }}
                onClick={() => setSelectedAttack(attack)}
              >
                <i className={`fa-solid ${attack.icon} me-3 text-center`} style={{ width: '18px' }}></i>
                {attack.name}
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* Details Card */}
      <div className="col-md-8 col-lg-9">
        <div className="card-cyber p-4 h-100 d-flex flex-column justify-content-between">
          <div>
            <div className="d-flex justify-content-between align-items-start border-bottom pb-3 mb-4 flex-wrap gap-2">
              <div className="d-flex align-items-center gap-3">
                <div className="bg-primary-subtle text-primary rounded p-3 d-flex align-items-center justify-content-center" style={{ width: '56px', height: '56px', fontSize: '24px' }}>
                  <i className={`fa-solid ${selectedAttack.icon}`}></i>
                </div>
                <div>
                  <h4 className="fw-bold text-dark mb-1">{selectedAttack.name}</h4>
                  <span className="text-muted small fw-bold text-uppercase me-3"><i className="fa-solid fa-folder me-1"></i>{selectedAttack.category}</span>
                </div>
              </div>
              <span className={`badge-sev ${selectedAttack.severity === 'Critical' ? 'badge-critical' : selectedAttack.severity === 'High' ? 'badge-high' : selectedAttack.severity === 'Medium' ? 'badge-medium' : 'badge-low'}`}>
                {selectedAttack.severity} Priority
              </span>
            </div>

            {/* Description */}
            <div className="mb-4">
              <h6 className="fw-bold text-dark mb-2"><i className="fa-solid fa-circle-info text-primary me-2"></i>Description & Vector Overview</h6>
              <p className="text-muted" style={{ fontSize: '14px', lineHeight: '1.6' }}>{selectedAttack.description}</p>
            </div>

            {/* Harmful Effects */}
            <div className="mb-4 p-3 rounded" style={{ backgroundColor: 'rgba(220, 38, 38, 0.03)', border: '1px dashed rgba(220, 38, 38, 0.15)' }}>
              <h6 className="fw-bold text-danger mb-2"><i className="fa-solid fa-triangle-exclamation me-2"></i>Harmful System Effects</h6>
              <p className="text-muted mb-0" style={{ fontSize: '14px', lineHeight: '1.6' }}>{selectedAttack.harmful_effects}</p>
            </div>

            {/* Prevention */}
            <div className="mb-4 p-3 rounded" style={{ backgroundColor: 'rgba(16, 185, 129, 0.03)', border: '1px dashed rgba(16, 185, 129, 0.15)' }}>
              <h6 className="fw-bold text-success mb-2"><i className="fa-solid fa-shield-halved me-2"></i>Prevention & Mitigation Actions</h6>
              <p className="text-muted mb-0" style={{ fontSize: '14px', lineHeight: '1.6' }}>{selectedAttack.prevention}</p>
            </div>
          </div>

          <div className="mt-4 p-3 bg-light rounded text-muted small border d-flex align-items-center">
            <i className="fa-solid fa-graduation-cap me-3 text-primary fa-lg"></i>
            <span>This Security Knowledge Base helps analysts configure firewall rules and patch systems to mitigate detected anomalies.</span>
          </div>
        </div>
      </div>
    </div>
  );
}

export default App;
