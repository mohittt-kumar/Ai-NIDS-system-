// AI-NIDS Client-Side Simulation & LocalStorage DB Service

const DEFAULT_THRESHOLDS = {
    'PORT_SCAN_COUNT': 15,
    'PORT_SCAN_WINDOW': 10,
    'PING_FLOOD_RATE': 10,
    'SYN_FLOOD_RATE': 15,
    'BRUTE_FORCE_RATE': 10,
    'HIGH_PACKET_RATE': 100
};

const DEFAULT_USERS = [
    { id: 1, username: 'admin', email: 'admin@ainids.local', role: 'Admin', profile_pic: 'default.svg', password: 'password123' },
    { id: 2, username: 'analyst', email: 'analyst@ainids.local', role: 'Security Analyst', profile_pic: 'default.svg', password: 'password123' }
];

// Helper to initialize database if empty
export const initDatabase = () => {
    if (!localStorage.getItem('nids_users')) {
        localStorage.setItem('nids_users', JSON.stringify(DEFAULT_USERS));
    }
    if (!localStorage.getItem('nids_settings')) {
        localStorage.setItem('nids_settings', JSON.stringify(DEFAULT_THRESHOLDS));
    }
    
    // Check if logs are empty; if so, pre-seed them with historical data
    if (!localStorage.getItem('nids_packets') || JSON.parse(localStorage.getItem('nids_packets') || '[]').length === 0) {
        const preseeded = generatePreseededData();
        localStorage.setItem('nids_packets', JSON.stringify(preseeded.packets));
        localStorage.setItem('nids_alerts', JSON.stringify(preseeded.alerts));
    } else {
        if (!localStorage.getItem('nids_packets')) {
            localStorage.setItem('nids_packets', JSON.stringify([]));
        }
        if (!localStorage.getItem('nids_alerts')) {
            localStorage.setItem('nids_alerts', JSON.stringify([]));
        }
    }
    
    if (!localStorage.getItem('nids_active_user')) {
        localStorage.setItem('nids_active_user', null);
    }
};

const generatePreseededData = () => {
    const packets = [];
    const alerts = [];
    const attackerIps = ['185.220.101.5', '45.133.1.20', '198.51.100.42'];
    const protocols = ['TCP', 'UDP', 'ICMP'];
    
    // Seed 50 packets spanning the last hour
    const now = new Date();
    for (let i = 50; i >= 0; i--) {
        const timeOffset = new Date(now.getTime() - i * 60 * 1000); // i minutes ago
        const isMalicious = i % 12 === 0;
        
        let src_ip = '192.168.1.' + (Math.floor(Math.random() * 80) + 50);
        let dst_port = [80, 443, 53, 22][Math.floor(Math.random() * 4)];
        let protocol = protocols[Math.floor(Math.random() * 3)];
        
        if (isMalicious) {
            src_ip = attackerIps[Math.floor(Math.random() * attackerIps.length)];
            protocol = 'TCP';
            dst_port = 22; // Brute force or scanning port
        }
        
        packets.push({
            timestamp: timeOffset.toISOString(),
            src_ip,
            dst_ip: '192.168.1.10',
            protocol,
            src_port: Math.floor(Math.random() * 50000) + 1000,
            dst_port,
            size: Math.floor(Math.random() * 1000) + 64,
            flags: isMalicious ? 'S' : 'PA'
        });
        
        // Seed some corresponding alerts
        if (isMalicious && i !== 0) {
            const attackTypes = ['Port Scan', 'SYN Flood', 'Brute Force', 'Ping Flood'];
            const attack_type = attackTypes[Math.floor(Math.random() * 4)];
            const severities = { 'Port Scan': 'High', 'SYN Flood': 'Critical', 'Brute Force': 'High', 'Ping Flood': 'Medium' };
            
            alerts.push({
                id: alerts.length + 1,
                timestamp: timeOffset.toISOString(),
                src_ip,
                dst_ip: '192.168.1.10',
                attack_type,
                severity: severities[attack_type],
                confidence: parseFloat((0.9 + Math.random() * 0.08).toFixed(2)),
                status: Math.random() > 0.4 ? 'Resolved' : 'Active'
            });
        }
    }
    
    return { packets, alerts };
};

// Database Methods
export const getSettings = () => {
    initDatabase();
    return JSON.parse(localStorage.getItem('nids_settings'));
};

export const saveSettings = (settings) => {
    localStorage.setItem('nids_settings', JSON.stringify(settings));
    return true;
};

export const getPackets = () => {
    initDatabase();
    return JSON.parse(localStorage.getItem('nids_packets'));
};

export const getAlerts = () => {
    initDatabase();
    return JSON.parse(localStorage.getItem('nids_alerts')).filter(a => a.status !== 'Deleted');
};

export const getUsers = () => {
    initDatabase();
    return JSON.parse(localStorage.getItem('nids_users'));
};

export const saveUsers = (users) => {
    localStorage.setItem('nids_users', JSON.stringify(users));
};

export const getActiveUser = () => {
    initDatabase();
    const user = localStorage.getItem('nids_active_user');
    return user ? JSON.parse(user) : null;
};

export const setActiveUser = (user) => {
    localStorage.setItem('nids_active_user', user ? JSON.stringify(user) : null);
};

// Clear all database tables (corresponds to `/api/alert/clear`)
export const clearAllLogs = () => {
    localStorage.setItem('nids_packets', JSON.stringify([]));
    localStorage.setItem('nids_alerts', JSON.stringify([]));
    return { success: true };
};

// Resolve single alert
export const resolveAlert = (alertId) => {
    const alerts = JSON.parse(localStorage.getItem('nids_alerts') || '[]');
    const index = alerts.findIndex(a => a.id === parseInt(alertId));
    if (index !== -1) {
        alerts[index].status = 'Resolved';
        localStorage.setItem('nids_alerts', JSON.stringify(alerts));
        return { success: true };
    }
    return { success: false, error: 'Alert not found' };
};

// Delete single alert (soft delete)
export const deleteAlert = (alertId) => {
    const alerts = JSON.parse(localStorage.getItem('nids_alerts') || '[]');
    const index = alerts.findIndex(a => a.id === parseInt(alertId));
    if (index !== -1) {
        alerts[index].status = 'Deleted';
        localStorage.setItem('nids_alerts', JSON.stringify(alerts));
        return { success: true };
    }
    return { success: false, error: 'Alert not found' };
};

// ML Model prediction emulation
export const predictPacket = (features) => {
    const {
        Source_Port, Destination_Port, Protocol, Flow_Duration,
        Total_Fwd_Packets, Total_Backward_Packets, Total_Length_of_Fwd_Packets,
        Fwd_Packet_Length_Max, Bwd_Packet_Length_Max, Flow_Bytes_s,
        Flow_Packets_s
    } = features;

    // Simple Decision boundaries mirroring our Random Forest model logic
    let attack_type = 'Normal';
    let confidence = 0.99;

    const dPort = parseInt(Destination_Port);
    const sPort = parseInt(Source_Port);
    const packetsRate = parseFloat(Flow_Packets_s);
    const duration = parseFloat(Flow_Duration);

    if (Protocol === 'ICMP' && packetsRate > 10) {
        attack_type = 'Ping Flood';
        confidence = 0.94 + Math.random() * 0.05;
    } else if (Protocol === 'TCP' && (dPort === 22 || dPort === 21 || dPort === 3389) && packetsRate > 8) {
        attack_type = 'Brute Force';
        confidence = 0.96 + Math.random() * 0.03;
    } else if (packetsRate > 100) {
        attack_type = 'DoS';
        confidence = 0.98 + Math.random() * 0.01;
    } else if (duration > 5000 && Total_Fwd_Packets > 30 && Flow_Bytes_s > 50000) {
        attack_type = 'DDoS';
        confidence = 0.97 + Math.random() * 0.02;
    } else if (dPort > 1024 && packetsRate > 40 && Total_Fwd_Packets > 15) {
        attack_type = 'Port Scan';
        confidence = 0.95 + Math.random() * 0.04;
    } else if (dPort === 80 || dPort === 443) {
        // Mock SQLi / XSS heuristic web attacks
        if (Total_Length_of_Fwd_Packets > 1000 && Fwd_Packet_Length_Max > 500 && Math.random() > 0.7) {
            attack_type = 'Web Attack';
            confidence = 0.92 + Math.random() * 0.06;
        }
    }

    return {
        is_malicious: attack_type !== 'Normal',
        attack_type,
        confidence: parseFloat(confidence.toFixed(4))
    };
};

// Simulation engine: generates packets and evaluates rules
export const generateSimulatedPacket = (specificType = null) => {
    const protocols = ['TCP', 'UDP', 'ICMP'];
    const commonIps = ['192.168.1.50', '192.168.1.100', '10.0.0.15', '10.0.0.22', '8.8.8.8', '1.1.1.1'];
    const attackerIps = ['185.220.101.5', '45.133.1.20', '198.51.100.42'];
    
    const type = specificType || (Math.random() > 0.85 ? 'Attack' : 'Normal');
    
    let src_ip = commonIps[Math.floor(Math.random() * commonIps.length)];
    let dst_ip = '192.168.1.10'; // Our protected asset
    let protocol = protocols[Math.floor(Math.random() * protocols.length)];
    let src_port = Math.floor(Math.random() * 64000) + 1025;
    let dst_port = [80, 443, 22, 53, 3389][Math.floor(Math.random() * 5)];
    let size = Math.floor(Math.random() * 1400) + 64;
    let flags = 'S';
    
    if (type === 'Attack') {
        src_ip = attackerIps[Math.floor(Math.random() * attackerIps.length)];
        const attackPatterns = ['Port Scan', 'SYN Flood', 'Ping Flood', 'Brute Force', 'Web Attack'];
        const pattern = specificType || attackPatterns[Math.floor(Math.random() * attackPatterns.length)];
        
        if (pattern === 'Port Scan') {
            dst_port = Math.floor(Math.random() * 1000) + 1; // Random scan port
            protocol = 'TCP';
            flags = 'S';
            size = 64;
        } else if (pattern === 'SYN Flood') {
            dst_port = 80;
            protocol = 'TCP';
            flags = 'S';
            size = 64;
        } else if (pattern === 'Ping Flood') {
            protocol = 'ICMP';
            dst_port = 0;
            flags = '';
            size = 1200;
        } else if (pattern === 'Brute Force') {
            dst_port = [22, 3389, 21][Math.floor(Math.random() * 3)];
            protocol = 'TCP';
            flags = 'PA';
            size = 128;
        } else if (pattern === 'Web Attack') {
            dst_port = 80;
            protocol = 'TCP';
            flags = 'PA';
            size = Math.floor(Math.random() * 800) + 600;
        }
    }
    
    return {
        timestamp: new Date().toISOString(),
        src_ip,
        dst_ip,
        protocol,
        src_port,
        dst_port,
        size,
        flags
    };
};

// Process packet through heuristic detection rules
export const processDetectionRules = (packet, packetsHistory) => {
    const thresholds = getSettings();
    const now = new Date();
    
    // Filter history for current packet's source IP
    const ipHistory = packetsHistory.filter(p => p.src_ip === packet.src_ip);
    
    // 1. Port Scan Detection
    const windowStart = new Date(now.getTime() - thresholds.PORT_SCAN_WINDOW * 1000);
    const recentIpHistory = ipHistory.filter(p => new Date(p.timestamp) >= windowStart);
    const uniquePorts = new Set(recentIpHistory.map(p => p.dst_port));
    
    if (uniquePorts.size >= thresholds.PORT_SCAN_COUNT && packet.protocol === 'TCP') {
        return {
            triggered: true,
            attack_type: 'Port Scan',
            severity: 'High',
            confidence: 0.95
        };
    }
    
    // 2. SYN Flood Detection
    const oneSecondAgo = new Date(now.getTime() - 1000);
    const synsLastSecond = recentIpHistory.filter(p => new Date(p.timestamp) >= oneSecondAgo && p.flags === 'S').length;
    
    if (synsLastSecond >= thresholds.SYN_FLOOD_RATE) {
        return {
            triggered: true,
            attack_type: 'SYN Flood',
            severity: 'Critical',
            confidence: 0.98
        };
    }
    
    // 3. Ping Flood Detection
    const icmpsLastSecond = recentIpHistory.filter(p => new Date(p.timestamp) >= oneSecondAgo && p.protocol === 'ICMP').length;
    
    if (icmpsLastSecond >= thresholds.PING_FLOOD_RATE) {
        return {
            triggered: true,
            attack_type: 'Ping Flood',
            severity: 'Medium',
            confidence: 0.92
        };
    }
    
    // 4. Brute Force Detection
    const bruteAttemptsLastSecond = recentIpHistory.filter(p => 
        new Date(p.timestamp) >= oneSecondAgo && 
        [22, 21, 3389].includes(p.dst_port)
    ).length;
    
    if (bruteAttemptsLastSecond >= thresholds.BRUTE_FORCE_RATE) {
        return {
            triggered: true,
            attack_type: 'Brute Force',
            severity: 'High',
            confidence: 0.96
        };
    }

    // 5. High Packet Rate Detection
    const totalLastSecond = packetsHistory.filter(p => new Date(p.timestamp) >= oneSecondAgo).length;
    if (totalLastSecond >= thresholds.HIGH_PACKET_RATE) {
        return {
            triggered: true,
            attack_type: 'DoS',
            severity: 'Critical',
            confidence: 0.99
        };
    }
    
    return { triggered: false };
};
