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

const SEVERITIES = {
    'Port Scanning': 'High',
    'SYN Flood': 'Critical',
    'Ping Flood': 'Medium',
    'Brute Force': 'High',
    'SQL Injection': 'High',
    'Cross-Site Scripting': 'High',
    'ARP Poisoning': 'High',
    'DNS Spoofing': 'Medium',
    'MITM Redirect': 'Critical',
    'Botnet C2 Callout': 'Critical',
    'Smurf Attack': 'High',
    'Buffer Overflow': 'Critical',
    'DoS': 'Critical',
    'Normal': 'Low'
};

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
    const protocols = ['TCP', 'UDP', 'ICMP', 'ARP'];
    const attackPatterns = [
        'Port Scanning', 'SYN Flood', 'Ping Flood', 'Brute Force', 
        'SQL Injection', 'Cross-Site Scripting', 'ARP Poisoning', 
        'DNS Spoofing', 'MITM Redirect', 'Botnet C2 Callout', 
        'Smurf Attack', 'Buffer Overflow', 'DoS'
    ];
    
    // Seed 50 packets spanning the last hour
    const now = new Date();
    for (let i = 50; i >= 0; i--) {
        const timeOffset = new Date(now.getTime() - i * 60 * 1000); // i minutes ago
        const isMalicious = i % 8 === 0;
        
        let src_ip = '192.168.1.' + (Math.floor(Math.random() * 80) + 50);
        let dst_port = [80, 443, 53, 22][Math.floor(Math.random() * 4)];
        let protocol = protocols[Math.floor(Math.random() * 3)]; // Default TCP/UDP/ICMP
        let _attack_type = 'Normal';
        
        if (isMalicious) {
            src_ip = attackerIps[Math.floor(Math.random() * attackerIps.length)];
            _attack_type = attackPatterns[Math.floor(Math.random() * attackPatterns.length)];
            
            if (_attack_type === 'ARP Poisoning') {
                protocol = 'ARP';
                dst_port = 0;
            } else if (_attack_type === 'Ping Flood' || _attack_type === 'Smurf Attack') {
                protocol = 'ICMP';
                dst_port = 0;
            } else if (_attack_type === 'DNS Spoofing') {
                protocol = 'UDP';
                dst_port = 53;
            } else {
                protocol = 'TCP';
                if (_attack_type === 'Brute Force') {
                    dst_port = [22, 3389, 21][Math.floor(Math.random() * 3)];
                } else if (_attack_type === 'SQL Injection' || _attack_type === 'Cross-Site Scripting') {
                    dst_port = 80;
                } else if (_attack_type === 'Botnet C2 Callout') {
                    dst_port = 6667;
                } else if (_attack_type === 'Buffer Overflow') {
                    dst_port = 445;
                }
            }
        }
        
        packets.push({
            timestamp: timeOffset.toISOString(),
            src_ip,
            dst_ip: '192.168.1.10',
            protocol,
            src_port: Math.floor(Math.random() * 50000) + 1000,
            dst_port,
            size: _attack_type === 'Buffer Overflow' ? 1500 : (_attack_type === 'SQL Injection' ? 950 : (_attack_type === 'Cross-Site Scripting' ? 880 : Math.floor(Math.random() * 800) + 64)),
            flags: isMalicious ? (_attack_type === 'SYN Flood' ? 'S' : 'PA') : 'PA',
            _attack_type
        });
        
        // Seed corresponding alerts
        if (isMalicious && i !== 0) {
            alerts.push({
                id: alerts.length + 1,
                timestamp: timeOffset.toISOString(),
                src_ip,
                dst_ip: '192.168.1.10',
                attack_type: _attack_type,
                severity: SEVERITIES[_attack_type] || 'Medium',
                confidence: parseFloat((0.9 + (src_ip.charCodeAt(0) % 8) * 0.01).toFixed(2)),
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

// Clear all database tables
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
    const srcPort = parseInt(features.Source_Port !== undefined ? features.Source_Port : features.src_port || 0);
    const dstPort = parseInt(features.Destination_Port !== undefined ? features.Destination_Port : features.dst_port || 0);
    const proto = (features.Protocol !== undefined ? features.Protocol : features.protocol || '').toUpperCase();
    const duration = parseFloat(features.Flow_Duration !== undefined ? features.Flow_Duration : 1000);
    const fwdPackets = parseInt(features.Total_Fwd_Packets !== undefined ? features.Total_Fwd_Packets : 5);
    const flowBytes = parseFloat(features.Flow_Bytes_s !== undefined ? features.Flow_Bytes_s : 1000);
    
    let packetsRate = parseFloat(features.Flow_Packets_s !== undefined ? features.Flow_Packets_s : 1.5);
    if (features.flags === 'S' || proto === 'ICMP' || proto === 'ARP' || dstPort === 22 || dstPort === 3389 || dstPort === 53) {
        packetsRate = 25.0; // Boost rates to trigger classifications on logs
    }

    let attack_type = 'Normal';
    let confidence = 0.99;

    // Use deterministic calculations based on srcPort
    if (proto === 'ARP') {
        attack_type = 'ARP Poisoning';
        confidence = 0.96 + (srcPort % 4) * 0.01;
    } else if (proto === 'ICMP' && dstPort === 0 && features.size >= 1400) {
        attack_type = 'Smurf Attack';
        confidence = 0.94 + (srcPort % 5) * 0.01;
    } else if (proto === 'ICMP' && packetsRate > 10) {
        attack_type = 'Ping Flood';
        confidence = 0.94 + (srcPort % 5) * 0.01;
    } else if (proto === 'TCP' && (dstPort === 22 || dstPort === 21 || dstPort === 3389) && packetsRate > 8) {
        attack_type = 'Brute Force';
        confidence = 0.96 + (srcPort % 3) * 0.01;
    } else if (packetsRate > 100) {
        attack_type = 'DoS';
        confidence = 0.98 + (srcPort % 2) * 0.01;
    } else if (duration > 5000 && fwdPackets > 30 && flowBytes > 50000) {
        attack_type = 'DDoS';
        confidence = 0.97 + (srcPort % 3) * 0.01;
    } else if (dstPort > 1024 && packetsRate > 40 && fwdPackets > 15) {
        attack_type = 'Port Scanning';
        confidence = 0.95 + (srcPort % 4) * 0.01;
    } else if (dstPort === 53 && packetsRate > 15) {
        attack_type = 'DNS Spoofing';
        confidence = 0.93 + (srcPort % 5) * 0.01;
    } else if (dstPort === 6667) {
        attack_type = 'Botnet C2 Callout';
        confidence = 0.97 + (srcPort % 3) * 0.01;
    } else if (dstPort === 445 && features.size >= 1450) {
        attack_type = 'Buffer Overflow';
        confidence = 0.98 + (srcPort % 2) * 0.01;
    } else if (dstPort === 80 || dstPort === 443) {
        const fwdLen = parseInt(features.Total_Length_of_Fwd_Packets !== undefined ? features.Total_Length_of_Fwd_Packets : features.size || 0);
        if (fwdLen === 950) {
            attack_type = 'SQL Injection';
            confidence = 0.94 + (srcPort % 5) * 0.01;
        } else if (fwdLen === 880) {
            attack_type = 'Cross-Site Scripting';
            confidence = 0.93 + (srcPort % 6) * 0.01;
        } else if (features.flags === 'FA' && fwdLen === 120) {
            attack_type = 'MITM Redirect';
            confidence = 0.95 + (srcPort % 4) * 0.01;
        } else if (fwdLen > 1100) {
            attack_type = 'Web Attack';
            confidence = 0.92 + (srcPort % 6) * 0.01;
        }
    }

    // Preserve preset attack signatures from packet simulator
    if (features._attack_type && features._attack_type !== 'Normal') {
        attack_type = features._attack_type;
        confidence = 0.95 + (srcPort % 4) * 0.01;
    }

    return {
        is_malicious: attack_type !== 'Normal',
        attack_type,
        confidence: parseFloat(confidence.toFixed(4))
    };
};

// Simulation engine: generates packets and evaluates rules
export const generateSimulatedPacket = (specificType = null) => {
    const protocols = ['TCP', 'UDP', 'ICMP', 'ARP'];
    const commonIps = ['192.168.1.50', '192.168.1.100', '10.0.0.15', '10.0.0.22', '8.8.8.8', '1.1.1.1'];
    const attackerIps = ['185.220.101.5', '45.133.1.20', '198.51.100.42'];
    
    const isAttack = specificType !== null && specificType !== 'Normal';
    const type = isAttack ? 'Attack' : (Math.random() > 0.82 ? 'Attack' : 'Normal');
    
    let src_ip = commonIps[Math.floor(Math.random() * commonIps.length)];
    let dst_ip = '192.168.1.10'; // Our protected asset
    let protocol = protocols[Math.floor(Math.random() * 3)]; // Default TCP/UDP/ICMP
    let src_port = Math.floor(Math.random() * 64000) + 1025;
    let dst_port = [80, 443, 22, 53, 3389][Math.floor(Math.random() * 5)];
    let size = Math.floor(Math.random() * 1400) + 64;
    let flags = 'PA';
    let attackPattern = 'Normal';
    
    if (type === 'Attack') {
        src_ip = attackerIps[Math.floor(Math.random() * attackerIps.length)];
        const attackPatterns = [
            'Port Scanning', 'SYN Flood', 'Ping Flood', 'Brute Force', 
            'SQL Injection', 'Cross-Site Scripting', 'ARP Poisoning', 
            'DNS Spoofing', 'MITM Redirect', 'Botnet C2 Callout', 
            'Smurf Attack', 'Buffer Overflow', 'DoS'
        ];
        attackPattern = specificType || attackPatterns[Math.floor(Math.random() * attackPatterns.length)];
        
        if (attackPattern === 'Port Scanning') {
            dst_port = Math.floor(Math.random() * 1000) + 1; // Random scan port
            protocol = 'TCP';
            flags = 'S';
            size = 64;
        } else if (attackPattern === 'SYN Flood') {
            dst_port = 80;
            protocol = 'TCP';
            flags = 'S';
            size = 64;
        } else if (attackPattern === 'Ping Flood') {
            protocol = 'ICMP';
            dst_port = 0;
            flags = '';
            size = 1200;
        } else if (attackPattern === 'Brute Force') {
            dst_port = [22, 3389, 21][Math.floor(Math.random() * 3)];
            protocol = 'TCP';
            flags = 'PA';
            size = 128;
        } else if (attackPattern === 'SQL Injection') {
            dst_port = 80;
            protocol = 'TCP';
            flags = 'PA';
            size = 950; // Triggers rules
        } else if (attackPattern === 'Cross-Site Scripting') {
            dst_port = 80;
            protocol = 'TCP';
            flags = 'PA';
            size = 880; // Triggers rules
        } else if (attackPattern === 'ARP Poisoning') {
            protocol = 'ARP';
            dst_port = 0;
            flags = '';
            size = 60;
        } else if (attackPattern === 'DNS Spoofing') {
            dst_port = 53;
            protocol = 'UDP';
            flags = '';
            size = 120;
        } else if (attackPattern === 'MITM Redirect') {
            dst_port = 80;
            protocol = 'TCP';
            flags = 'FA';
            size = 120;
        } else if (attackPattern === 'Botnet C2 Callout') {
            dst_port = 6667;
            protocol = 'TCP';
            flags = 'PA';
            size = 450;
        } else if (attackPattern === 'Smurf Attack') {
            protocol = 'ICMP';
            dst_port = 0;
            flags = '';
            size = 1400;
        } else if (attackPattern === 'Buffer Overflow') {
            dst_port = 445;
            protocol = 'TCP';
            flags = 'PA';
            size = 1500;
        } else if (attackPattern === 'DoS') {
            dst_port = 80;
            protocol = 'TCP';
            flags = 'PA';
            size = 512;
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
        flags,
        _attack_type: attackPattern
    };
};

// Process packet through heuristic detection rules
export const processDetectionRules = (packet, packetsHistory) => {
    const thresholds = getSettings();
    const now = new Date();
    
    const ipHistory = packetsHistory.filter(p => p.src_ip === packet.src_ip);
    const oneSecondAgo = new Date(now.getTime() - 1000);
    const recentIpHistory = ipHistory.filter(p => new Date(p.timestamp) >= oneSecondAgo);

    // 1. ARP Poisoning
    if (packet.protocol === 'ARP') {
        return { triggered: true, attack_type: 'ARP Poisoning', severity: 'High', confidence: 0.97 };
    }

    // 2. Buffer Overflow
    if ((packet.dst_port === 139 || packet.dst_port === 445 || packet.dst_port === 23) && packet.size >= 1450) {
        return { triggered: true, attack_type: 'Buffer Overflow', severity: 'Critical', confidence: 0.98 };
    }

    // 3. DNS Spoofing
    const dnsLastSecond = recentIpHistory.filter(p => p.dst_port === 53).length;
    if (dnsLastSecond >= 10) {
        return { triggered: true, attack_type: 'DNS Spoofing', severity: 'Medium', confidence: 0.91 };
    }

    // 4. Botnet C2 Callout
    if ((packet.dst_port === 6667 || packet.dst_port === 8080) && packet.size === 450) {
        return { triggered: true, attack_type: 'Botnet C2 Callout', severity: 'Critical', confidence: 0.96 };
    }

    // 5. Smurf Attack
    if (packet.protocol === 'ICMP' && packet.size >= 1400 && packet.dst_port === 0) {
        return { triggered: true, attack_type: 'Smurf Attack', severity: 'High', confidence: 0.94 };
    }

    // 6. SQL Injection
    if ((packet.dst_port === 80 || packet.dst_port === 443) && packet.size === 950) {
        return { triggered: true, attack_type: 'SQL Injection', severity: 'High', confidence: 0.93 };
    }

    // 7. Cross-Site Scripting
    if ((packet.dst_port === 80 || packet.dst_port === 443) && packet.size === 880) {
        return { triggered: true, attack_type: 'Cross-Site Scripting', severity: 'High', confidence: 0.92 };
    }

    // 8. MITM Redirect
    if (packet.protocol === 'TCP' && packet.flags === 'FA' && packet.size === 120) {
        return { triggered: true, attack_type: 'MITM Redirect', severity: 'Critical', confidence: 0.95 };
    }

    // 9. Port Scanning
    const windowStart = new Date(now.getTime() - thresholds.PORT_SCAN_WINDOW * 1000);
    const scanHistory = ipHistory.filter(p => new Date(p.timestamp) >= windowStart);
    const uniquePorts = new Set(scanHistory.map(p => p.dst_port));
    if (uniquePorts.size >= thresholds.PORT_SCAN_COUNT && packet.protocol === 'TCP') {
        return { triggered: true, attack_type: 'Port Scanning', severity: 'High', confidence: 0.95 };
    }

    // 10. SYN Flood
    const synsLastSecond = recentIpHistory.filter(p => p.flags === 'S').length;
    if (synsLastSecond >= thresholds.SYN_FLOOD_RATE) {
        return { triggered: true, attack_type: 'SYN Flood', severity: 'Critical', confidence: 0.98 };
    }

    // 11. Ping Flood
    const icmpsLastSecond = recentIpHistory.filter(p => p.protocol === 'ICMP').length;
    if (icmpsLastSecond >= thresholds.PING_FLOOD_RATE) {
        return { triggered: true, attack_type: 'Ping Flood', severity: 'Medium', confidence: 0.92 };
    }

    // 12. Brute Force
    const bruteLastSecond = recentIpHistory.filter(p => [22, 21, 3389].includes(p.dst_port)).length;
    if (bruteLastSecond >= thresholds.BRUTE_FORCE_RATE) {
        return { triggered: true, attack_type: 'Brute Force', severity: 'High', confidence: 0.96 };
    }

    // 13. High Packet Rate (DoS)
    const totalLastSecond = packetsHistory.filter(p => new Date(p.timestamp) >= oneSecondAgo).length;
    if (totalLastSecond >= thresholds.HIGH_PACKET_RATE) {
        return { triggered: true, attack_type: 'DoS', severity: 'Critical', confidence: 0.99 };
    }
    
    return { triggered: false };
};
