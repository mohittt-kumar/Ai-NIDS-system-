from datetime import datetime
from collections import defaultdict, deque
import time
from app.models.setting import Setting

class DetectionEngine:
    _instance = None
    
    def __new__(cls, *args, **kwargs):
        if not cls._instance:
            cls._instance = super(DetectionEngine, cls).__new__(cls, *args, **kwargs)
            cls._instance.ip_traffic = defaultdict(lambda: deque(maxlen=2000))
            cls._instance.ip_ports = defaultdict(dict)
            cls._instance.ip_icmp = defaultdict(lambda: deque(maxlen=1000))
            cls._instance.ip_syn = defaultdict(lambda: deque(maxlen=1000))
            cls._instance.ip_brute = defaultdict(lambda: deque(maxlen=1000))
            cls._instance.global_traffic = deque(maxlen=5000)
            cls._instance.ip_blacklist = {'198.51.100.42', '203.0.113.110', '185.220.101.4'}
        return cls._instance

    def process_packet(self, packet):
        alerts = []
        now_epoch = time.time()
        src_ip = packet.src_ip
        dst_ip = packet.dst_ip
        dst_port = None
        
        # Parse destination port from payload preview
        try:
            if "DPort: " in packet.payload_preview:
                port_part = packet.payload_preview.split("DPort: ")[1].split(" |")[0]
                dst_port = int(port_part)
        except Exception:
            dst_port = 80
            
        try:
            port_scan_count = Setting.get_int('PORT_SCAN_COUNT', 15)
            port_scan_window = Setting.get_int('PORT_SCAN_WINDOW', 10)
            ping_flood_rate = Setting.get_int('PING_FLOOD_RATE', 10)
            syn_flood_rate = Setting.get_int('SYN_FLOOD_RATE', 15)
            high_packet_rate = Setting.get_int('HIGH_PACKET_RATE', 100)
            brute_force_rate = Setting.get_int('BRUTE_FORCE_RATE', 10)
        except Exception:
            port_scan_count = 15
            port_scan_window = 10
            ping_flood_rate = 10
            syn_flood_rate = 15
            high_packet_rate = 100
            brute_force_rate = 10
            
        self.global_traffic.append(now_epoch)
        self.ip_traffic[src_ip].append(now_epoch)
        
        # Blacklisted IP check
        if src_ip in self.ip_blacklist or dst_ip in self.ip_blacklist:
            alerts.append({
                'attack_type': 'Blacklisted IP',
                'severity': 'Critical',
                'confidence': 1.0,
                'details': f"Traffic involving blacklisted IP {src_ip if src_ip in self.ip_blacklist else dst_ip}"
            })
            
        # Restricted port check
        suspicious_ports = {23: "Telnet", 445: "SMB", 135: "RPC", 139: "NetBIOS", 1433: "MSSQL", 3306: "MySQL"}
        if dst_port in suspicious_ports:
            alerts.append({
                'attack_type': 'Suspicious Ports',
                'severity': 'Medium',
                'confidence': 0.95,
                'details': f"Traffic detected on restricted {suspicious_ports[dst_port]} port ({dst_port})"
            })
            
        # Port scan detection
        window_cutoff = now_epoch - port_scan_window
        if dst_port is not None:
            self.ip_ports[src_ip][dst_port] = now_epoch
            
            # Clean expired port lookups
            expired_ports = [p for p, ts in self.ip_ports[src_ip].items() if ts < window_cutoff]
            for p in expired_ports:
                self.ip_ports[src_ip].pop(p, None)
                
            if len(self.ip_ports[src_ip]) >= port_scan_count:
                alerts.append({
                    'attack_type': 'Port Scan',
                    'severity': 'Medium',
                    'confidence': 0.90,
                    'details': f"Source IP scanned {len(self.ip_ports[src_ip])} unique ports in {port_scan_window}s"
                })
                self.ip_ports[src_ip].clear()

        # Rate based check thresholds
        one_sec_cutoff = now_epoch - 1.0
        
        # Global high packet rate
        while self.global_traffic and self.global_traffic[0] < one_sec_cutoff:
            self.global_traffic.popleft()
        if len(self.global_traffic) > high_packet_rate:
            alerts.append({
                'attack_type': 'High Packet Rate',
                'severity': 'Low',
                'confidence': 0.85,
                'details': f"Total traffic rate exceeded: {len(self.global_traffic)} packets/sec"
            })
            
        # ICMP Flood
        if packet.protocol == 'ICMP':
            self.ip_icmp[src_ip].append(now_epoch)
            while self.ip_icmp[src_ip] and self.ip_icmp[src_ip][0] < one_sec_cutoff:
                self.ip_icmp[src_ip].popleft()
            
            if len(self.ip_icmp[src_ip]) > ping_flood_rate:
                alerts.append({
                    'attack_type': 'ICMP Flood',
                    'severity': 'High',
                    'confidence': 0.92,
                    'details': f"ICMP ping flood from {src_ip}: {len(self.ip_icmp[src_ip])} packets/sec"
                })
                self.ip_icmp[src_ip].clear()
                
        # TCP SYN Flood
        is_syn = packet.protocol == 'TCP' and "Flags: S " in (packet.payload_preview or "")
        if is_syn:
            self.ip_syn[src_ip].append(now_epoch)
            while self.ip_syn[src_ip] and self.ip_syn[src_ip][0] < one_sec_cutoff:
                self.ip_syn[src_ip].popleft()
                
            if len(self.ip_syn[src_ip]) > syn_flood_rate:
                alerts.append({
                    'attack_type': 'SYN Flood',
                    'severity': 'Critical',
                    'confidence': 0.95,
                    'details': f"TCP SYN Flood from {src_ip}: {len(self.ip_syn[src_ip])} SYN/sec"
                })
                self.ip_syn[src_ip].clear()
                
        # Brute Force connection rate check
        if dst_port in [22, 3389, 21]:
            self.ip_brute[src_ip].append(now_epoch)
            while self.ip_brute[src_ip] and self.ip_brute[src_ip][0] < one_sec_cutoff:
                self.ip_brute[src_ip].popleft()
                
            if len(self.ip_brute[src_ip]) > brute_force_rate:
                alerts.append({
                    'attack_type': 'Brute Force',
                    'severity': 'High',
                    'confidence': 0.88,
                    'details': f"Brute force attempts from {src_ip} on port {dst_port}: {len(self.ip_brute[src_ip])}/sec"
                })
                self.ip_brute[src_ip].clear()
                
        return alerts
