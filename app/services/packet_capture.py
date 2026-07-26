import threading
import time
import random
import sys
from datetime import datetime
from app import db
from app.models.packet import Packet
from app.models.alert import Alert
from app.models.threat import Threat
from app.models.setting import Setting
from app.models.prediction import AIPrediction
from app.services.detection_engine import DetectionEngine
from app.services.ai_engine import AIEngine
from app.services.logger import log_event

try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw
    SCAPY_AVAILABLE = True
except Exception:
    SCAPY_AVAILABLE = False

class PacketCaptureService:
    _instance = None
    _lock = threading.Lock()
    
    def __new__(cls, *args, **kwargs):
        with cls._lock:
            if not cls._instance:
                cls._instance = super(PacketCaptureService, cls).__new__(cls, *args, **kwargs)
                cls._instance.thread = None
                cls._instance.stop_event = threading.Event()
                cls._instance.app = None
                cls._instance.running = False
        return cls._instance
        
    def start(self, app):
        with self._lock:
            if self.running:
                return
            self.app = app
            self.stop_event.clear()
            self.running = True
            
            with self.app.app_context():
                Setting.set_val('MONITORING_ACTIVE', 'True')
                log_event('System', 'INFO', 'Packet capture thread started.')
                
            self.thread = threading.Thread(target=self._capture_loop, daemon=True)
            self.thread.start()
            
    def stop(self):
        with self._lock:
            if not self.running:
                return
            self.stop_event.set()
            self.running = False
            
            if self.app:
                with self.app.app_context():
                    Setting.set_val('MONITORING_ACTIVE', 'False')
                    log_event('System', 'INFO', 'Packet capture thread stopped.')
            
    def _capture_loop(self):
        with self.app.app_context():
            scapy_active = SCAPY_AVAILABLE and (Setting.get_val('SIMULATION_MODE') == 'False')
            
        if scapy_active:
            try:
                sniff(prn=self._process_scapy_packet, 
                      stop_filter=lambda p: self.stop_event.is_set(),
                      store=0)
            except Exception as e:
                print(f"Scapy sniffing failed: {e}. Falling back to simulation.")
                with self.app.app_context():
                    Setting.set_val('SIMULATION_MODE', 'True')
                self._run_simulation()
        else:
            self._run_simulation()
            
    def _run_simulation(self):
        attack_types = ['DoS', 'DDoS', 'Port Scan', 'Brute Force', 'Web Attack', 'ICMP Flood']
        next_attack_time = time.time() + random.uniform(8, 15)
        
        sim_ips = ['192.168.1.10', '192.168.1.15', '192.168.1.20', '10.0.0.5', '10.0.0.12']
        ext_ips = ['8.8.8.8', '1.1.1.1', '142.250.190.46', '204.79.197.200', '151.101.1.69']
        malicious_ips = ['198.51.100.42', '203.0.113.110', '185.220.101.4', '45.227.254.12']
        
        while not self.stop_event.is_set():
            time.sleep(random.uniform(0.2, 0.6))
            
            with self.app.app_context():
                try:
                    if Setting.get_val('MONITORING_ACTIVE') == 'False':
                        self.stop()
                        break
                        
                    now = time.time()
                    if now >= next_attack_time:
                        attack_choice = random.choice(attack_types)
                        self._inject_attack_burst(attack_choice, sim_ips, ext_ips, malicious_ips)
                        next_attack_time = now + random.uniform(15, 30)
                        continue
                        
                    src = random.choice(sim_ips)
                    dst = random.choice(ext_ips)
                    proto = random.choice(['TCP', 'UDP', 'ICMP'])
                    sport = random.randint(1024, 65535)
                    dport = random.choice([80, 443, 53, 123])
                    
                    if proto == 'ICMP':
                        payload = "SPort: 0 -> DPort: 0 | ICMP Echo Request"
                        length = 64
                    else:
                        payload = f"SPort: {sport} -> DPort: {dport} | HTTP GET /index.html" if dport in [80, 443] else f"SPort: {sport} -> DPort: {dport} | DNS Query"
                        length = random.randint(64, 1500)
                        
                    self._create_and_process_packet(src, dst, proto, length, payload, dport, sport, 'Normal')
                except Exception as e:
                    print(f"Error in simulation loop: {e}", file=sys.stderr)
                    db.session.rollback()
                    
    def _inject_attack_burst(self, attack_type, sim_ips, ext_ips, malicious_ips):
        victim_ip = random.choice(sim_ips)
        attacker_ip = random.choice(malicious_ips)
        
        if attack_type == 'DoS':
            port = random.choice([80, 443])
            for _ in range(25):
                sport = random.randint(1024, 65535)
                payload = f"SPort: {sport} -> DPort: {port} | Flags: S | TCP Connection Request"
                self._create_and_process_packet(attacker_ip, victim_ip, 'TCP', 64, payload, port, sport, 'DoS')
                time.sleep(0.02)
                
        elif attack_type == 'DDoS':
            port = random.choice([80, 443, 8080])
            for _ in range(30):
                fake_src = f"172.16.20.{random.randint(1, 254)}"
                sport = random.randint(1024, 65535)
                payload = f"SPort: {sport} -> DPort: {port} | Flags: S | UDP Flood / SYN Flood"
                self._create_and_process_packet(fake_src, victim_ip, 'TCP', 54, payload, port, sport, 'DDoS')
                time.sleep(0.02)
                
        elif attack_type == 'Port Scan':
            start_port = random.randint(20, 1000)
            for port in range(start_port, start_port + 20):
                sport = random.randint(1024, 65535)
                payload = f"SPort: {sport} -> DPort: {port} | Flags: S | Port Scan Probe"
                self._create_and_process_packet(attacker_ip, victim_ip, 'TCP', 40, payload, port, sport, 'Port Scan')
                time.sleep(0.02)
                
        elif attack_type == 'ICMP Flood':
            for _ in range(20):
                payload = "SPort: 0 -> DPort: 0 | ICMP Echo request (Ping Flood)"
                self._create_and_process_packet(attacker_ip, victim_ip, 'ICMP', 64, payload, 0, 0, 'DoS')
                time.sleep(0.02)
                
        elif attack_type == 'Brute Force':
            port = random.choice([22, 3389, 21])
            sport = random.randint(1024, 65535)
            for _ in range(12):
                payload = f"SPort: {sport} -> DPort: {port} | SSH/RDP login attempt: admin"
                self._create_and_process_packet(attacker_ip, victim_ip, 'TCP', 80, payload, port, sport, 'Brute Force')
                time.sleep(0.05)
                
        elif attack_type == 'Web Attack':
            sport = random.randint(1024, 65535)
            sql_payloads = [
                "SPort: {sport} -> DPort: 80 | GET /products?id=1' UNION SELECT NULL,username,pass FROM users--",
                "SPort: {sport} -> DPort: 443 | GET /login?user=<script>alert('XSS')</script>&pass=123",
                "SPort: {sport} -> DPort: 80 | POST /upload payload=../../etc/passwd"
            ]
            for p in sql_payloads:
                payload = p.format(sport=sport)
                self._create_and_process_packet(attacker_ip, victim_ip, 'TCP', 1200, payload, 80, sport, 'Web Attack')
                time.sleep(0.1)

    def _process_scapy_packet(self, scapy_pkt):
        if not self.running or self.stop_event.is_set():
            return
            
        if IP in scapy_pkt:
            src = scapy_pkt[IP].src
            dst = scapy_pkt[IP].dst
            proto = 'TCP' if TCP in scapy_pkt else ('UDP' if UDP in scapy_pkt else ('ICMP' if ICMP in scapy_pkt else 'Other'))
            length = len(scapy_pkt)
            sport, dport = 0, 0
            flags_str = ""
            
            if TCP in scapy_pkt:
                sport = scapy_pkt[TCP].sport
                dport = scapy_pkt[TCP].dport
                flags_str = f"Flags: {str(scapy_pkt[TCP].flags)} "
            elif UDP in scapy_pkt:
                sport = scapy_pkt[UDP].sport
                dport = scapy_pkt[UDP].dport
                
            payload_str = ""
            if Raw in scapy_pkt:
                try:
                    payload_str = scapy_pkt[Raw].load.decode('utf-8', errors='ignore')[:100]
                except Exception:
                    payload_str = str(scapy_pkt[Raw].load)[:100]
                    
            payload = f"SPort: {sport} -> DPort: {dport} | {flags_str}{payload_str}"
            
            with self.app.app_context():
                try:
                    self._create_and_process_packet(src, dst, proto, length, payload, dport, sport, 'Normal')
                except Exception as e:
                    db.session.rollback()
                    print(f"Error processing Scapy packet: {e}", file=sys.stderr)

    def _create_and_process_packet(self, src, dst, proto, length, payload, dport, sport, raw_intent='Normal'):
        pkt = Packet(
            timestamp=datetime.utcnow(),
            src_ip=src,
            dst_ip=dst,
            protocol=proto,
            length=length,
            payload_preview=payload
        )
        db.session.add(pkt)
        db.session.flush()
        
        proto_map = {'TCP': 6, 'UDP': 17, 'ICMP': 1, 'Other': 0}
        
        features = {
            'Source_Port': int(sport),
            'Destination_Port': int(dport),
            'Protocol': proto_map.get(proto, 6),
            'Flow_Duration': 0.01 if raw_intent != 'Normal' else 0.5,
            'Total_Fwd_Packets': 5 if raw_intent != 'Normal' else 2,
            'Total_Backward_Packets': 2 if raw_intent != 'Normal' else 2,
            'Total_Length_of_Fwd_Packets': float(length),
            'Fwd_Packet_Length_Max': float(length),
            'Bwd_Packet_Length_Max': 64.0 if proto == 'TCP' else 0.0,
            'Flow_Bytes_s': float(length * 100) if raw_intent != 'Normal' else float(length * 2),
            'Flow_Packets_s': 200.0 if raw_intent != 'Normal' else 4.0
        }
        
        ai_label, ai_conf = AIEngine().predict(features)
        heuristic_alerts = DetectionEngine().process_packet(pkt)
        
        is_malicious = False
        final_prediction = 'Normal'
        final_conf = 1.0
        final_severity = 'Low'
        alert_instances = []
        
        if ai_label != 'Normal' and ai_conf >= 0.70:
            is_malicious = True
            final_prediction = ai_label
            final_conf = ai_conf
            
            severity_map = {
                'DoS': 'Critical', 'DDoS': 'Critical',
                'Bot': 'High', 'Brute Force': 'High', 'Web Attack': 'High',
                'Port Scan': 'Medium', 'Unknown Attack': 'Medium'
            }
            final_severity = severity_map.get(ai_label, 'Medium')
            
            ai_alert = Alert(
                timestamp=datetime.utcnow(),
                src_ip=src,
                dst_ip=dst,
                attack_type=f"AI: {ai_label}",
                severity=final_severity,
                confidence=ai_conf,
                status='Active',
                packet_id=pkt.id
            )
            alert_instances.append(ai_alert)
            
            ai_pred = AIPrediction(
                packet_id=pkt.id,
                predicted_label=ai_label,
                confidence=ai_conf
            )
            ai_pred.set_features(features)
            db.session.add(ai_pred)
            
        if heuristic_alerts:
            is_malicious = True
            for alert_data in heuristic_alerts:
                rule_alert = Alert(
                    timestamp=datetime.utcnow(),
                    src_ip=src,
                    dst_ip=dst,
                    attack_type=f"Rule: {alert_data['attack_type']}",
                    severity=alert_data['severity'],
                    confidence=alert_data['confidence'],
                    status='Active',
                    packet_id=pkt.id
                )
                alert_instances.append(rule_alert)
                
                if alert_data['severity'] == 'Critical' or (alert_data['severity'] == 'High' and final_severity != 'Critical'):
                    final_severity = alert_data['severity']
                    
            if final_prediction == 'Normal':
                final_prediction = heuristic_alerts[0]['attack_type']
                final_conf = heuristic_alerts[0]['confidence']
                
        pkt.is_malicious = is_malicious
        pkt.prediction = final_prediction
        pkt.confidence = final_conf
        pkt.severity = final_severity
        
        for alert_inst in alert_instances:
            db.session.add(alert_inst)
            self._update_threat_database(alert_inst)
            log_event('Alert', alert_inst.severity, 
                      f"Intrusion detected: {alert_inst.attack_type} from {src} -> {dst}")
            
        db.session.commit()
        
    def _update_threat_database(self, alert_instance):
        threat = Threat.query.filter_by(
            source=alert_instance.src_ip,
            threat_type=alert_instance.attack_type,
            status='Active'
        ).first()
        
        if threat:
            threat.timestamp = datetime.utcnow()
            details = threat.details or ""
            count = 1
            if "Alert occurrences:" in details:
                try:
                    count = int(details.split("Alert occurrences: ")[1]) + 1
                except Exception:
                    pass
            threat.details = f"Aggregated threat actor logs. Alert occurrences: {count}"
        else:
            threat = Threat(
                timestamp=datetime.utcnow(),
                threat_type=alert_instance.attack_type,
                severity=alert_instance.severity,
                source=alert_instance.src_ip,
                status='Active',
                details="Aggregated threat actor logs. Alert occurrences: 1"
            )
            db.session.add(threat)
