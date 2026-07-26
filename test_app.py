import unittest
import os
from app import create_app, db
from app.models.user import User
from app.models.packet import Packet
from app.models.alert import Alert
from app.models.setting import Setting
from app.services.ai_engine import AIEngine
from app.services.detection_engine import DetectionEngine

class TestingConfig:
    TESTING = True
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SECRET_KEY = 'test-security-key'
    
    # Path mappings
    BASE_DIR = os.path.abspath(os.path.dirname(__file__))
    MODEL_DIR = os.path.join(BASE_DIR, 'trained_model')
    DATASET_DIR = os.path.join(BASE_DIR, 'dataset')

class LAINIDSTestCase(unittest.TestCase):
    def setUp(self):
        # Configure app to use testing database directly at init
        self.app = create_app(TestingConfig)
        self.app_context = self.app.app_context()
        self.app_context.push()
        
        # Create database
        db.create_all()
        Setting.initialize_defaults()
        
    def tearDown(self):
        db.session.remove()
        db.drop_all()
        self.app_context.pop()
        
    def test_database_initialization(self):
        """Verify that default settings and schemas build."""
        # Verify default thresholds exist
        port_scan_count = Setting.get_int('PORT_SCAN_COUNT')
        self.assertEqual(port_scan_count, 15)
        
        monitoring_active = Setting.get_val('MONITORING_ACTIVE')
        self.assertEqual(monitoring_active, 'False')
        
    def test_user_creation_and_hashing(self):
        """Verify password hashing and checks."""
        user = User(username='test_analyst', email='analyst@nids.local', role='Security Analyst')
        user.set_password('my_secure_password_123')
        db.session.add(user)
        db.session.commit()
        
        # Query user
        queried = User.query.filter_by(username='test_analyst').first()
        self.assertIsNotNone(queried)
        self.assertTrue(queried.check_password('my_secure_password_123'))
        self.assertFalse(queried.check_password('wrong_password'))
        self.assertFalse(queried.is_admin)

    def test_ai_engine_predictions(self):
        """Verify the ML prediction interface processes features."""
        engine = AIEngine()
        # Normal packet features
        normal_feats = {
            'Source_Port': 443, 'Destination_Port': 80, 'Protocol': 6, 
            'Flow_Duration': 1.2, 'Total_Fwd_Packets': 5, 'Total_Backward_Packets': 5, 
            'Total_Length_of_Fwd_Packets': 400.0, 'Fwd_Packet_Length_Max': 200.0, 
            'Bwd_Packet_Length_Max': 200.0, 'Flow_Bytes_s': 800.0, 'Flow_Packets_s': 8.3
        }
        label, conf = engine.predict(normal_feats)
        self.assertIn(label, ['Normal', 'DoS', 'DDoS', 'Port Scan', 'Bot', 'Brute Force', 'Web Attack'])
        self.assertTrue(0.0 <= conf <= 1.0)
        
    def test_detection_engine_heuristics(self):
        """Verify heuristic rules triggers (e.g. suspicious ports)."""
        rule_engine = DetectionEngine()
        
        # 1. Test suspicious port (SMB port 445)
        pkt1 = Packet(
            src_ip='192.168.1.5',
            dst_ip='192.168.1.20',
            protocol='TCP',
            length=64,
            payload_preview='SPort: 2315 -> DPort: 445 | SMB Connection Probe'
        )
        alerts1 = rule_engine.process_packet(pkt1)
        self.assertEqual(len(alerts1), 1)
        self.assertEqual(alerts1[0]['attack_type'], 'Suspicious Ports')
        self.assertEqual(alerts1[0]['severity'], 'Medium')

        # 2. Test ICMP Flood
        pkt_icmp = Packet(
            src_ip='192.168.1.100',
            dst_ip='192.168.1.1',
            protocol='ICMP',
            length=64,
            payload_preview='SPort: 0 -> DPort: 0 | ICMP Echo Request'
        )
        
        # Exceed threshold (default rate is 10/sec, let's inject 12 packets)
        alerts2 = []
        for _ in range(12):
            alerts2.extend(rule_engine.process_packet(pkt_icmp))
            
        # At least one iteration should trigger the flood alert
        self.assertTrue(any(a['attack_type'] == 'ICMP Flood' for a in alerts2))

if __name__ == '__main__':
    unittest.main()
