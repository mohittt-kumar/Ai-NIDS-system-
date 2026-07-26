from app import db
from datetime import datetime

class Alert(db.Model):
    __tablename__ = 'alerts'
    
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    src_ip = db.Column(db.String(45), nullable=False)
    dst_ip = db.Column(db.String(45), nullable=False)
    attack_type = db.Column(db.String(50), nullable=False)  # Port Scan, DoS, etc.
    severity = db.Column(db.String(20), nullable=False)  # Low, Medium, High, Critical
    confidence = db.Column(db.Float, nullable=False, default=1.0)
    status = db.Column(db.String(20), nullable=False, default='Active')  # Active, Resolved, Deleted
    packet_id = db.Column(db.Integer, db.ForeignKey('packets.id'), nullable=True)
    
    def to_dict(self):
        return {
            'id': self.id,
            'timestamp': self.timestamp.strftime('%Y-%m-%d %H:%M:%S.%f')[:-3],
            'src_ip': self.src_ip,
            'dst_ip': self.dst_ip,
            'attack_type': self.attack_type,
            'severity': self.severity,
            'confidence': round(self.confidence, 4),
            'status': self.status,
            'packet_id': self.packet_id
        }
