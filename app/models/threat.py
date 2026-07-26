from app import db
from datetime import datetime

class Threat(db.Model):
    __tablename__ = 'threats'
    
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    threat_type = db.Column(db.String(50), nullable=False)  # DDoS Actor, Port Scanner, Brute Forcer
    severity = db.Column(db.String(20), nullable=False)      # Low, Medium, High, Critical
    source = db.Column(db.String(45), nullable=False)        # Source IP address
    status = db.Column(db.String(20), nullable=False, default='Active')  # Active, Mitigated
    details = db.Column(db.Text, nullable=True)
    
    def to_dict(self):
        return {
            'id': self.id,
            'timestamp': self.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
            'threat_type': self.threat_type,
            'severity': self.severity,
            'source': self.source,
            'status': self.status,
            'details': self.details or ''
        }
