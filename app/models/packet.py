from app import db
from datetime import datetime

class Packet(db.Model):
    __tablename__ = 'packets'
    
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    src_ip = db.Column(db.String(45), nullable=False)
    dst_ip = db.Column(db.String(45), nullable=False)
    protocol = db.Column(db.String(10), nullable=False)  # TCP, UDP, ICMP, etc.
    length = db.Column(db.Integer, nullable=False)
    payload_preview = db.Column(db.Text, nullable=True)
    is_malicious = db.Column(db.Boolean, nullable=False, default=False)
    prediction = db.Column(db.String(50), nullable=False, default='Normal')
    confidence = db.Column(db.Float, nullable=False, default=1.0)
    severity = db.Column(db.String(20), nullable=False, default='Low')  # Low, Medium, High, Critical
    
    # Relationships
    alerts = db.relationship('Alert', backref='packet', lazy=True, cascade="all, delete-orphan")
    ai_prediction = db.relationship('AIPrediction', backref='packet', uselist=False, lazy=True, cascade="all, delete-orphan")
    
    def to_dict(self):
        return {
            'id': self.id,
            'timestamp': self.timestamp.strftime('%Y-%m-%d %H:%M:%S.%f')[:-3],
            'src_ip': self.src_ip,
            'dst_ip': self.dst_ip,
            'protocol': self.protocol,
            'length': self.length,
            'payload_preview': self.payload_preview or '',
            'is_malicious': self.is_malicious,
            'prediction': self.prediction,
            'confidence': round(self.confidence, 4),
            'severity': self.severity
        }
