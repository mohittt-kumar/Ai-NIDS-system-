from app import db
from datetime import datetime

class SystemLog(db.Model):
    __tablename__ = 'system_logs'
    
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    log_type = db.Column(db.String(20), nullable=False)  # Packet, Alert, System, Login
    level = db.Column(db.String(10), nullable=False, default='INFO')  # INFO, WARNING, ERROR
    message = db.Column(db.Text, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    
    def to_dict(self):
        return {
            'id': self.id,
            'timestamp': self.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
            'log_type': self.log_type,
            'level': self.level,
            'message': self.message,
            'user_id': self.user_id
        }
