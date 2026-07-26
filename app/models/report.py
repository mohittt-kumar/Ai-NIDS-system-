from app import db
from datetime import datetime

class Report(db.Model):
    __tablename__ = 'reports'
    
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    name = db.Column(db.String(100), nullable=False)
    report_type = db.Column(db.String(10), nullable=False)  # PDF or CSV
    filepath = db.Column(db.String(255), nullable=False)
    generated_by = db.Column(db.String(50), nullable=False)
    
    def to_dict(self):
        return {
            'id': self.id,
            'timestamp': self.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
            'name': self.name,
            'report_type': self.report_type,
            'filepath': self.filepath,
            'generated_by': self.generated_by
        }
