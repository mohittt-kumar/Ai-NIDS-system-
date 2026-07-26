from app import db
import json

class AIPrediction(db.Model):
    __tablename__ = 'ai_predictions'
    
    id = db.Column(db.Integer, primary_key=True)
    packet_id = db.Column(db.Integer, db.ForeignKey('packets.id'), nullable=False)
    predicted_label = db.Column(db.String(50), nullable=False)
    confidence = db.Column(db.Float, nullable=False)
    feature_values = db.Column(db.Text, nullable=False)  # JSON-encoded features
    
    def set_features(self, features_dict):
        self.feature_values = json.dumps(features_dict)
        
    def get_features(self):
        try:
            return json.loads(self.feature_values)
        except Exception:
            return {}
            
    def to_dict(self):
        return {
            'id': self.id,
            'packet_id': self.packet_id,
            'predicted_label': self.predicted_label,
            'confidence': round(self.confidence, 4),
            'features': self.get_features()
        }
