from app import db, login_manager
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class User(db.Model, UserMixin):
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='Security Analyst')  # Admin or Security Analyst
    profile_pic = db.Column(db.String(200), nullable=False, default='default.svg')
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    
    # Relationships
    logs = db.relationship('SystemLog', backref='user', lazy=True, cascade="all, delete-orphan")
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
        
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
        
    @property
    def is_admin(self):
        return self.role == 'Admin'
        
    def to_dict(self):
        return {
            'id': self.id,
            'username': self.username,
            'email': self.email,
            'role': self.role,
            'profile_pic': self.profile_pic,
            'created_at': self.created_at.strftime('%Y-%m-%d %H:%M:%S')
        }

    @classmethod
    def initialize_defaults(cls):
        if cls.query.first() is None:
            admin = cls(username='admin', email='admin@ainids.local', role='Admin')
            admin.set_password('password123')
            db.session.add(admin)
            
            analyst = cls(username='analyst', email='analyst@ainids.local', role='Security Analyst')
            analyst.set_password('password123')
            db.session.add(analyst)
            
            db.session.commit()

