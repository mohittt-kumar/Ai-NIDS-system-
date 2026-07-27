from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from config import Config
import os

db = SQLAlchemy()
login_manager = LoginManager()
login_manager.login_view = 'auth.login'
login_manager.login_message_category = 'info'

def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)
    
    db.init_app(app)
    login_manager.init_app(app)
    
    # Ensure directories exist (skipped on Vercel's read-only filesystem)
    try:
        if os.environ.get('VERCEL') != '1':
            os.makedirs(app.instance_path, exist_ok=True)
            os.makedirs(os.path.join(os.path.dirname(app.root_path), 'trained_model'), exist_ok=True)
            os.makedirs(os.path.join(os.path.dirname(app.root_path), 'dataset'), exist_ok=True)
            os.makedirs(os.path.join(app.root_path, 'static', 'images', 'profiles'), exist_ok=True)
    except Exception as e:
        print(f"Directory creation warning: {e}")
    
    # Import routes
    from app.routes.auth import auth_bp
    from app.routes.views import views_bp
    from app.routes.api_dashboard import dashboard_bp
    from app.routes.api_packet import packet_bp
    from app.routes.api_alert import alert_bp
    from app.routes.api_admin import admin_bp
    from app.routes.api_report import report_bp
    
    # Register blueprints
    app.register_blueprint(auth_bp)
    app.register_blueprint(views_bp)
    app.register_blueprint(dashboard_bp, url_prefix='/api/dashboard')
    app.register_blueprint(packet_bp, url_prefix='/api/packet')
    app.register_blueprint(alert_bp, url_prefix='/api/alert')
    app.register_blueprint(admin_bp, url_prefix='/api/admin')
    app.register_blueprint(report_bp, url_prefix='/api/report')
    
    # Register error handlers
    @app.errorhandler(404)
    def page_not_found(e):
        from flask import render_template
        return render_template('404.html'), 404
        
    # Initialize database schemas and default seeds
    with app.app_context():
        from app.models.setting import Setting
        from app.models.user import User
        db.create_all()
        Setting.initialize_defaults()
        User.initialize_defaults()
        
    return app

