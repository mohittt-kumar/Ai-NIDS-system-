from flask import Blueprint, render_template, redirect, url_for
from flask_login import login_required, current_user
from app.models.user import User
from app import db

views_bp = Blueprint('views', __name__)

def provision_default_users():
    """Auto-provision default accounts if database is empty."""
    if User.query.first() is None:
        # Create Admin
        admin = User(username='admin', email='admin@ainids.local', role='Admin')
        admin.set_password('password123')
        db.session.add(admin)
        
        # Create Analyst
        analyst = User(username='analyst', email='analyst@ainids.local', role='Security Analyst')
        analyst.set_password('password123')
        db.session.add(analyst)
        
        db.session.commit()
        print("Default users provisioned: admin/password123, analyst/password123")

@views_bp.route('/')
def home():
    provision_default_users()
    if current_user.is_authenticated:
        return redirect(url_for('views.dashboard'))
    return render_template('home.html')

@views_bp.route('/about')
def about():
    return render_template('about.html')

@views_bp.route('/features')
def features():
    return render_template('features.html')

@views_bp.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html')

@views_bp.route('/monitor')
@login_required
def monitor():
    return render_template('monitor.html')

@views_bp.route('/threats')
@login_required
def threats():
    return render_template('threats.html')

@views_bp.route('/alerts')
@login_required
def alerts():
    return render_template('alerts.html')

@views_bp.route('/reports')
@login_required
def reports():
    return render_template('reports.html')

@views_bp.route('/profile')
@login_required
def profile():
    return render_template('profile.html')

@views_bp.route('/settings')
@login_required
def settings():
    return render_template('settings.html')

@views_bp.route('/admin')
@login_required
def admin():
    if not current_user.is_admin:
        return redirect(url_for('views.dashboard'))
    return render_template('admin.html')
