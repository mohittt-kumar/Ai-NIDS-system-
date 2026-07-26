from flask import Blueprint, render_template, redirect, url_for, request, flash, jsonify
from flask_login import login_user, logout_user, login_required, current_user
from app.models.user import User
from app.services.logger import log_event
from functools import wraps
from app import db

auth_bp = Blueprint('auth', __name__)

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            return jsonify({'error': 'Unauthorized: Admin privileges required'}), 403
        return f(*args, **kwargs)
    return decorated_function

@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('views.dashboard'))
        
    if request.method == 'POST':
        # API login support
        if request.headers.get('Content-Type') == 'application/json':
            data = request.get_json(silent=True) or {}
            username = data.get('username')
            password = data.get('password')
            is_api = True
        else:
            username = request.form.get('username')
            password = request.form.get('password')
            is_api = False
            
        user = User.query.filter_by(username=username).first()
        
        if user and user.check_password(password):
            login_user(user)
            log_event('Login', 'INFO', f"User '{username}' logged in successfully.", user.id)
            if is_api:
                return jsonify({'success': True, 'redirect': url_for('views.dashboard')})
            return redirect(url_for('views.dashboard'))
        else:
            log_event('Login', 'WARNING', f"Failed login attempt for username '{username}'.")
            if is_api:
                return jsonify({'success': False, 'error': 'Invalid credentials'}), 401
            flash('Invalid username or password.', 'danger')
            
    return render_template('login.html')

@auth_bp.route('/logout')
@login_required
def logout():
    username = current_user.username
    uid = current_user.id
    logout_user()
    log_event('Login', 'INFO', f"User '{username}' logged out.", uid)
    flash('You have been logged out.', 'info')
    return redirect(url_for('auth.login'))

@auth_bp.route('/change_password', methods=['POST'])
@login_required
def change_password():
    data = request.get_json(silent=True) or {}
    old_password = data.get('old_password')
    new_password = data.get('new_password')
    
    if not old_password or not new_password:
        return jsonify({'success': False, 'error': 'Missing password fields.'}), 400
        
    user = User.query.get(current_user.id)
    if not user.check_password(old_password):
        return jsonify({'success': False, 'error': 'Incorrect current password.'}), 400
        
    try:
        user.set_password(new_password)
        db.session.commit()
        log_event('System', 'INFO', f"Password updated for user '{user.username}'.", user.id)
        return jsonify({'success': True, 'message': 'Password changed successfully.'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500
