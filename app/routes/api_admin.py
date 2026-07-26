from flask import Blueprint, jsonify, request
from flask_login import login_required, current_user
from app.models.user import User
from app.models.log import SystemLog
from app.models.setting import Setting
from app.routes.auth import admin_required
from app.services.logger import log_event
from app import db
import os
import json

admin_bp = Blueprint('api_admin', __name__)

@admin_bp.route('/users', methods=['GET', 'POST'])
@login_required
@admin_required
def manage_users():
    if request.method == 'GET':
        users = User.query.all()
        return jsonify([u.to_dict() for u in users])
        
    if request.method == 'POST':
        data = request.get_json(silent=True) or {}
        username = data.get('username')
        email = data.get('email')
        password = data.get('password')
        role = data.get('role', 'Security Analyst')
        
        if not username or not email or not password:
            return jsonify({'success': False, 'error': 'Missing fields: username, email, password.'}), 400
            
        if User.query.filter_by(username=username).first():
            return jsonify({'success': False, 'error': f"Username '{username}' already exists."}), 400
            
        if User.query.filter_by(email=email).first():
            return jsonify({'success': False, 'error': f"Email '{email}' is already registered."}), 400
            
        try:
            new_user = User(username=username, email=email, role=role)
            new_user.set_password(password)
            db.session.add(new_user)
            db.session.commit()
            
            log_event('System', 'INFO', f"New user '{username}' (Role: {role}) created by admin '{current_user.username}'.")
            return jsonify({'success': True, 'user': new_user.to_dict()})
        except Exception as e:
            db.session.rollback()
            return jsonify({'success': False, 'error': str(e)}), 500

@admin_bp.route('/users/<int:user_id>', methods=['DELETE'])
@login_required
@admin_required
def delete_user(user_id):
    if current_user.id == user_id:
        return jsonify({'success': False, 'error': 'Cannot delete your own active admin account.'}), 400
        
    user = User.query.get_or_404(user_id)
    try:
        username = user.username
        db.session.delete(user)
        db.session.commit()
        
        log_event('System', 'WARNING', f"User account '{username}' deleted by admin '{current_user.username}'.")
        return jsonify({'success': True, 'message': f"User '{username}' deleted."})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500

@admin_bp.route('/logs')
@login_required
@admin_required
def get_logs():
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 25, type=int)
    log_type = request.args.get('log_type', 'All')
    
    query = SystemLog.query
    if log_type != 'All':
        query = query.filter_by(log_type=log_type)
        
    pagination = query.order_by(SystemLog.timestamp.desc()).paginate(page=page, per_page=per_page, error_out=False)
    logs_list = [l.to_dict() for l in pagination.items]
    
    return jsonify({
        'logs': logs_list,
        'page': page,
        'pages': pagination.pages,
        'total': pagination.total
    })

@admin_bp.route('/settings', methods=['GET', 'POST'])
@login_required
def update_settings():
    if request.method == 'GET':
        settings = Setting.query.all()
        return jsonify({s.key: {'value': s.value, 'description': s.description} for s in settings})
        
    # Allow analysts to edit limits if required, but admin is safer. 
    # The prompt says "Settings: Manage rule thresholds"
    data = request.get_json(silent=True) or {}
    
    try:
        updated_keys = []
        for key, val in data.items():
            # Check if setting exists
            setting = Setting.query.filter_by(key=key).first()
            if setting:
                Setting.set_val(key, val)
                updated_keys.append(key)
                
        if updated_keys:
            log_event('System', 'INFO', f"System settings updated: {', '.join(updated_keys)} by user '{current_user.username}'.")
            return jsonify({'success': True, 'message': f"Updated keys: {', '.join(updated_keys)}"})
        return jsonify({'success': False, 'error': 'No valid setting keys supplied.'}), 400
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@admin_bp.route('/model_info')
@login_required
def get_model_info():
    """
    Read training statistics from JSON.
    """
    base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    meta_path = os.path.join(base_dir, 'trained_model', 'model_meta.json')
    
    if os.path.exists(meta_path):
        try:
            with open(meta_path, 'r') as f:
                meta = json.load(f)
            return jsonify({
                'success': True,
                'trained': True,
                'metadata': meta
            })
        except Exception as e:
            return jsonify({'success': False, 'error': f"Failed reading metadata: {str(e)}"}), 500
    else:
        return jsonify({
            'success': True,
            'trained': False,
            'message': 'Model metadata not generated. Run train_model.py first.'
        })
