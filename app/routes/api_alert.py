from flask import Blueprint, jsonify, request
from flask_login import login_required
from app.models.alert import Alert
from app.services.logger import log_event
from app import db

alert_bp = Blueprint('api_alert', __name__)

@alert_bp.route('/list')
@login_required
def get_alerts():
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 15, type=int)
    
    # Filters
    severity = request.args.get('severity')
    status = request.args.get('status')
    search = request.args.get('search')
    
    query = Alert.query
    
    if severity and severity != 'All':
        query = query.filter_by(severity=severity)
        
    if status and status != 'All':
        query = query.filter_by(status=status)
    else:
        # Default exclude deleted status unless requested
        query = query.filter(Alert.status != 'Deleted')
        
    if search:
        search_fmt = f"%{search}%"
        query = query.filter(
            (Alert.src_ip.like(search_fmt)) | 
            (Alert.dst_ip.like(search_fmt)) | 
            (Alert.attack_type.like(search_fmt))
        )
        
    # Pagination
    pagination = query.order_by(Alert.timestamp.desc()).paginate(page=page, per_page=per_page, error_out=False)
    
    alerts_list = [a.to_dict() for a in pagination.items]
    
    return jsonify({
        'alerts': alerts_list,
        'page': page,
        'pages': pagination.pages,
        'total': pagination.total,
        'has_next': pagination.has_next,
        'has_prev': pagination.has_prev
    })

@alert_bp.route('/<int:alert_id>/resolve', methods=['POST'])
@login_required
def resolve_alert(alert_id):
    alert = Alert.query.get_or_404(alert_id)
    try:
        alert.status = 'Resolved'
        db.session.commit()
        log_event('Alert', 'INFO', f"Alert ID {alert_id} resolved by user.")
        return jsonify({'success': True, 'message': f'Alert ID {alert_id} resolved.'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500

@alert_bp.route('/<int:alert_id>/delete', methods=['POST'])
@login_required
def delete_alert(alert_id):
    alert = Alert.query.get_or_404(alert_id)
    try:
        # Soft delete by marking status as Deleted
        alert.status = 'Deleted'
        db.session.commit()
        log_event('Alert', 'INFO', f"Alert ID {alert_id} marked as Deleted.")
        return jsonify({'success': True, 'message': f'Alert ID {alert_id} deleted.'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500
