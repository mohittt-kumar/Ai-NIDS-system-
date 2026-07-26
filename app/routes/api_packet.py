from flask import Blueprint, jsonify, current_app, request
from flask_login import login_required
from app.models.packet import Packet
from app.models.setting import Setting
from app.services.packet_capture import PacketCaptureService
from app.services.logger import log_event
from app import db

packet_bp = Blueprint('api_packet', __name__)

@packet_bp.route('/status')
@login_required
def status():
    is_active = Setting.get_val('MONITORING_ACTIVE') == 'True'
    sim_mode = Setting.get_val('SIMULATION_MODE') == 'True'
    
    # Retrieve last 50 packets
    recent = Packet.query.order_by(Packet.timestamp.desc()).limit(50).all()
    packets_list = [p.to_dict() for p in recent]
    
    return jsonify({
        'monitoring_active': is_active,
        'simulation_mode': sim_mode,
        'packets': packets_list
    })

@packet_bp.route('/start', methods=['POST'])
@login_required
def start_capture():
    try:
        data = request.get_json(silent=True) or {}
        sim_choice = data.get('simulation_mode')
        
        if sim_choice is not None:
            Setting.set_val('SIMULATION_MODE', 'True' if sim_choice else 'False')
            
        service = PacketCaptureService()
        app_obj = current_app._get_current_object()
        service.start(app_obj)
        
        return jsonify({'success': True, 'message': 'Packet capture started successfully.'})
    except Exception as e:
        log_event('System', 'ERROR', f"Failed to start packet capture thread: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500

@packet_bp.route('/stop', methods=['POST'])
@login_required
def stop_capture():
    try:
        service = PacketCaptureService()
        service.stop()
        return jsonify({'success': True, 'message': 'Packet capture stopped successfully.'})
    except Exception as e:
        log_event('System', 'ERROR', f"Failed to stop packet capture thread: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500

@packet_bp.route('/clear', methods=['POST'])
@login_required
def clear_logs():
    try:
        # Delete packets (Alerts will cascade delete because of the relationship setup)
        num_packets = Packet.query.delete()
        db.session.commit()
        log_event('System', 'INFO', f"Packet logs and associated alerts database cleared by user. Deleted count: {num_packets}")
        return jsonify({'success': True, 'message': f'Cleared {num_packets} packets and cascading alerts.'})
    except Exception as e:
        db.session.rollback()
        log_event('System', 'ERROR', f"Failed to clear packet logs: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500

@packet_bp.route('/stream')
@login_required
def packet_stream():
    # AJAX polling endpoint for new packets.
    # Frontend passes last packet ID, returns any packet created after that ID.
    last_id = request.args.get('last_id', 0, type=int)
    
    new_packets = Packet.query.filter(Packet.id > last_id).order_by(Packet.timestamp.desc()).limit(30).all()
    packets_list = [p.to_dict() for p in new_packets]
    
    return jsonify({
        'packets': packets_list
    })
