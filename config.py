import os

basedir = os.path.abspath(os.path.dirname(__file__))

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'security-operations-center-nids-key-987654'
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or \
        'sqlite:///' + os.path.join(basedir, 'instance', 'nids.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # Path mappings
    MODEL_DIR = os.path.join(basedir, 'trained_model')
    DATASET_DIR = os.path.join(basedir, 'dataset')
    
    # File upload configurations
    UPLOAD_FOLDER = os.path.join(basedir, 'app', 'static', 'images', 'profiles')
    MAX_CONTENT_LENGTH = 2 * 1024 * 1024  # 2MB limits for profile pictures
    
    # Heuristic Rule Defaults
    DEFAULT_THRESHOLDS = {
        'PORT_SCAN_COUNT': 15,          # Number of unique ports targetted
        'PORT_SCAN_WINDOW': 10,         # Time window in seconds
        'PING_FLOOD_RATE': 10,          # ICMP packets per second
        'SYN_FLOOD_RATE': 15,           # SYN packets per second from one source
        'HIGH_PACKET_RATE': 100,        # Total packets per second overall
        'BRUTE_FORCE_RATE': 10,         # Connection attempts to 22/3389/21 per second
    }
