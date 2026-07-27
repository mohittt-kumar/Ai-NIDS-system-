import os

basedir = os.path.abspath(os.path.dirname(__file__))

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'security-operations-center-nids-key-987654'
    # Test if local instance folder is writable; if not (like Vercel), use /tmp
    _db_dir = os.path.join(basedir, 'instance')
    _db_path = os.path.join(_db_dir, 'nids.db')
    _is_writable = False
    try:
        if not os.path.exists(_db_dir):
            os.makedirs(_db_dir, exist_ok=True)
        _test_file = os.path.join(_db_dir, '.write_test')
        with open(_test_file, 'w') as _f:
            _f.write('test')
        os.remove(_test_file)
        _is_writable = True
    except Exception:
        _is_writable = False

    if _is_writable and os.environ.get('VERCEL') != '1':
        SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or 'sqlite:///' + _db_path
    else:
        SQLALCHEMY_DATABASE_URI = 'sqlite:////tmp/nids.db'
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
