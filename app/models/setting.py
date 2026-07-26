from app import db

class Setting(db.Model):
    __tablename__ = 'settings'
    
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(50), unique=True, nullable=False)
    value = db.Column(db.String(255), nullable=False)
    description = db.Column(db.String(255), nullable=True)
    
    @classmethod
    def get_val(cls, key, default=None):
        setting = cls.query.filter_by(key=key).first()
        return setting.value if setting else default
        
    @classmethod
    def get_int(cls, key, default=None):
        val = cls.get_val(key, default)
        try:
            return int(val)
        except (ValueError, TypeError):
            return default
            
    @classmethod
    def set_val(cls, key, value):
        setting = cls.query.filter_by(key=key).first()
        if setting:
            setting.value = str(value)
        else:
            setting = cls(key=key, value=str(value))
            db.session.add(setting)
        db.session.commit()
        
    @classmethod
    def initialize_defaults(cls):
        from config import Config
        # Rule threshold defaults
        defaults = {
            'PORT_SCAN_COUNT': (str(Config.DEFAULT_THRESHOLDS['PORT_SCAN_COUNT']), 'Number of unique destination ports targetted from a single IP to trigger a Port Scan alert'),
            'PORT_SCAN_WINDOW': (str(Config.DEFAULT_THRESHOLDS['PORT_SCAN_WINDOW']), 'Evaluation window (seconds) for Port Scan heuristic'),
            'PING_FLOOD_RATE': (str(Config.DEFAULT_THRESHOLDS['PING_FLOOD_RATE']), 'ICMP packets per second from a single IP to trigger ICMP Flood alert'),
            'SYN_FLOOD_RATE': (str(Config.DEFAULT_THRESHOLDS['SYN_FLOOD_RATE']), 'TCP packets with only SYN flag per second from a single IP to trigger SYN Flood alert'),
            'HIGH_PACKET_RATE': (str(Config.DEFAULT_THRESHOLDS['HIGH_PACKET_RATE']), 'Total packets captured per second to trigger High Traffic alert'),
            'BRUTE_FORCE_RATE': (str(Config.DEFAULT_THRESHOLDS['BRUTE_FORCE_RATE']), 'Connection attempts targeting secure ports (22, 3389, 21) per second to trigger Brute Force alert'),
            'MONITORING_ACTIVE': ('False', 'Status of the live packet capture engine (True/False)'),
            'SIMULATION_MODE': ('True', 'Fallback to simulated traffic generation (True/False)')
        }
        
        for k, (v, desc) in defaults.items():
            if not cls.query.filter_by(key=k).first():
                db.session.add(cls(key=k, value=v, description=desc))
        db.session.commit()
        print("Default settings database initialized.")
