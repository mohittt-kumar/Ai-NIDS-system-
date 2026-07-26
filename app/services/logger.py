from app import db
from app.models.log import SystemLog
from datetime import datetime

def log_event(log_type, level, message, user_id=None):
    # Save to database log table
    try:
        log_entry = SystemLog(
            timestamp=datetime.utcnow(),
            log_type=log_type,
            level=level,
            message=message,
            user_id=user_id
        )
        db.session.add(log_entry)
        db.session.commit()
    except Exception:
        pass
        
    # Safe console printing fallback for Windows output redirecting
    try:
        print(f"[{datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')}] [{log_type.upper()}] [{level}] {message}")
    except Exception:
        pass
