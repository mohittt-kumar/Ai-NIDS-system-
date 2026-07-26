from app import create_app, db
from app.models.setting import Setting
from app.models.user import User
import os

app = create_app()

if __name__ == '__main__':
    os.makedirs(os.path.join(os.path.dirname(__file__), 'instance'), exist_ok=True)
    os.makedirs(os.path.join(os.path.dirname(__file__), 'trained_model'), exist_ok=True)
    os.makedirs(os.path.join(os.path.dirname(__file__), 'dataset'), exist_ok=True)
    os.makedirs(os.path.join(os.path.dirname(__file__), 'app', 'static', 'images', 'profiles'), exist_ok=True)
    
    with app.app_context():
        db.create_all()
        Setting.initialize_defaults()
        User.initialize_defaults()
        
    app.run(host='127.0.0.1', port=5000, debug=True, use_reloader=False)
