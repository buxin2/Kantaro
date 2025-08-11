from app import db, login_manager
from flask_login import UserMixin
from datetime import datetime, timedelta

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class User(UserMixin, db.Model):
    # ... (User model code from the main file)

class Camera(db.Model):
    # ... (Camera model code from the main file)