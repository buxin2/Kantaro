# =====================================
# models/__init__.py - Database models
# =====================================

from app import db, login_manager
from flask_login import UserMixin
from datetime import datetime, timedelta
import math

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    subscription_plan = db.Column(db.String(20), default='free')
    subscription_end = db.Column(db.DateTime, nullable=True)
    stripe_customer_id = db.Column(db.String(50), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    cameras = db.relationship('Camera', backref='owner', lazy=True, cascade='all, delete-orphan')
    
    def __repr__(self):
        return f"User('{self.username}', '{self.email}', '{self.subscription_plan}')"
    
    @property
    def is_subscription_active(self):
        if self.subscription_plan == 'free':
            return True
        return self.subscription_end and self.subscription_end > datetime.utcnow()
    
    @property
    def camera_limit(self):
        from config import Config
        return Config.SUBSCRIPTION_PLANS.get(self.subscription_plan, {}).get('cameras', 1)
    
    def can_add_camera(self):
        return len(self.cameras) < self.camera_limit

class Camera(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    camera_url = db.Column(db.String(200), nullable=True)
    camera_type = db.Column(db.String(20), nullable=False)  # 'ip' or 'device'
    is_active = db.Column(db.Boolean, default=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def __repr__(self):
        return f"Camera('{self.name}', '{self.camera_type}')"