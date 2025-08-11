# app.py - Simple Render-compatible version
import os
import cv2
import numpy as np
from flask import Flask, Response, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from datetime import datetime
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)

# Configuration
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'fallback-secret-key-for-development')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///security_app.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize extensions
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'

# Database Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    subscription_plan = db.Column(db.String(20), default='free')
    cameras = db.relationship('Camera', backref='owner', lazy=True, cascade='all, delete-orphan')
    
    @property
    def camera_limit(self):
        limits = {'free': 1, 'basic': 1, 'pro': 4, 'business': 10}
        return limits.get(self.subscription_plan, 1)

class Camera(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    camera_url = db.Column(db.String(200), nullable=True)
    camera_type = db.Column(db.String(20), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

def create_demo_frame():
    """Create a demo frame for deployment"""
    frame = np.zeros((480, 640, 3), dtype=np.uint8)
    
    # Add gradient background
    for i in range(480):
        intensity = int(50 + (i / 480) * 100)
        frame[i, :] = [intensity, intensity//2, intensity//3]
    
    # Add text
    cv2.putText(frame, "AI Security Camera System", (120, 200), 
                cv2.FONT_HERSHEY_SIMPLEX, 1, (255, 255, 255), 2)
    cv2.putText(frame, "Demo Mode - Camera Streaming", (140, 250), 
                cv2.FONT_HERSHEY_SIMPLEX, 0.7, (200, 200, 200), 2)
    cv2.putText(frame, "Object Detection Ready", (170, 300), 
                cv2.FONT_HERSHEY_SIMPLEX, 0.7, (100, 255, 100), 2)
    
    # Add some "detected objects" simulation
    cv2.rectangle(frame, (100, 100), (200, 150), (0, 255, 0), 2)
    cv2.putText(frame, "person 0.95", (105, 95), cv2.FONT_HERSHEY_SIMPLEX, 0.5, (0, 255, 0), 1)
    
    cv2.rectangle(frame, (400, 120), (520, 180), (0, 255, 0), 2)
    cv2.putText(frame, "car 0.87", (405, 115), cv2.FONT_HERSHEY_SIMPLEX, 0.5, (0, 255, 0), 1)
    
    return frame

def generate_demo_frames():
    """Generate demo frames for deployment"""
    while True:
        frame = create_demo_frame()
        _, buffer = cv2.imencode('.jpg', frame, [cv2.IMWRITE_JPEG_QUALITY, 85])
        yield (b'--frame\r\n'
               b'Content-Type: image/jpeg\r\n\r\n' + buffer.tobytes() + b'\r\n')

# Routes
@app.route('/')
def home():
    return render_template('home.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash('Email already registered. Please log in.', 'danger')
            return redirect(url_for('login'))
        
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        user = User(username=username, email=email, password=hashed_password)
        
        db.session.add(user)
        db.session.commit()
        
        flash('Account created successfully! Please log in.', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        
        user = User.query.filter_by(email=email).first()
        
        if user and bcrypt.check_password_hash(user.password, password):
            login_user(user, remember=request.form.get('remember'))
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('dashboard'))
        else:
            flash('Login failed. Please check email and password.', 'danger')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('home'))

@app.route('/dashboard')
@login_required
def dashboard():
    cameras = Camera.query.filter_by(user_id=current_user.id).all()
    return render_template('dashboard.html', cameras=cameras, user=current_user)

@app.route('/add_camera', methods=['GET', 'POST'])
@login_required
def add_camera():
    if len(current_user.cameras) >= current_user.camera_limit:
        flash(f'You have reached your camera limit ({current_user.camera_limit}). Please upgrade your plan.', 'warning')
        return redirect(url_for('pricing'))
    
    if request.method == 'POST':
        name = request.form['name']
        camera_type = request.form['type']
        camera_url = request.form.get('camera_url') if camera_type == 'ip' else None
        
        camera = Camera(
            name=name,
            camera_type=camera_type,
            camera_url=camera_url,
            user_id=current_user.id
        )
        
        db.session.add(camera)
        db.session.commit()
        
        flash('Camera added successfully! (Demo mode for deployment)', 'success')
        return redirect(url_for('dashboard'))
    
    return render_template('add_camera.html')

@app.route('/stream/<int:camera_id>')
@login_required
def stream(camera_id):
    camera = db.session.get(Camera, camera_id)
    if not camera or camera.owner != current_user:
        flash('Access denied.', 'danger')
        return redirect(url_for('dashboard'))
    
    return render_template('stream.html', camera=camera)

@app.route('/video/<int:camera_id>')
@login_required
def video(camera_id):
    camera = db.session.get(Camera, camera_id)
    if not camera or camera.owner != current_user:
        return "Access denied", 403
    
    # Return demo stream for deployment
    return Response(generate_demo_frames(),
                   mimetype='multipart/x-mixed-replace; boundary=frame')

@app.route('/delete_camera/<int:camera_id>')
@login_required
def delete_camera(camera_id):
    camera = db.session.get(Camera, camera_id)
    if not camera or camera.owner != current_user:
        flash('Access denied.', 'danger')
        return redirect(url_for('dashboard'))
    
    db.session.delete(camera)
    db.session.commit()
    flash('Camera deleted successfully!', 'success')
    return redirect(url_for('dashboard'))

@app.route('/pricing')
def pricing():
    return render_template('pricing.html')

@app.route('/account')
@login_required
def account():
    return render_template('account.html', user=current_user)

@app.route('/health')
def health():
    return {'status': 'healthy', 'timestamp': datetime.utcnow().isoformat()}

# Initialize database
def create_tables():
    """Create database tables"""
    with app.app_context():
        try:
            db.create_all()
            logger.info("Database tables created successfully")
        except Exception as e:
            logger.error(f"Error creating database tables: {e}")

if __name__ == "__main__":
    create_tables()
    port = int(os.environ.get('PORT', 5000))
    app.run(host="0.0.0.0", port=port)
else:
    # For Gunicorn
    create_tables()
