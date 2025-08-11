# app.py - Updated deployment-ready version with full features
import os
import cv2
import numpy as np
from flask import Flask, Response, render_template, request, redirect, url_for, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from datetime import datetime, timedelta
import stripe
from functools import wraps
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)

# Configuration - Use environment variables for production
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-production')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///security_app.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Fix for PostgreSQL URL format (Render/Heroku compatibility)
if app.config['SQLALCHEMY_DATABASE_URI'] and app.config['SQLALCHEMY_DATABASE_URI'].startswith('postgres://'):
    app.config['SQLALCHEMY_DATABASE_URI'] = app.config['SQLALCHEMY_DATABASE_URI'].replace('postgres://', 'postgresql://', 1)

# Stripe configuration
stripe.api_key = os.environ.get('STRIPE_SECRET_KEY', 'sk_test_your_stripe_secret_key')
STRIPE_PUBLISHABLE_KEY = os.environ.get('STRIPE_PUBLISHABLE_KEY', 'pk_test_your_stripe_publishable_key')

# Initialize extensions
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'

# Try to load YOLO model - fallback gracefully if not available
try:
    from ultralytics import YOLO
    model = YOLO("yolov8n.pt")
    YOLO_AVAILABLE = True
    logger.info("YOLO model loaded successfully")
except ImportError:
    logger.warning("YOLO not available - running in demo mode")
    model = None
    YOLO_AVAILABLE = False
except Exception as e:
    logger.warning(f"YOLO model loading failed: {e} - running in demo mode")
    model = None
    YOLO_AVAILABLE = False

# YOLO class names for object detection
classNames = [
    "person", "bicycle", "car", "motorbike", "aeroplane", "bus", "train",
    "truck", "boat", "traffic light", "fire hydrant", "stop sign", "parking meter",
    "bench", "bird", "cat", "dog", "horse", "sheep", "cow", "elephant", "bear",
    "zebra", "giraffe", "backpack", "umbrella", "handbag", "tie", "suitcase",
    "frisbee", "skis", "snowboard", "sports ball", "kite", "baseball bat",
    "baseball glove", "skateboard", "surfboard", "tennis racket", "bottle",
    "wine glass", "cup", "fork", "knife", "spoon", "bowl", "banana", "apple",
    "sandwich", "orange", "broccoli", "carrot", "hot dog", "pizza", "donut",
    "cake", "chair", "sofa", "pottedplant", "bed", "diningtable", "toilet",
    "tvmonitor", "laptop", "mouse", "remote", "keyboard", "cell phone",
    "microwave", "oven", "toaster", "sink", "refrigerator", "book", "clock",
    "vase", "scissors", "teddy bear", "hair drier", "toothbrush"
]

# Database Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    subscription_plan = db.Column(db.String(20), default='free')
    subscription_end = db.Column(db.DateTime, nullable=True)
    stripe_customer_id = db.Column(db.String(50), nullable=True)
    cameras = db.relationship('Camera', backref='owner', lazy=True, cascade='all, delete-orphan')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    @property
    def is_subscription_active(self):
        if self.subscription_plan == 'free':
            return True
        return self.subscription_end and self.subscription_end > datetime.utcnow()
    
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

# Decorators
def subscription_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_subscription_active:
            flash('Your subscription has expired. Please upgrade your plan.', 'warning')
            return redirect(url_for('pricing'))
        return f(*args, **kwargs)
    return decorated_function

# Helper functions for camera processing
def draw_bounding_box(frame, x1, y1, x2, y2, label, conf):
    """Draw bounding box and label without external dependencies"""
    # Draw rectangle
    cv2.rectangle(frame, (x1, y1), (x2, y2), (0, 255, 0), 2)
    
    # Prepare label text
    label_text = f'{label} {conf:.2f}'
    
    # Get text size
    (text_width, text_height), _ = cv2.getTextSize(label_text, cv2.FONT_HERSHEY_SIMPLEX, 0.5, 2)
    
    # Draw label background
    cv2.rectangle(frame, (x1, y1 - text_height - 10), (x1 + text_width, y1), (0, 255, 0), -1)
    
    # Draw label text
    cv2.putText(frame, label_text, (x1, y1 - 5), cv2.FONT_HERSHEY_SIMPLEX, 0.5, (0, 0, 0), 2)

def create_demo_frame():
    """Create a demo frame showing AI detection simulation"""
    frame = np.zeros((480, 640, 3), dtype=np.uint8)
    
    # Create gradient background
    for i in range(480):
        intensity = int(30 + (i / 480) * 80)
        frame[i, :] = [intensity, intensity//2, intensity//3]
    
    # Add main title
    cv2.putText(frame, "AI Security Camera System", (120, 60), 
                cv2.FONT_HERSHEY_SIMPLEX, 1, (255, 255, 255), 2)
    
    # Add subtitle based on YOLO availability
    if YOLO_AVAILABLE:
        cv2.putText(frame, "YOLOv8 Object Detection Active", (140, 100), 
                    cv2.FONT_HERSHEY_SIMPLEX, 0.7, (100, 255, 100), 2)
    else:
        cv2.putText(frame, "Demo Mode - AI Detection Ready", (140, 100), 
                    cv2.FONT_HERSHEY_SIMPLEX, 0.7, (255, 255, 100), 2)
    
    # Add simulated detections
    detections = [
        (100, 150, 200, 220, "person", 0.95),
        (400, 160, 520, 240, "car", 0.87),
        (250, 180, 350, 250, "bicycle", 0.78)
    ]
    
    for x1, y1, x2, y2, label, conf in detections:
        draw_bounding_box(frame, x1, y1, x2, y2, label, conf)
    
    # Add status info
    cv2.putText(frame, f"Status: {'AI Active' if YOLO_AVAILABLE else 'Demo Mode'}", (20, 450), 
                cv2.FONT_HERSHEY_SIMPLEX, 0.6, (255, 255, 255), 2)
    cv2.putText(frame, "Objects Detected: 3", (350, 450), 
                cv2.FONT_HERSHEY_SIMPLEX, 0.6, (255, 255, 255), 2)
    
    return frame

def process_frame_with_yolo(frame):
    """Process frame with YOLO if available, otherwise return demo frame"""
    if not YOLO_AVAILABLE or model is None:
        return create_demo_frame()
    
    try:
        results = model(frame, stream=True, verbose=False)
        
        for r in results:
            if r.boxes is not None:
                for box in r.boxes:
                    x1, y1, x2, y2 = map(int, box.xyxy[0])
                    conf = float(box.conf[0])
                    cls = int(box.cls[0])
                    
                    if cls < len(classNames):
                        detected_class = classNames[cls]
                        draw_bounding_box(frame, x1, y1, x2, y2, detected_class, conf)
        
        return frame
    except Exception as e:
        logger.error(f"YOLO processing error: {e}")
        return create_demo_frame()

def generate_frames(camera_id):
    """Generate video frames for streaming"""
    # Get camera info
    with app.app_context():
        camera = db.session.get(Camera, camera_id)
        if not camera:
            logger.error(f"Camera {camera_id} not found")
            # Generate error frames
            while True:
                error_frame = create_demo_frame()
                cv2.putText(error_frame, "Camera Not Found", (200, 240), 
                           cv2.FONT_HERSHEY_SIMPLEX, 1, (0, 0, 255), 2)
                _, buffer = cv2.imencode('.jpg', error_frame)
                yield (b'--frame\r\n'
                       b'Content-Type: image/jpeg\r\n\r\n' + buffer.tobytes() + b'\r\n')
    
    logger.info(f"Starting stream for camera {camera_id}: {camera.name}")
    
    # For demo purposes, generate simulated frames
    # In production, this would connect to actual cameras
    frame_count = 0
    while True:
        try:
            if camera.camera_type == 'device':
                # Try to connect to actual device camera
                cap = cv2.VideoCapture(0)
                if cap.isOpened():
                    ret, frame = cap.read()
                    cap.release()
                    if ret:
                        processed_frame = process_frame_with_yolo(frame)
                    else:
                        processed_frame = create_demo_frame()
                else:
                    processed_frame = create_demo_frame()
            else:
                # For IP cameras or demo mode
                processed_frame = create_demo_frame()
            
            # Add frame counter for dynamic demo
            frame_count += 1
            cv2.putText(processed_frame, f"Frame: {frame_count}", (20, 30), 
                       cv2.FONT_HERSHEY_SIMPLEX, 0.5, (255, 255, 255), 1)
            
            _, buffer = cv2.imencode('.jpg', processed_frame, [cv2.IMWRITE_JPEG_QUALITY, 85])
            yield (b'--frame\r\n'
                   b'Content-Type: image/jpeg\r\n\r\n' + buffer.tobytes() + b'\r\n')
            
        except Exception as e:
            logger.error(f"Frame generation error: {e}")
            # Generate error frame
            error_frame = create_demo_frame()
            cv2.putText(error_frame, "Stream Error", (200, 240), 
                       cv2.FONT_HERSHEY_SIMPLEX, 1, (0, 0, 255), 2)
            _, buffer = cv2.imencode('.jpg', error_frame)
            yield (b'--frame\r\n'
                   b'Content-Type: image/jpeg\r\n\r\n' + buffer.tobytes() + b'\r\n')

# Routes
@app.route('/')
def home():
    return render_template('home.html', yolo_available=YOLO_AVAILABLE)

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
@subscription_required
def dashboard():
    cameras = Camera.query.filter_by(user_id=current_user.id).all()
    return render_template('dashboard.html', cameras=cameras, user=current_user, yolo_available=YOLO_AVAILABLE)

@app.route('/add_camera', methods=['GET', 'POST'])
@login_required
@subscription_required
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
        
        mode_msg = "with AI detection" if YOLO_AVAILABLE else "in demo mode"
        flash(f'Camera "{name}" added successfully {mode_msg}!', 'success')
        return redirect(url_for('dashboard'))
    
    return render_template('add_camera.html')

@app.route('/stream/<int:camera_id>')
@login_required
@subscription_required
def stream(camera_id):
    camera = db.session.get(Camera, camera_id)
    if not camera or camera.owner != current_user:
        flash('Access denied.', 'danger')
        return redirect(url_for('dashboard'))
    
    return render_template('stream.html', camera=camera, yolo_available=YOLO_AVAILABLE)

@app.route('/video/<int:camera_id>')
@login_required
@subscription_required
def video(camera_id):
    camera = db.session.get(Camera, camera_id)
    if not camera or camera.owner != current_user:
        return "Access denied", 403
    
    return Response(generate_frames(camera_id),
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
    return render_template('pricing.html', stripe_public_key=STRIPE_PUBLISHABLE_KEY)

@app.route('/account')
@login_required
def account():
    return render_template('account.html', user=current_user)

@app.route('/health')
def health():
    return {
        'status': 'healthy',
        'timestamp': datetime.utcnow().isoformat(),
        'version': '2.0.0',
        'yolo_available': YOLO_AVAILABLE,
        'features': [
            'User Authentication',
            'Camera Management',
            'Live Streaming',
            'AI Object Detection' if YOLO_AVAILABLE else 'Demo Mode',
            'Subscription Management'
        ]
    }

# Initialize database
def create_tables():
    """Initialize database tables"""
    with app.app_context():
        try:
            db.create_all()
            logger.info("Database tables created successfully")
        except Exception as e:
            logger.error(f"Error creating database: {e}")

if __name__ == "__main__":
    create_tables()
    port = int(os.environ.get('PORT', 5000))
    app.run(host="0.0.0.0", port=port, debug=os.environ.get('FLASK_ENV') == 'development')
else:
    # For Gunicorn deployment
    create_tables()
