# app.py - Deployment ready version with fixed database initialization
import math
import cv2
# import cvzone  # Commented out for deployment compatibility
from ultralytics import YOLO
from flask import Flask, Response, render_template, request, redirect, url_for, session, flash, jsonify, current_app, copy_current_request_context
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from datetime import datetime, timedelta
import stripe
import os
from functools import wraps
import logging
import threading

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'your-secret-key-change-this')

# Fix database URL for deployment
database_url = os.environ.get('DATABASE_URL', 'sqlite:///security_app.db')
if database_url.startswith('postgres://'):
    database_url = database_url.replace('postgres://', 'postgresql://', 1)

app.config['SQLALCHEMY_DATABASE_URI'] = database_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
    'pool_timeout': 20,
    'pool_recycle': -1,
    'pool_pre_ping': True
}

# Stripe configuration
stripe.api_key = os.environ.get('STRIPE_SECRET_KEY', "sk_test_your_stripe_secret_key")
STRIPE_PUBLISHABLE_KEY = os.environ.get('STRIPE_PUBLISHABLE_KEY', "pk_test_your_stripe_publishable_key")

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'

# Load YOLO model
try:
    model = YOLO("yolov8n.pt")
    logger.info("YOLO model loaded successfully")
except Exception as e:
    logger.error(f"Error loading YOLO model: {e}")
    model = None

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
    __tablename__ = 'users'  # Explicitly define table name
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    subscription_plan = db.Column(db.String(20), default='free')
    subscription_end = db.Column(db.DateTime, nullable=True)
    stripe_customer_id = db.Column(db.String(50), nullable=True)
    cameras = db.relationship('Camera', backref='owner', lazy=True, cascade='all, delete-orphan')
    
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
    __tablename__ = 'cameras'  # Explicitly define table name
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    camera_url = db.Column(db.String(200), nullable=True)
    camera_type = db.Column(db.String(20), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

# User loader
@login_manager.user_loader
def load_user(user_id):
    try:
        return db.session.get(User, int(user_id))
    except Exception as e:
        logger.error(f"Error loading user {user_id}: {e}")
        return None

# Subscription decorator
def subscription_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_subscription_active:
            flash('Your subscription has expired. Please upgrade your plan.', 'warning')
            return redirect(url_for('pricing'))
        return f(*args, **kwargs)
    return decorated_function

# Simple bounding box drawing function (replacement for cvzone)
def draw_bounding_box(frame, x1, y1, x2, y2, label, conf):
    """Draw bounding box and label without cvzone dependency"""
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

def get_camera_capture(camera_type, camera_url=None):
    """Initialize camera capture"""
    try:
        if camera_type == 'ip' and camera_url:
            logger.info(f"Connecting to IP camera: {camera_url}")
            cap = cv2.VideoCapture(camera_url)
        else:
            logger.info("Connecting to device camera")
            cap = cv2.VideoCapture(0)
        
        if cap.isOpened():
            cap.set(cv2.CAP_PROP_FRAME_WIDTH, 640)
            cap.set(cv2.CAP_PROP_FRAME_HEIGHT, 480)
            cap.set(cv2.CAP_PROP_FPS, 30)
            
            # Test connection
            ret, frame = cap.read()
            if not ret:
                logger.error("Failed to read from camera")
                cap.release()
                return None
            
            logger.info("Camera connected successfully")
            return cap
        else:
            logger.error("Failed to open camera")
            return None
    except Exception as e:
        logger.error(f"Error connecting to camera: {e}")
        return None

def process_frame(frame):
    """Process frame with YOLO detection"""
    try:
        if model is None:
            _, buffer = cv2.imencode('.jpg', frame)
            return buffer.tobytes()
        
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
        
        _, buffer = cv2.imencode('.jpg', frame, [cv2.IMWRITE_JPEG_QUALITY, 85])
        return buffer.tobytes()
    except Exception as e:
        logger.error(f"Error processing frame: {e}")
        _, buffer = cv2.imencode('.jpg', frame)
        return buffer.tobytes()

def create_error_frame(message):
    """Create error frame"""
    import numpy as np
    frame = np.zeros((480, 640, 3), dtype=np.uint8)
    cv2.putText(frame, "Camera Error", (200, 200), cv2.FONT_HERSHEY_SIMPLEX, 1, (0, 0, 255), 2)
    cv2.putText(frame, message, (50, 250), cv2.FONT_HERSHEY_SIMPLEX, 0.6, (255, 255, 255), 2)
    cv2.putText(frame, "Check camera connection", (150, 300), cv2.FONT_HERSHEY_SIMPLEX, 0.6, (255, 255, 255), 2)
    _, buffer = cv2.imencode('.jpg', frame)
    return buffer.tobytes()

def generate_frames(camera_id):
    """Generate video frames for streaming"""
    with app.app_context():
        try:
            camera = db.session.get(Camera, camera_id)
            if not camera:
                logger.error(f"Camera {camera_id} not found")
                error_frame = create_error_frame("Camera not found")
                while True:
                    yield (b'--frame\r\n'
                           b'Content-Type: image/jpeg\r\n\r\n' + error_frame + b'\r\n')
            
            camera_type = camera.camera_type
            camera_url = camera.camera_url
            camera_name = camera.name
        except Exception as e:
            logger.error(f"Database error accessing camera {camera_id}: {e}")
            error_frame = create_error_frame("Database error")
            while True:
                yield (b'--frame\r\n'
                       b'Content-Type: image/jpeg\r\n\r\n' + error_frame + b'\r\n')
    
    logger.info(f"Starting video stream for camera {camera_id}: {camera_name}")
    cap = get_camera_capture(camera_type, camera_url)
    
    if cap is None:
        error_frame = create_error_frame("Failed to connect to camera")
        while True:
            yield (b'--frame\r\n'
                   b'Content-Type: image/jpeg\r\n\r\n' + error_frame + b'\r\n')
    
    try:
        frame_count = 0
        while True:
            success, frame = cap.read()
            if not success:
                logger.warning(f"Failed to read frame {frame_count}")
                if frame_count % 30 == 0:
                    cap.release()
                    cap = get_camera_capture(camera_type, camera_url)
                    if cap is None:
                        error_frame = create_error_frame("Camera reconnection failed")
                        yield (b'--frame\r\n'
                               b'Content-Type: image/jpeg\r\n\r\n' + error_frame + b'\r\n')
                        continue
                continue
            
            frame_count += 1
            frame_bytes = process_frame(frame)
            yield (b'--frame\r\n'
                   b'Content-Type: image/jpeg\r\n\r\n' + frame_bytes + b'\r\n')
            
    except Exception as e:
        logger.error(f"Error in frame generation: {e}")
        error_frame = create_error_frame(f"Streaming error: {str(e)}")
        yield (b'--frame\r\n'
               b'Content-Type: image/jpeg\r\n\r\n' + error_frame + b'\r\n')
    finally:
        if cap:
            cap.release()
            logger.info(f"Camera {camera_id} released")

# Initialize database function
def init_db():
    """Initialize the database with proper error handling"""
    try:
        with app.app_context():
            # Drop all tables and recreate (be careful in production!)
            db.drop_all()
            db.create_all()
            logger.info("Database tables created successfully")
            
            # Create a test user if none exists
            if User.query.first() is None:
                test_user = User(
                    username='admin',
                    email='admin@example.com',
                    password=bcrypt.generate_password_hash('password123').decode('utf-8')
                )
                db.session.add(test_user)
                db.session.commit()
                logger.info("Test admin user created: admin@example.com / password123")
                
    except Exception as e:
        logger.error(f"Error initializing database: {e}")
        raise

# Routes
@app.route('/')
def home():
    return render_template('home.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        try:
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
            
        except Exception as e:
            logger.error(f"Registration error: {e}")
            db.session.rollback()
            flash('Registration failed. Please try again.', 'danger')
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        try:
            email = request.form['email']
            password = request.form['password']
            
            user = User.query.filter_by(email=email).first()
            
            if user and bcrypt.check_password_hash(user.password, password):
                login_user(user, remember=request.form.get('remember'))
                next_page = request.args.get('next')
                return redirect(next_page) if next_page else redirect(url_for('dashboard'))
            else:
                flash('Login failed. Please check email and password.', 'danger')
                
        except Exception as e:
            logger.error(f"Login error: {e}")
            flash('Login failed. Please try again.', 'danger')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('home'))

@app.route('/dashboard')
@login_required
@subscription_required
def dashboard():
    try:
        cameras = Camera.query.filter_by(user_id=current_user.id).all()
        return render_template('dashboard.html', cameras=cameras, user=current_user)
    except Exception as e:
        logger.error(f"Dashboard error: {e}")
        flash('Error loading dashboard. Please try again.', 'danger')
        return render_template('dashboard.html', cameras=[], user=current_user)

@app.route('/add_camera', methods=['GET', 'POST'])
@login_required
@subscription_required
def add_camera():
    try:
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
            
            flash('Camera added successfully!', 'success')
            return redirect(url_for('dashboard'))
            
    except Exception as e:
        logger.error(f"Add camera error: {e}")
        db.session.rollback()
        flash('Error adding camera. Please try again.', 'danger')
    
    return render_template('add_camera.html')

@app.route('/stream/<int:camera_id>')
@login_required
@subscription_required
def stream(camera_id):
    try:
        camera = db.session.get(Camera, camera_id)
        if not camera or camera.owner != current_user:
            flash('Access denied.', 'danger')
            return redirect(url_for('dashboard'))
        
        return render_template('stream.html', camera=camera)
    except Exception as e:
        logger.error(f"Stream route error: {e}")
        flash('Error accessing camera stream.', 'danger')
        return redirect(url_for('dashboard'))

@app.route('/video/<int:camera_id>')
@login_required
@subscription_required
def video(camera_id):
    try:
        camera = db.session.get(Camera, camera_id)
        if not camera or camera.owner != current_user:
            return "Access denied", 403
        
        logger.info(f"Starting video stream for camera {camera_id}")
        return Response(generate_frames(camera_id),
                       mimetype='multipart/x-mixed-replace; boundary=frame')
    except Exception as e:
        logger.error(f"Video route error: {e}")
        return "Video stream error", 500

@app.route('/delete_camera/<int:camera_id>')
@login_required
def delete_camera(camera_id):
    try:
        camera = db.session.get(Camera, camera_id)
        if not camera or camera.owner != current_user:
            flash('Access denied.', 'danger')
            return redirect(url_for('dashboard'))
        
        db.session.delete(camera)
        db.session.commit()
        flash('Camera deleted successfully!', 'success')
    except Exception as e:
        logger.error(f"Delete camera error: {e}")
        db.session.rollback()
        flash('Error deleting camera. Please try again.', 'danger')
    
    return redirect(url_for('dashboard'))

@app.route('/pricing')
def pricing():
    return render_template('pricing.html', stripe_public_key=STRIPE_PUBLISHABLE_KEY)

@app.route('/account')
@login_required
def account():
    return render_template('account.html', user=current_user)

@app.route('/test_camera/<int:camera_id>')
@login_required
def test_camera(camera_id):
    """Test camera connection"""
    try:
        camera = db.session.get(Camera, camera_id)
        if not camera or camera.owner != current_user:
            return "Access denied", 403
        
        cap = get_camera_capture(camera.camera_type, camera.camera_url)
        if cap:
            cap.release()
            return "✅ Camera connection successful"
        else:
            return "❌ Camera connection failed"
    except Exception as e:
        logger.error(f"Test camera error: {e}")
        return f"❌ Camera test failed: {str(e)}"

@app.route('/health')
def health_check():
    """Health check endpoint for deployment platforms"""
    try:
        # Test database connection
        User.query.first()
        return {'status': 'healthy', 'database': 'connected'}, 200
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        return {'status': 'unhealthy', 'error': str(e)}, 500

# Error handlers
@app.errorhandler(404)
def not_found_error(error):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    logger.error(f"Internal server error: {error}")
    return render_template('500.html'), 500


@app.route('/setup-database')
def setup_database():
    """Create database tables - visit this URL once after deployment"""
    try:
        db.create_all()
        
        # Create test user
        from flask_bcrypt import Bcrypt
        bcrypt = Bcrypt(app)
        
        # Import your User model (adjust import based on your structure)
        from models.user import User  # or wherever your User model is
        
        test_user = User(
            username='admin',
            email='admin@example.com', 
            password=bcrypt.generate_password_hash('password123').decode('utf-8')
        )
        
        db.session.add(test_user)
        db.session.commit()
        
        return "SUCCESS! Database created. You can now login with admin@example.com / password123"
        
    except Exception as e:
        return f"Error: {e}"

if __name__ == "__main__":
    try:
        # Initialize database
        init_db()
        
        # Start the app
        port = int(os.environ.get('PORT', 5000))
        app.run(host="0.0.0.0", port=port, debug=False)
    except Exception as e:
        logger.error(f"Failed to start application: {e}")
        raise
