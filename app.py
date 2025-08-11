# Fixed app.py - Replace your current app.py with this
import math
import cv2
import cvzone
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
app.config['SECRET_KEY'] = 'your-secret-key-change-this'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///security_app.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Stripe configuration
stripe.api_key = "sk_test_your_stripe_secret_key"  # Replace with your Stripe secret key
STRIPE_PUBLISHABLE_KEY = "pk_test_your_stripe_publishable_key"  # Replace with your Stripe publishable key

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
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    camera_url = db.Column(db.String(200), nullable=True)
    camera_type = db.Column(db.String(20), nullable=False)  # 'ip' or 'device'
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

# User loader - MUST be after model definition
@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

# Subscription decorator
def subscription_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_subscription_active:
            flash('Your subscription has expired. Please upgrade your plan.', 'warning')
            return redirect(url_for('pricing'))
        return f(*args, **kwargs)
    return decorated_function

# Camera processing functions
def get_camera_capture(camera_type, camera_url=None):
    """Initialize camera capture"""
    try:
        if camera_type == 'ip' and camera_url:
            logger.info(f"Connecting to IP camera: {camera_url}")
            cap = cv2.VideoCapture(camera_url)
        else:
            logger.info("Connecting to device camera")
            cap = cv2.VideoCapture(0)
        
        # Set properties
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
    except Exception as e:
        logger.error(f"Error connecting to camera: {e}")
        return None

def process_frame(frame):
    """Process frame with YOLO detection"""
    try:
        if model is None:
            # Return frame without detection if model failed to load
            _, buffer = cv2.imencode('.jpg', frame)
            return buffer.tobytes()
        
        results = model(frame, stream=True, verbose=False)
        
        for r in results:
            if r.boxes is not None:
                for box in r.boxes:
                    x1, y1, x2, y2 = map(int, box.xyxy[0])
                    w, h = x2 - x1, y2 - y1
                    conf = math.ceil(box.conf[0] * 100) / 100
                    cls = int(box.cls[0])
                    
                    if cls < len(classNames):
                        detected_class = classNames[cls]
                        cvzone.cornerRect(frame, (x1, y1, w, h))
                        cvzone.putTextRect(frame, f'{detected_class} {conf}',
                                           (max(0, x1), max(35, y1)),
                                           scale=1, thickness=1)
        
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
    """Generate video frames - FIXED version with proper context handling"""
    
    # Get camera info ONCE at the start, within the request context
    with app.app_context():
        camera = db.session.get(Camera, camera_id)
        if not camera:
            logger.error(f"Camera {camera_id} not found")
            error_frame = create_error_frame("Camera not found")
            while True:
                yield (b'--frame\r\n'
                       b'Content-Type: image/jpeg\r\n\r\n' + error_frame + b'\r\n')
        
        # Store camera info for use in the generator
        camera_type = camera.camera_type
        camera_url = camera.camera_url
        camera_name = camera.name
    
    logger.info(f"Starting video stream for camera {camera_id}: {camera_name} (Type: {camera_type})")
    
    # Initialize camera
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
                if frame_count % 30 == 0:  # Try to reconnect every 30 failed attempts
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
@subscription_required
def dashboard():
    cameras = Camera.query.filter_by(user_id=current_user.id).all()
    return render_template('dashboard.html', cameras=cameras, user=current_user)

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
        
        flash('Camera added successfully!', 'success')
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
    
    return render_template('stream.html', camera=camera)

@app.route('/video/<int:camera_id>')
@login_required
@subscription_required
def video(camera_id):
    # Check access within app context
    camera = db.session.get(Camera, camera_id)
    if not camera or camera.owner != current_user:
        return "Access denied", 403
    
    logger.info(f"Starting video stream for camera {camera_id}")
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

@app.route('/create-payment-intent', methods=['POST'])
@login_required
def create_payment():
    try:
        data = request.get_json()
        plan = data['plan']
        
        prices = {
            'basic': 999,   # $9.99
            'pro': 1999,    # $19.99
            'business': 4999 # $49.99
        }
        
        if plan not in prices:
            return jsonify({'error': 'Invalid plan'}), 400
        
        if not current_user.stripe_customer_id:
            customer = stripe.Customer.create(
                email=current_user.email,
                name=current_user.username
            )
            current_user.stripe_customer_id = customer.id
            db.session.commit()
        
        intent = stripe.PaymentIntent.create(
            amount=prices[plan],
            currency='usd',
            customer=current_user.stripe_customer_id,
            metadata={'plan': plan, 'user_id': current_user.id}
        )
        
        return jsonify({
            'client_secret': intent.client_secret
        })
    
    except Exception as e:
        return jsonify({'error': str(e)}), 403

@app.route('/webhook', methods=['POST'])
def stripe_webhook():
    payload = request.get_data()
    sig_header = request.headers.get('Stripe-Signature')
    endpoint_secret = 'whsec_your_webhook_secret'
    
    try:
        event = stripe.Webhook.construct_event(payload, sig_header, endpoint_secret)
    except ValueError:
        return 'Invalid payload', 400
    except stripe.error.SignatureVerificationError:
        return 'Invalid signature', 400
    
    if event['type'] == 'payment_intent.succeeded':
        payment_intent = event['data']['object']
        user_id = payment_intent['metadata']['user_id']
        plan = payment_intent['metadata']['plan']
        
        user = db.session.get(User, user_id)
        if user:
            user.subscription_plan = plan
            user.subscription_end = datetime.utcnow() + timedelta(days=30)
            db.session.commit()
    
    return 'Success', 200

@app.route('/account')
@login_required
def account():
    return render_template('account.html', user=current_user)

@app.route('/test_camera/<int:camera_id>')
@login_required
def test_camera(camera_id):
    """Test camera connection"""
    camera = db.session.get(Camera, camera_id)
    if not camera or camera.owner != current_user:
        return "Access denied", 403
    
    cap = get_camera_capture(camera.camera_type, camera.camera_url)
    if cap:
        cap.release()
        return "✅ Camera connection successful"
    else:
        return "❌ Camera connection failed"

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(host="0.0.0.0", port=5000, debug=True)