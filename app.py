# app.py - Simple all-in-one version that works with your structure
import os
import logging
from datetime import datetime, timedelta
from flask import Flask, render_template, request, redirect, url_for, flash, Response
import cv2
import numpy as np
import threading
import time
import cloudinary
import cloudinary.uploader
import tempfile
from collections import deque
import smtplib
from email.message import EmailMessage
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from services.camera_service import CameraService

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s %(levelname)s %(name)s %(message)s'
)
logger = logging.getLogger(__name__)

# Initialize Flask app
app = Flask(__name__)

# Configuration
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'fallback-key-change-this')

# Database configuration
database_url = os.environ.get('DATABASE_URL')
if database_url:
    # Fix PostgreSQL URL format if needed
    if database_url.startswith('postgres://'):
        database_url = database_url.replace('postgres://', 'postgresql://', 1)
    app.config['SQLALCHEMY_DATABASE_URI'] = database_url
    logger.info("✅ Using PostgreSQL database from Render")
    
    # PostgreSQL connection settings for Render
    app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
        'pool_timeout': 30,
        'pool_recycle': 3600,
        'pool_pre_ping': True,
        'connect_args': {
            'connect_timeout': 30,
            'sslmode': 'require'
        }
    }
else:
    # Fallback for local development - use absolute SQLite path to avoid cwd issues
    basedir = os.path.abspath(os.path.dirname(__file__))
    sqlite_path = os.path.join(basedir, 'security_app.db')
    app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{sqlite_path}'
    logger.warning("⚠️ DATABASE_URL not found! Using SQLite at %s", sqlite_path)
    app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
        'connect_args': {
            'check_same_thread': False
        }
    }

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize extensions
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'

# Initialize services
camera_service = CameraService()

# In-memory live stream hub: one publisher, many watchers per camera_id
class LiveStreamHub:
    def __init__(self):
        self._lock = threading.Lock()
        # camera_id -> { 'frame': bytes|None, 'cond': threading.Condition, 'version': int }
        self._streams = {}

    def _get_entry(self, camera_id: int):
        if camera_id not in self._streams:
            self._streams[camera_id] = {
                'frame': None,
                'cond': threading.Condition(self._lock),
                'version': 0,
            }
        return self._streams[camera_id]

    def publish(self, camera_id: int, jpeg_bytes: bytes):
        with self._lock:
            entry = self._get_entry(camera_id)
            entry['frame'] = jpeg_bytes
            entry['version'] += 1
            entry['cond'].notify_all()

    def wait_for_next(self, camera_id: int, last_version: int, timeout: float = 10.0):
        with self._lock:
            entry = self._get_entry(camera_id)
            if entry['version'] != last_version and entry['frame'] is not None:
                return entry['frame'], entry['version']
            entry['cond'].wait(timeout=timeout)
            return entry['frame'], entry['version']

    def get_latest(self, camera_id: int):
        with self._lock:
            entry = self._get_entry(camera_id)
            return entry['frame'], entry['version']

live_hub = LiveStreamHub()

# Monitoring threads per camera_id
monitor_threads = {}
monitor_flags = {}

def send_email_notification(subject: str, to_emails: list[str], html_body: str, text_body: str | None = None) -> None:
    host = os.environ.get('SMTP_HOST', 'smtp.gmail.com')
    port = int(os.environ.get('SMTP_PORT', '587'))
    username = os.environ.get('SMTP_USERNAME')
    password = os.environ.get('SMTP_PASSWORD')
    use_tls = os.environ.get('SMTP_USE_TLS', '1').lower() in ('1', 'true', 'yes')
    if not (username and password):
        logger.warning('Email not sent: SMTP credentials not set')
        return
    msg = EmailMessage()
    msg['Subject'] = subject
    msg['From'] = username
    msg['To'] = ', '.join(to_emails)
    if text_body is None:
        text_body = 'See HTML version.'
    msg.set_content(text_body)
    msg.add_alternative(html_body, subtype='html')
    try:
        with smtplib.SMTP(host, port, timeout=30) as server:
            if use_tls:
                server.starttls()
            server.login(username, password)
            server.send_message(msg)
        logger.info('Notification email sent to %s', to_emails)
    except Exception as e:
        logger.error('Failed to send email: %s', e)

def monitor_camera_detections(camera_id: int, user_id: int, clip_seconds: int = 15):
    """Continuously watch pushed frames and record a short clip when detection occurs."""
    # Ensure app context for DB operations inside thread
    app_ctx = app.app_context()
    app_ctx.push()
    # Rolling buffer of last N seconds worth of frames
    target_fps = 10
    max_frames = clip_seconds * target_fps
    buffer = deque(maxlen=max_frames)
    last_version = 0

    while monitor_flags.get(camera_id):
        frame_bytes, version = live_hub.wait_for_next(camera_id, last_version, timeout=5.0)
        if version == last_version:
            continue
        last_version = version
        timestamp = time.time()
        buffer.append((timestamp, frame_bytes))

        # Run lightweight detection sampling (every N frames)
        if len(buffer) % (target_fps // 2 or 1) == 0:
            # Decode a frame to run detection
            np_arr = np.frombuffer(frame_bytes, np.uint8)
            frame = cv2.imdecode(np_arr, cv2.IMREAD_COLOR)
            # Proper detection check
            annotated, detected = camera_service.detect_and_annotate(frame)
            if detected:
                try:
                    # Create snapshot from current annotated bytes
                    with tempfile.NamedTemporaryFile(suffix='.jpg', delete=False) as img_tmp:
                        img_tmp.write(annotated)
                        img_path = img_tmp.name
                    img_up = cloudinary.uploader.upload(img_path, folder=f"detections/{user_id}/{camera_id}")
                    snapshot_url = img_up.get('secure_url')

                    # Write buffered frames to a temporary video file
                    with tempfile.NamedTemporaryFile(suffix='.mp4', delete=False) as vid_tmp:
                        video_path = vid_tmp.name
                    # Assemble video using OpenCV VideoWriter
                    frames = []
                    for _, fb in buffer:
                        arr = np.frombuffer(fb, np.uint8)
                        f = cv2.imdecode(arr, cv2.IMREAD_COLOR)
                        frames.append(f)
                    if frames:
                        h, w = frames[0].shape[:2]
                        fourcc = cv2.VideoWriter_fourcc(*'mp4v')
                        out = cv2.VideoWriter(video_path, fourcc, target_fps, (w, h))
                        for f in frames:
                            out.write(f)
                        out.release()

                    vid_up = cloudinary.uploader.upload_large(video_path, resource_type='video', folder=f"detections/{user_id}/{camera_id}")
                    video_url = vid_up.get('secure_url')

                    # Persist detection record
                    det = Detection(camera_id=camera_id, user_id=user_id, label='object', snapshot_url=snapshot_url, video_url=video_url)
                    db.session.add(det)
                    db.session.commit()

                    # Notify user/admin via email if configured
                    try:
                        # Build detection link on our site
                        base_url = os.environ.get('SITE_URL', '').rstrip('/')
                        if base_url:
                            detection_link = f"{base_url}/detection/{det.id}"
                        else:
                            detection_link = det.video_url
                        user = db.session.get(User, user_id)
                        recipients = []
                        if user and user.email:
                            recipients.append(user.email)
                        # Include admins
                        recipients.extend(list(ADMIN_EMAILS))
                        recipients = list(dict.fromkeys(recipients))  # dedupe
                        if recipients:
                            subject = f"Object detected on Camera {camera_id}"
                            html = f"""
                                <h3>Object detected</h3>
                                <p>Camera ID: {camera_id}</p>
                                <p><strong>Snapshot:</strong><br><img src='{snapshot_url}' style='max-width:100%'/></p>
                                <p><a href='{detection_link}'>View full video</a></p>
                            """
                            text = f"Object detected on camera {camera_id}. View: {detection_link}"
                            send_email_notification(subject, recipients, html, text)
                    except Exception as ne:
                        logger.error('Notification error: %s', ne)

                    # Reset buffer after detection to avoid duplicate uploads
                    buffer.clear()
                except Exception as e:
                    logger.error(f"Detection upload failed: {e}")
    # Pop app context on exit
    app_ctx.pop()

# Admin configuration
ADMIN_EMAILS = set(
    e.strip().lower()
    for e in os.environ.get('ADMIN_EMAILS', 'admin@example.com').split(',')
    if e.strip()
)

def is_current_user_admin() -> bool:
    try:
        return bool(current_user.is_authenticated and current_user.email.lower() in ADMIN_EMAILS)
    except Exception:
        return False

@app.context_processor
def inject_admin_flag():
    return { 'is_admin': is_current_user_admin() }

def admin_required(view_func):
    def wrapper(*args, **kwargs):
        if not current_user.is_authenticated or not is_current_user_admin():
            flash('Admin access required.', 'danger')
            return redirect(url_for('dashboard'))
        return view_func(*args, **kwargs)
    wrapper.__name__ = view_func.__name__
    return wrapper

# Database Models (defined in app.py to avoid circular imports)
class User(UserMixin, db.Model):
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    subscription_plan = db.Column(db.String(20), default='free')
    subscription_end = db.Column(db.DateTime, nullable=True)
    stripe_customer_id = db.Column(db.String(50), nullable=True)
    cameras = db.relationship('Camera', backref='owner', lazy=True, cascade='all, delete-orphan')
    
    def __repr__(self):
        return f"User('{self.username}', '{self.email}', '{self.subscription_plan}')"
    
    @property
    def is_subscription_active(self):
        # Subscriptions disabled: always active
        return True
    
    @property
    def camera_limit(self):
        # Subscriptions disabled: effectively unlimited
        return 1_000_000

    # Convenience for decorators that might call can_add_camera
    def can_add_camera(self) -> bool:
        return len(self.cameras) < self.camera_limit

class Camera(db.Model):
    __tablename__ = 'cameras'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    camera_url = db.Column(db.String(200), nullable=True)
    camera_type = db.Column(db.String(20), nullable=False, default='device')
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def __repr__(self):
        return f"Camera('{self.name}', '{self.camera_type}', user_id={self.user_id})"

class Detection(db.Model):
    __tablename__ = 'detections'
    id = db.Column(db.Integer, primary_key=True)
    camera_id = db.Column(db.Integer, db.ForeignKey('cameras.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    label = db.Column(db.String(50), nullable=False)
    snapshot_url = db.Column(db.String(500), nullable=False)
    video_url = db.Column(db.String(500), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

# User loader for Flask-Login
@login_manager.user_loader
def load_user(user_id):
    try:
        return db.session.get(User, int(user_id))
    except Exception as e:
        logger.error(f"Error loading user {user_id}: {e}")
        return None

# Initialize database and create admin user
def init_database():
    """Initialize database with tables and admin user"""
    try:
        with app.app_context():
            # Create all tables
            db.create_all()
            logger.info("✅ Database tables created successfully")
            
            # Create admin user if it doesn't exist
            admin_user = User.query.filter_by(email='admin@example.com').first()
            if not admin_user:
                hashed_password = bcrypt.generate_password_hash('password123').decode('utf-8')
                admin_user = User(
                    username='admin',
                    email='admin@example.com',
                    password=hashed_password
                )
                db.session.add(admin_user)
                db.session.commit()
                logger.info("✅ Admin user created: admin@example.com / password123")
            else:
                logger.info("ℹ️ Admin user already exists")
            
    except Exception as e:
        logger.error(f"❌ Database initialization error: {e}")

# Cloudinary configuration from environment
cloudinary.config(
    cloud_name=os.environ.get('CLOUDINARY_CLOUD_NAME', ''),
    api_key=os.environ.get('CLOUDINARY_API_KEY', ''),
    api_secret=os.environ.get('CLOUDINARY_API_SECRET', ''),
    secure=True
)

# Routes
@app.route('/')
def home():
    return render_template('home.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        try:
            username = request.form.get('username', '').strip()
            email = request.form.get('email', '').strip().lower()
            password = request.form.get('password', '')
            
            if not all([username, email, password]):
                flash('All fields are required.', 'danger')
                return render_template('register.html')
            
            if len(password) < 6:
                flash('Password must be at least 6 characters long.', 'danger')
                return render_template('register.html')
            
            # Check if user exists
            existing_user = User.query.filter_by(email=email).first()
            if existing_user:
                flash('Email already registered. Please log in.', 'danger')
                return redirect(url_for('login'))
            
            # Create user
            hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
            new_user = User(username=username, email=email, password=hashed_password)
            
            db.session.add(new_user)
            db.session.commit()
            
            logger.info(f"New user registered: {email}")
            flash('Account created successfully! Please log in.', 'success')
            return redirect(url_for('login'))
            
        except Exception as e:
            logger.error(f"Registration error: {e}")
            db.session.rollback()
            flash('Registration failed. Please try again.', 'danger')
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        try:
            email = request.form.get('email', '').strip().lower()
            password = request.form.get('password', '')
            
            if not email or not password:
                flash('Email and password are required.', 'danger')
                return render_template('login.html')
            
            user = User.query.filter_by(email=email).first()
            
            if user and bcrypt.check_password_hash(user.password, password):
                login_user(user, remember=request.form.get('remember'))
                logger.info(f"User logged in: {email}")
                
                next_page = request.args.get('next')
                return redirect(next_page) if next_page else redirect(url_for('dashboard'))
            else:
                flash('Invalid email or password.', 'danger')
                logger.warning(f"Failed login attempt for: {email}")
                
        except Exception as e:
            logger.error(f"Login error: {e}")
            flash('Login failed. Please try again.', 'danger')
    
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logger.info(f"User logged out: {current_user.email}")
    logout_user()
    flash('Logged out successfully.', 'info')
    return redirect(url_for('home'))

# Replace your dashboard route in app.py with this improved version

@app.route('/dashboard')
@login_required
def dashboard():
    try:
        # Ensure session state is fresh before querying
        db.session.expire_all()

        # Get cameras for current user with explicit query
        cameras = Camera.query.filter_by(user_id=current_user.id).all()
        
        # Log debug information
        logger.info(f"Dashboard accessed by user {current_user.id} ({current_user.email})")
        logger.info(f"Found {len(cameras)} cameras for user {current_user.id}")
        
        # Debug: Print camera details
        for camera in cameras:
            logger.info(f"Camera: {camera.name} (ID: {camera.id}, Type: {camera.camera_type})")
        
        return render_template('dashboard.html', cameras=cameras, user=current_user)
        
    except Exception as e:
        logger.error(f"Dashboard error for user {current_user.id}: {e}")
        flash(f'Error loading dashboard: {str(e)}', 'danger')
        
        # Return dashboard with empty cameras list as fallback
        return render_template('dashboard.html', cameras=[], user=current_user)

@app.route('/add_camera', methods=['GET', 'POST'])
@login_required
def add_camera():
    try:
        if request.method == 'POST':
            name = request.form.get('name', '').strip()
            camera_type = request.form.get('type', 'device')
            camera_url = request.form.get('camera_url', '').strip() if camera_type == 'ip' else None
            
            logger.info(f"Adding camera: name='{name}', type='{camera_type}', url='{camera_url}', user_id={current_user.id}")
            
            if not name:
                flash('Camera name is required.', 'danger')
                return render_template('add_camera.html')
            
            # Create camera
            camera = Camera(
                name=name,
                camera_type=camera_type,
                camera_url=camera_url,
                user_id=current_user.id
            )
            
            # Add to database
            db.session.add(camera)
            db.session.commit()
            
            # Verify it was added
            added_camera = Camera.query.filter_by(name=name, user_id=current_user.id).first()
            if added_camera:
                logger.info(f"✅ Camera successfully added: ID={added_camera.id}, Name='{added_camera.name}'")
                flash(f'Camera "{name}" added successfully!', 'success')
            else:
                logger.error(f"❌ Camera was not found after adding: {name}")
                flash('Camera may not have been saved properly. Please check your cameras.', 'warning')
            
            return redirect(url_for('dashboard'))
            
    except Exception as e:
        logger.error(f"Add camera error for user {current_user.id}: {e}")
        db.session.rollback()
        flash(f'Error adding camera: {str(e)}', 'danger')
    
    return render_template('add_camera.html')


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

@app.route('/debug-cameras')
@login_required
def debug_cameras():
    try:
        db.session.expire_all()
        cameras = Camera.query.filter_by(user_id=current_user.id).all()
        lines = [
            f"User: {current_user.id} ({current_user.email})",
            f"Camera count: {len(cameras)}",
            "",
        ]
        for cam in cameras:
            lines.append(
                f"- ID={cam.id} | Name='{cam.name}' | Type={cam.camera_type} | URL={cam.camera_url or '-'} | Created={cam.created_at}"
            )
        return "<pre>" + "\n".join(lines) + "</pre>", 200
    except Exception as e:
        logger.error(f"Debug cameras error: {e}")
        return f"<pre>Error: {e}</pre>", 500

@app.route('/pricing')
def pricing():
    return render_template('pricing.html')

@app.route('/account')
@login_required
def account():
    return render_template('account.html', user=current_user)

# Compatibility aliases for any old links using /camera/* paths
@app.route('/camera/dashboard')
@login_required
def camera_dashboard_alias():
    return redirect(url_for('dashboard'))

@app.route('/camera/add', methods=['GET', 'POST'])
@login_required
def camera_add_alias():
    return redirect(url_for('add_camera'))

@app.route('/camera/delete/<int:camera_id>')
@login_required
def camera_delete_alias(camera_id):
    return redirect(url_for('delete_camera', camera_id=camera_id))

@app.route('/stream/<int:camera_id>')
@login_required
def stream(camera_id):
    camera = db.session.get(Camera, camera_id)
    if not camera or (camera.owner != current_user and not is_current_user_admin()):
        flash('Access denied.', 'danger')
        return redirect(url_for('dashboard'))
    return render_template('stream.html', camera=camera)

@app.route('/video/<int:camera_id>')
@login_required
def video(camera_id):
    camera = db.session.get(Camera, camera_id)
    if not camera or (camera.owner != current_user and not is_current_user_admin()):
        return "Access denied", 403
    # Toggle detection overlay via query param (?detect=1)
    enable_detection = request.args.get('detect') in ('1', 'true', 'yes')
    return Response(
        camera_service.generate_frames(camera, enable_detection=enable_detection),
        mimetype='multipart/x-mixed-replace; boundary=frame'
    )

# Publisher: device client posts frames here to broadcast to watchers
@app.route('/push/<int:camera_id>', methods=['POST'])
@login_required
def push_frame(camera_id):
    camera = db.session.get(Camera, camera_id)
    if not camera or (camera.owner != current_user and not is_current_user_admin()):
        return "Access denied", 403
    file = request.files.get('frame')
    if not file:
        return "No frame provided", 400
    # Broadcast raw JPEG to minimize CPU/memory; annotation remains optional via /analyze
    jpeg_bytes = file.read()
    live_hub.publish(camera_id, jpeg_bytes)
    return "OK", 200

# Watcher: returns MJPEG stream of the latest pushed frames
@app.route('/watch/<int:camera_id>')
@login_required
def watch_stream(camera_id):
    camera = db.session.get(Camera, camera_id)
    if not camera or (camera.owner != current_user and not is_current_user_admin()):
        return "Access denied", 403

    def generate():
        # Initial status/priming
        latest, version = live_hub.get_latest(camera_id)
        if latest is None:
            yield camera_service._make_text_frame([
                'Waiting for live broadcast...',
                'Open this camera on the streaming computer and click Start Broadcast.'
            ])
        else:
            yield (b'--frame\r\n'
                   b'Content-Type: image/jpeg\r\n\r\n' + latest + b'\r\n')

        last_version = version
        last_frame = latest
        while True:
            frame, version = live_hub.wait_for_next(camera_id, last_version, timeout=10.0)
            if frame is None:
                # No new frame; repeat last frame as keep-alive
                if last_frame is not None:
                    yield (b'--frame\r\n'
                           b'Content-Type: image/jpeg\r\n\r\n' + last_frame + b'\r\n')
                continue
            last_version = version
            last_frame = frame
            yield (b'--frame\r\n'
                   b'Content-Type: image/jpeg\r\n\r\n' + frame + b'\r\n')

    headers = {
        'Cache-Control': 'no-cache, no-store, must-revalidate',
        'Pragma': 'no-cache',
        'Expires': '0',
    }
    return Response(generate(), headers=headers, mimetype='multipart/x-mixed-replace; boundary=frame')

@app.route('/monitor/start/<int:camera_id>')
@login_required
def start_monitor(camera_id):
    camera = db.session.get(Camera, camera_id)
    if not camera or (camera.owner != current_user and not is_current_user_admin()):
        flash('Access denied.', 'danger')
        return redirect(url_for('dashboard'))
    if monitor_flags.get(camera_id):
        flash('Monitoring already running.', 'info')
        return redirect(url_for('stream', camera_id=camera_id))
    monitor_flags[camera_id] = True
    t = threading.Thread(target=monitor_camera_detections, args=(camera_id, camera.user_id), daemon=True)
    monitor_threads[camera_id] = t
    t.start()
    flash('Monitoring started.', 'success')
    return redirect(url_for('stream', camera_id=camera_id))

@app.route('/monitor/stop/<int:camera_id>')
@login_required
def stop_monitor(camera_id):
    if monitor_flags.get(camera_id):
        monitor_flags[camera_id] = False
        # Wake any waiting monitor thread
        try:
            _ = live_hub.get_latest(camera_id)
            # Publish a tiny keep-alive to trigger condition
            live_hub.publish(camera_id, b'')
        except Exception:
            pass
        flash('Monitoring stopping...', 'info')
    else:
        flash('Monitoring not running.', 'info')
    return redirect(url_for('stream', camera_id=camera_id))

@app.route('/analyze/<int:camera_id>', methods=['POST'])
@login_required
def analyze_frame(camera_id):
    camera = db.session.get(Camera, camera_id)
    if not camera or (camera.owner != current_user and not is_current_user_admin()):
        return "Access denied", 403
    file = request.files.get('frame')
    if not file:
        return "No frame provided", 400
    file_bytes = file.read()
    np_arr = np.frombuffer(file_bytes, np.uint8)
    frame = cv2.imdecode(np_arr, cv2.IMREAD_COLOR)
    jpeg_out = camera_service.annotate_frame(frame)
    return Response(jpeg_out, mimetype='image/jpeg')

# Aliases for old camera stream paths
@app.route('/camera/stream/<int:camera_id>')
@login_required
def camera_stream_alias(camera_id):
    return redirect(url_for('stream', camera_id=camera_id))

@app.route('/camera/video/<int:camera_id>')
@login_required
def camera_video_alias(camera_id):
    return redirect(url_for('video', camera_id=camera_id))

@app.route('/admin')
@login_required
@admin_required
def admin_dashboard():
    try:
        # Metrics
        total_users = User.query.count()
        total_cameras = Camera.query.count()
        plans = {'free': 0, 'basic': 0, 'pro': 0, 'business': 0}
        for plan, count in db.session.query(User.subscription_plan, db.func.count(User.id)).group_by(User.subscription_plan):
            plans[plan] = count

        # Detailed lists
        users = User.query.order_by(User.id.desc()).all()
        cameras = Camera.query.order_by(Camera.created_at.desc()).all()

        # Environment
        database_type = 'postgresql' if os.environ.get('DATABASE_URL') else 'sqlite'

        recent_detections = Detection.query.order_by(Detection.created_at.desc()).limit(50).all()
        return render_template(
            'admin.html',
            users=users,
            cameras=cameras,
            total_users=total_users,
            total_cameras=total_cameras,
            plans=plans,
            database_type=database_type,
            detections=recent_detections,
        )
    except Exception as e:
        logger.error(f"Admin dashboard error: {e}")
        flash('Failed to load admin dashboard.', 'danger')
        return redirect(url_for('dashboard'))

# Utility routes
@app.route('/detection/<int:det_id>')
@login_required
def view_detection(det_id):
    det = db.session.get(Detection, det_id)
    if not det:
        return redirect(url_for('dashboard'))
    # Allow owner or admin to view
    if det.user_id != current_user.id and not is_current_user_admin():
        flash('Access denied.', 'danger')
        return redirect(url_for('dashboard'))
    return render_template('detection.html', detection=det)
@app.route('/health')
def health_check():
    try:
        User.query.first()
        return {
            'status': 'healthy', 
            'database': 'connected',
            'database_type': 'postgresql' if os.environ.get('DATABASE_URL') else 'sqlite',
            'users': User.query.count(),
            'cameras': Camera.query.count()
        }, 200
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        return {'status': 'unhealthy', 'error': str(e)}, 500

@app.route('/init-db')
def init_db():
    try:
        db.create_all()
        
        admin_user = User.query.filter_by(email='admin@example.com').first()
        if not admin_user:
            hashed_password = bcrypt.generate_password_hash('password123').decode('utf-8')
            admin_user = User(
                username='admin',
                email='admin@example.com',
                password=hashed_password
            )
            db.session.add(admin_user)
            db.session.commit()
            admin_created = True
        else:
            admin_created = False
        
        user_count = User.query.count()
        camera_count = Camera.query.count()
        
        return f'''
        <h1>✅ Database Initialized Successfully!</h1>
        <p><strong>Database:</strong> {"PostgreSQL" if os.environ.get('DATABASE_URL') else "SQLite"}</p>
        <p><strong>Tables:</strong> ✅ Created</p>
        <p><strong>Admin User:</strong> {"✅ Created" if admin_created else "ℹ️ Already exists"}</p>
        <p><strong>Users:</strong> {user_count}</p>
        <p><strong>Cameras:</strong> {camera_count}</p>
        <hr>
        <p><strong>Login with:</strong></p>
        <ul>
            <li>Email: admin@example.com</li>
            <li>Password: password123</li>
        </ul>
        <p><a href="/">🏠 Home</a> | <a href="/login">🔐 Login</a> | <a href="/register">📝 Register</a></p>
        '''
    except Exception as e:
        logger.error(f"Manual DB init failed: {e}")
        return f'<h1>❌ Error</h1><p>{e}</p>', 500

@app.route('/favicon.ico')
def favicon():
    return "", 204

# Error handlers
@app.errorhandler(404)
def not_found(error):
    return "<h1>404 - Page Not Found</h1><p><a href='/'>Go Home</a></p>", 404

@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    logger.error(f"Internal server error: {error}")
    return "<h1>500 - Internal Server Error</h1><p><a href='/'>Go Home</a></p>", 500

# Initialize database on startup
init_database()

if __name__ == "__main__":
    port = int(os.environ.get('PORT', 5000))
    logger.info(f"🚀 Starting app on port {port}")
    app.run(host="0.0.0.0", port=port, debug=False)
