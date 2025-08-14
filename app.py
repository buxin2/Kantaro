# app.py - Simple all-in-one version that works with your structure
import os
import logging
from datetime import datetime, timedelta
from flask import Flask, render_template, request, redirect, url_for, flash, Response
import cv2
import numpy as np
import threading
import time
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
        self._streams = {}  # camera_id -> { 'frame': bytes|None, 'cond': threading.Condition, 'updated_at': float }

    def _get_entry(self, camera_id: int):
        if camera_id not in self._streams:
            # Condition uses the same lock for wait/notify
            self._streams[camera_id] = {
                'frame': None,
                'cond': threading.Condition(self._lock),
                'updated_at': 0.0,
            }
        return self._streams[camera_id]

    def publish(self, camera_id: int, jpeg_bytes: bytes):
        with self._lock:
            entry = self._get_entry(camera_id)
            entry['frame'] = jpeg_bytes
            entry['updated_at'] = time.time()
            entry['cond'].notify_all()

    def wait_for_frame(self, camera_id: int, timeout: float = 5.0) -> bytes | None:
        with self._lock:
            entry = self._get_entry(camera_id)
            # If we already have a frame, return it immediately
            if entry['frame'] is not None:
                return entry['frame']
            # Otherwise wait for a new one
            entry['cond'].wait(timeout=timeout)
            return entry['frame']

    def get_latest(self, camera_id: int) -> bytes | None:
        with self._lock:
            entry = self._get_entry(camera_id)
            return entry['frame']

live_hub = LiveStreamHub()

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
    return Response(
        camera_service.generate_frames(camera),
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
        # Send a placeholder if no publisher yet
        latest = live_hub.get_latest(camera_id)
        if latest is None:
            placeholder = camera_service._make_text_frame([
                'Waiting for live broadcast...',
                'Open this camera on the streaming computer and click Start Broadcast.'
            ])
            yield placeholder

        while True:
            frame = live_hub.wait_for_frame(camera_id, timeout=5.0)
            if frame is None:
                # Keep-alive placeholder
                placeholder = camera_service._make_text_frame(['No live frame yet...'])
                yield placeholder
            else:
                yield (b'--frame\r\n'
                       b'Content-Type: image/jpeg\r\n\r\n' + frame + b'\r\n')
            time.sleep(0.1)  # ~10 FPS

    return Response(generate(), mimetype='multipart/x-mixed-replace; boundary=frame')

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

        return render_template(
            'admin.html',
            users=users,
            cameras=cameras,
            total_users=total_users,
            total_cameras=total_cameras,
            plans=plans,
            database_type=database_type,
        )
    except Exception as e:
        logger.error(f"Admin dashboard error: {e}")
        flash('Failed to load admin dashboard.', 'danger')
        return redirect(url_for('dashboard'))

# Utility routes
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
