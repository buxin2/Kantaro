# app.py - Simple all-in-one version that works with your structure
import os
import logging
from datetime import datetime, timedelta
from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user

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
    # Fallback for local development
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///security_app.db'
    logger.warning("⚠️ DATABASE_URL not found! Using SQLite")
    app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {}

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize extensions
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'

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
        if self.subscription_plan == 'free':
            return True
        return self.subscription_end and self.subscription_end > datetime.utcnow()
    
    @property
    def camera_limit(self):
        limits = {'free': 1, 'basic': 1, 'pro': 4, 'business': 10}
        return limits.get(self.subscription_plan, 1)

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
        # Check camera limit
        current_camera_count = len(current_user.cameras)
        logger.info(f"User {current_user.id} has {current_camera_count} cameras, limit is {current_user.camera_limit}")
        
        if current_camera_count >= current_user.camera_limit:
            flash(f'Camera limit reached ({current_user.camera_limit}). Upgrade your plan.', 'warning')
            return redirect(url_for('pricing'))
        
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


# Add this debug route to your app.py to see what's happening...................................................................................

@app.route('/debug-cameras')
@login_required
def debug_cameras():
    """Debug route to see what cameras exist"""
    try:
        # Get all cameras for current user
        user_cameras = Camera.query.filter_by(user_id=current_user.id).all()
        
        # Get all cameras in database
        all_cameras = Camera.query.all()
        
        # Get current user info
        user_info = {
            'id': current_user.id,
            'username': current_user.username,
            'email': current_user.email,
            'camera_limit': current_user.camera_limit
        }
        
        debug_info = f"""
        <h1>🔍 Camera Debug Information</h1>
        
        <h2>Current User:</h2>
        <ul>
            <li>ID: {user_info['id']}</li>
            <li>Username: {user_info['username']}</li>
            <li>Email: {user_info['email']}</li>
            <li>Camera Limit: {user_info['camera_limit']}</li>
        </ul>
        
        <h2>Your Cameras ({len(user_cameras)}):</h2>
        """
        
        if user_cameras:
            debug_info += "<ul>"
            for camera in user_cameras:
                debug_info += f"""
                <li>
                    <strong>{camera.name}</strong> 
                    (ID: {camera.id}, Type: {camera.camera_type}, 
                    User ID: {camera.user_id}, Created: {camera.created_at})
                </li>
                """
            debug_info += "</ul>"
        else:
            debug_info += "<p><em>No cameras found for your user ID</em></p>"
        
        debug_info += f"""
        <h2>All Cameras in Database ({len(all_cameras)}):</h2>
        """
        
        if all_cameras:
            debug_info += "<ul>"
            for camera in all_cameras:
                debug_info += f"""
                <li>
                    <strong>{camera.name}</strong> 
                    (ID: {camera.id}, Type: {camera.camera_type}, 
                    User ID: {camera.user_id}, Owner: {camera.owner.username if camera.owner else 'None'})
                </li>
                """
            debug_info += "</ul>"
        else:
            debug_info += "<p><em>No cameras found in database</em></p>"
            
        debug_info += """
        <h2>Quick Actions:</h2>
        <p>
            <a href="/dashboard" class="btn btn-primary">Back to Dashboard</a>
            <a href="/add_camera" class="btn btn-success">Add Camera</a>
            <a href="/health" class="btn btn-info">Health Check</a>
        </p>
        """
        
        return debug_info
        
    except Exception as e:
        return f"""
        <h1>❌ Debug Error</h1>
        <p><strong>Error:</strong> {e}</p>
        <p><a href="/dashboard">Back to Dashboard</a></p>
        """


@app.route('/debug-cameras')
@login_required
def debug_cameras():
    """Simple debug route to see what's happening"""
    try:
        # Get cameras for current user
        user_cameras = Camera.query.filter_by(user_id=current_user.id).all()
        
        # Get all cameras
        all_cameras = Camera.query.all()
        
        # Create simple HTML response
        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Camera Debug</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                .info {{ background: #f8f9fa; padding: 15px; border-radius: 5px; margin: 10px 0; }}
                .camera {{ background: #e9ecef; padding: 10px; margin: 5px 0; border-radius: 3px; }}
                .btn {{ padding: 8px 16px; margin: 5px; background: #007bff; color: white; text-decoration: none; border-radius: 4px; }}
            </style>
        </head>
        <body>
            <h1>🔍 Camera Debug Information</h1>
            
            <div class="info">
                <h2>Current User:</h2>
                <p>ID: {current_user.id}</p>
                <p>Email: {current_user.email}</p>
                <p>Username: {current_user.username}</p>
                <p>Camera Limit: {current_user.camera_limit}</p>
                <p>Subscription: {current_user.subscription_plan}</p>
            </div>
            
            <div class="info">
                <h2>Your Cameras ({len(user_cameras)}):</h2>
        """
        
        if user_cameras:
            for camera in user_cameras:
                html += f"""
                <div class="camera">
                    <strong>Name:</strong> {camera.name}<br>
                    <strong>ID:</strong> {camera.id}<br>
                    <strong>Type:</strong> {camera.camera_type}<br>
                    <strong>User ID:</strong> {camera.user_id}<br>
                    <strong>Created:</strong> {camera.created_at}<br>
                    <strong>URL:</strong> {camera.camera_url or 'None'}
                </div>
                """
        else:
            html += "<p style='color: red;'>❌ No cameras found for your user ID!</p>"
        
        html += f"""
            </div>
            
            <div class="info">
                <h2>All Cameras in Database ({len(all_cameras)}):</h2>
        """
        
        if all_cameras:
            for camera in all_cameras:
                html += f"""
                <div class="camera">
                    <strong>Name:</strong> {camera.name} 
                    <strong>ID:</strong> {camera.id} 
                    <strong>User ID:</strong> {camera.user_id} 
                    <strong>Type:</strong> {camera.camera_type}
                </div>
                """
        else:
            html += "<p>No cameras in database</p>"
        
        html += f"""
            </div>
            
            <div class="info">
                <h2>Actions:</h2>
                <a href="/dashboard" class="btn">📊 Dashboard</a>
                <a href="/add_camera" class="btn">➕ Add Camera</a>
                <a href="/health" class="btn">🏥 Health</a>
                <a href="/logout" class="btn">🚪 Logout</a>
            </div>
            
        </body>
        </html>
        """
        
        return html
        
    except Exception as e:
        return f"""
        <h1>Debug Error</h1>
        <p>Error: {e}</p>
        <p><a href="/dashboard">Back to Dashboard</a></p>
        """

#...........................................................................................................................................................................................................................................

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
    return render_template('pricing.html')

@app.route('/account')
@login_required
def account():
    return render_template('account.html', user=current_user)

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
