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

@app.route('/dashboard')
@login_required
def dashboard():
    try:
        cameras = Camera.query.filter_by(user_id=current_user.id).all()
        return render_template('dashboard.html', cameras=cameras, user=current_user)
    except Exception as e:
        logger.error(f"Dashboard error: {e}")
        flash('Error loading dashboard.', 'danger')
        return render_template('dashboard.html', cameras=[], user=current_user)

@app.route('/add_camera', methods=['GET', 'POST'])
@login_required
def add_camera():
    try:
        if len(current_user.cameras) >= current_user.camera_limit:
            flash(f'Camera limit reached ({current_user.camera_limit}). Upgrade your plan.', 'warning')
            return redirect(url_for('pricing'))
        
        if request.method == 'POST':
            name = request.form.get('name', '').strip()
            camera_type = request.form.get('type', 'device')
            camera_url = request.form.get('camera_url') if camera_type == 'ip' else None
            
            if not name:
                flash('Camera name is required.', 'danger')
                return render_template('add_camera.html')
            
            camera = Camera(
                name=name,
                camera_type=camera_type,
                camera_url=camera_url,
                user_id=current_user.id
            )
            
            db.session.add(camera)
            db.session.commit()
            
            logger.info(f"Camera added: {name} by user {current_user.email}")
            flash('Camera added successfully!', 'success')
            return redirect(url_for('dashboard'))
            
    except Exception as e:
        logger.error(f"Add camera error: {e}")
        db.session.rollback()
        flash('Error adding camera. Please try again.', 'danger')
    
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
