# =====================================
# routes/camera.py - Camera routes
# =====================================

from flask import Blueprint, render_template, request, redirect, url_for, flash, Response
from flask_login import login_required, current_user
from models import Camera
from services.camera_service import CameraService
from utils.decorators import subscription_required, camera_limit_check
from app import db

camera_bp = Blueprint('camera', __name__, url_prefix='/camera')
camera_service = CameraService()

@camera_bp.route('/dashboard')
@login_required
@subscription_required
def dashboard():
    cameras = Camera.query.filter_by(user_id=current_user.id).all()
    return render_template('camera/dashboard.html', cameras=cameras, user=current_user)

@camera_bp.route('/add', methods=['GET', 'POST'])
@login_required
@subscription_required
@camera_limit_check
def add_camera():
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
        return redirect(url_for('camera.dashboard'))
    
    return render_template('camera/add_camera.html')

@camera_bp.route('/stream/<int:camera_id>')
@login_required
@subscription_required
def stream(camera_id):
    camera = Camera.query.get_or_404(camera_id)
    if camera.owner != current_user:
        flash('Access denied.', 'danger')
        return redirect(url_for('camera.dashboard'))
    
    return render_template('camera/stream.html', camera=camera)

@camera_bp.route('/video/<int:camera_id>')
@login_required
@subscription_required
def video(camera_id):
    camera = Camera.query.get_or_404(camera_id)
    if camera.owner != current_user:
        return "Access denied", 403
    
    return Response(camera_service.generate_frames(camera),
                   mimetype='multipart/x-mixed-replace; boundary=frame')

@camera_bp.route('/delete/<int:camera_id>')
@login_required
def delete_camera(camera_id):
    camera = Camera.query.get_or_404(camera_id)
    if camera.owner != current_user:
        flash('Access denied.', 'danger')
        return redirect(url_for('camera.dashboard'))
    
    db.session.delete(camera)
    db.session.commit()
    flash('Camera deleted successfully!', 'success')
    return redirect(url_for('camera.dashboard'))